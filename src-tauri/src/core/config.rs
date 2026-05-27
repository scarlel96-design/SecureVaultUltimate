use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const SETTINGS_FILE: &str = "settings.json";
const EXTERNAL_LOCKS_FILE: &str = "external_locks.json";
const DECOY_SALT_SIZE: usize = 16;
const DECOY_KEY_SIZE: usize = 32;
const DECOY_MEMORY_KIB: u32 = 128 * 1024;
const DECOY_TIME_COST: u32 = 3;
const DECOY_PARALLELISM: u32 = 2;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("설정 IO 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("설정 JSON 오류: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Argon2 오류: {0}")]
    Argon2(String),
    #[error("설정값이 허용 범위를 벗어났습니다: {0}")]
    InvalidValue(String),
}

pub type ConfigResult<T> = Result<T, ConfigError>;

#[derive(Debug, Clone)]
pub struct SettingsStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub auto_lock_minutes: u64,
    pub threat_update_hours: u64,
    pub threat_feed_url: String,
    #[serde(default = "default_vanguard_scan_interval_minutes")]
    pub vanguard_scan_interval_minutes: u64,
    #[serde(default = "default_scan_on_action_integrity")]
    pub scan_on_action_integrity: bool,
    #[serde(default)]
    pub secure_wipe_on_uninstall: bool,
    #[serde(default)]
    pub decoy_password: Option<DecoyPasswordRecord>,
    pub updated_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecoyPasswordRecord {
    pub algorithm: String,
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt_b64: String,
    pub hash_b64: String,
    pub created_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    pub auto_lock_minutes: u64,
    pub threat_update_hours: u64,
    pub threat_feed_url: String,
    pub vanguard_scan_interval_minutes: u64,
    pub scan_on_action_integrity: bool,
    pub secure_wipe_on_uninstall: bool,
    pub decoy_password_configured: bool,
    pub updated_utc: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsUpdate {
    pub auto_lock_minutes: u64,
    pub threat_update_hours: u64,
    pub threat_feed_url: String,
    pub vanguard_scan_interval_minutes: u64,
    pub scan_on_action_integrity: bool,
    pub secure_wipe_on_uninstall: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalLockRegistry {
    version: u32,
    updated_utc: String,
    paths: BTreeSet<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 10,
            threat_update_hours: 12,
            threat_feed_url: String::new(),
            vanguard_scan_interval_minutes: default_vanguard_scan_interval_minutes(),
            scan_on_action_integrity: default_scan_on_action_integrity(),
            secure_wipe_on_uninstall: false,
            decoy_password: None,
            updated_utc: Utc::now().to_rfc3339(),
        }
    }
}

impl SettingsStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn default() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::new(base.join("SecureVaultUltimate"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(&self) -> ConfigResult<AppSettings> {
        let path = self.path();
        if !path.exists() {
            let settings = AppSettings::default();
            self.save(&settings)?;
            return Ok(settings);
        }
        let bytes = fs::read(path)?;
        let mut settings: AppSettings = serde_json::from_slice(&bytes)?;
        validate_settings(&settings)?;
        if settings.updated_utc.is_empty() {
            settings.updated_utc = Utc::now().to_rfc3339();
        }
        Ok(settings)
    }

    pub fn save(&self, settings: &AppSettings) -> ConfigResult<()> {
        validate_settings(settings)?;
        fs::create_dir_all(&self.root)?;
        let path = self.path();
        let temp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(settings)?;
        fs::write(&temp, bytes)?;
        fs::rename(temp, path)?;
        Ok(())
    }

    pub fn update(&self, update: SettingsUpdate) -> ConfigResult<AppSettings> {
        let mut settings = self.load()?;
        settings.auto_lock_minutes = update.auto_lock_minutes;
        settings.threat_update_hours = update.threat_update_hours;
        settings.threat_feed_url = update.threat_feed_url.trim().to_string();
        settings.vanguard_scan_interval_minutes = update.vanguard_scan_interval_minutes;
        settings.scan_on_action_integrity = update.scan_on_action_integrity;
        settings.secure_wipe_on_uninstall = update.secure_wipe_on_uninstall;
        settings.updated_utc = Utc::now().to_rfc3339();
        self.save(&settings)?;
        Ok(settings)
    }

    pub fn set_decoy_password(&self, password: String) -> ConfigResult<AppSettings> {
        if password.len() < 12 {
            return Err(ConfigError::InvalidValue(
                "데코이 비밀번호는 최소 12자 이상이어야 합니다.".to_string(),
            ));
        }
        let mut password = Zeroizing::new(password.into_bytes());
        let mut salt = [0u8; DECOY_SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let mut hash = Zeroizing::new(vec![0u8; DECOY_KEY_SIZE]);
        let params = Params::new(
            DECOY_MEMORY_KIB,
            DECOY_TIME_COST,
            DECOY_PARALLELISM,
            Some(DECOY_KEY_SIZE),
        )
        .map_err(|error| ConfigError::Argon2(error.to_string()))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&password, &salt, &mut hash)
            .map_err(|error| ConfigError::Argon2(error.to_string()))?;
        password.zeroize();

        let mut settings = self.load()?;
        settings.decoy_password = Some(DecoyPasswordRecord {
            algorithm: "argon2id".to_string(),
            memory_kib: DECOY_MEMORY_KIB,
            time_cost: DECOY_TIME_COST,
            parallelism: DECOY_PARALLELISM,
            salt_b64: B64.encode(salt),
            hash_b64: B64.encode(&hash),
            created_utc: Utc::now().to_rfc3339(),
        });
        settings.updated_utc = Utc::now().to_rfc3339();
        self.save(&settings)?;
        Ok(settings)
    }

    pub fn clear_decoy_password(&self) -> ConfigResult<AppSettings> {
        let mut settings = self.load()?;
        settings.decoy_password = None;
        settings.updated_utc = Utc::now().to_rfc3339();
        self.save(&settings)?;
        Ok(settings)
    }

    fn path(&self) -> PathBuf {
        self.root.join(SETTINGS_FILE)
    }
}

impl From<&AppSettings> for SettingsView {
    fn from(settings: &AppSettings) -> Self {
        Self {
            auto_lock_minutes: settings.auto_lock_minutes,
            threat_update_hours: settings.threat_update_hours,
            threat_feed_url: settings.threat_feed_url.clone(),
            vanguard_scan_interval_minutes: settings.vanguard_scan_interval_minutes,
            scan_on_action_integrity: settings.scan_on_action_integrity,
            secure_wipe_on_uninstall: settings.secure_wipe_on_uninstall,
            decoy_password_configured: settings.decoy_password.is_some(),
            updated_utc: settings.updated_utc.clone(),
        }
    }
}

pub fn validate_settings(settings: &AppSettings) -> ConfigResult<()> {
    if !(1..=120).contains(&settings.auto_lock_minutes) {
        return Err(ConfigError::InvalidValue(
            "자동 잠금 타이머는 1~120분 사이여야 합니다.".to_string(),
        ));
    }
    if ![1, 3, 6, 12, 24].contains(&settings.threat_update_hours) {
        return Err(ConfigError::InvalidValue(
            "위협 인텔리전스 업데이트 주기는 1, 3, 6, 12, 24시간만 허용됩니다.".to_string(),
        ));
    }
    if !(1..=60).contains(&settings.vanguard_scan_interval_minutes) {
        return Err(ConfigError::InvalidValue(
            "뱅가드 감시 인터벌은 1~60분 사이여야 합니다.".to_string(),
        ));
    }
    if !settings.threat_feed_url.is_empty() {
        validate_feed_url(&settings.threat_feed_url)?;
    }
    Ok(())
}

pub fn app_data_dir() -> PathBuf {
    SettingsStore::default().root
}

pub fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn register_external_locks(paths: &[PathBuf]) -> ConfigResult<()> {
    let mut registry = load_external_lock_registry()?;
    for path in paths {
        registry.paths.insert(normalize_path(path));
    }
    registry.updated_utc = Utc::now().to_rfc3339();
    save_external_lock_registry(&registry)
}

pub fn unregister_external_locks(paths: &[PathBuf]) -> ConfigResult<()> {
    let mut registry = load_external_lock_registry()?;
    for path in paths {
        registry.paths.remove(&normalize_path(path));
    }
    registry.updated_utc = Utc::now().to_rfc3339();
    save_external_lock_registry(&registry)
}

pub fn tracked_external_locks() -> ConfigResult<Vec<PathBuf>> {
    Ok(load_external_lock_registry()?
        .paths
        .into_iter()
        .map(PathBuf::from)
        .collect())
}

pub fn clear_external_locks() -> ConfigResult<()> {
    let path = external_locks_path();
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn validate_feed_url(url: &str) -> ConfigResult<()> {
    if !url.starts_with("https://") {
        return Err(ConfigError::InvalidValue(
            "위협 피드 URL은 https:// 주소만 허용됩니다.".to_string(),
        ));
    }
    if url.len() > 2048 || url.chars().any(|ch| matches!(ch, '\r' | '\n' | '\t')) {
        return Err(ConfigError::InvalidValue(
            "위협 피드 URL 형식이 안전하지 않습니다.".to_string(),
        ));
    }
    Ok(())
}

fn load_external_lock_registry() -> ConfigResult<ExternalLockRegistry> {
    let path = external_locks_path();
    if !path.exists() {
        return Ok(ExternalLockRegistry {
            version: 1,
            updated_utc: Utc::now().to_rfc3339(),
            paths: BTreeSet::new(),
        });
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(ConfigError::from)
}

fn save_external_lock_registry(registry: &ExternalLockRegistry) -> ConfigResult<()> {
    let path = external_locks_path();
    ensure_parent(&path)?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, serde_json::to_vec_pretty(registry)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn external_locks_path() -> PathBuf {
    app_data_dir().join(EXTERNAL_LOCKS_FILE)
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn default_vanguard_scan_interval_minutes() -> u64 {
    1
}

fn default_scan_on_action_integrity() -> bool {
    true
}
