use crate::core::config::{self, AppSettings, SettingsStore};
use crate::vault::VaultRoot;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MIRROR_DIR: &str = "vanguard_mirror";
const MIRROR_FILE: &str = "golden_image.svm";
const MIRROR_AAD: &[u8] = b"SecureVaultUltimate:vanguard:golden-image:v1";
const MIRROR_KEY_LABEL: &[u8] = b"SecureVaultUltimate local golden mirror key v1";

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("복구 IO 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("복구 JSON 오류: {0}")]
    Json(#[from] serde_json::Error),
    #[error("복구 설정 오류: {0}")]
    Config(#[from] config::ConfigError),
    #[error("마스터 미러 암복호화 오류")]
    Crypto,
    #[error("마스터 미러 무결성 검증 실패")]
    MirrorTampered,
}

pub type RecoveryResult<T> = Result<T, RecoveryError>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    pub restored_settings: bool,
    pub restored_vault_index_from_backup: bool,
    pub actions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenImage {
    version: u32,
    created_utc: String,
    default_settings: AppSettings,
    required_directories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenEnvelope {
    version: u32,
    nonce_b64: String,
    ciphertext_b64: String,
    sha256_b64: String,
}

pub fn ensure_master_mirror(
    settings_store: &SettingsStore,
    vault_root: &VaultRoot,
) -> RecoveryResult<()> {
    let path = mirror_path();
    if path.exists() {
        let _ = load_golden_image()?;
        return Ok(());
    }

    fs::create_dir_all(mirror_dir())?;
    let image = GoldenImage {
        version: 1,
        created_utc: Utc::now().to_rfc3339(),
        default_settings: AppSettings::default(),
        required_directories: vec![
            settings_store.root().display().to_string(),
            vault_root.data_dir().display().to_string(),
            vault_root.quarantine_dir().display().to_string(),
            vault_root.temp_dir().display().to_string(),
        ],
    };
    write_golden_image(&image)
}

pub fn flash_rollback(
    settings_store: &SettingsStore,
    vault_root: &VaultRoot,
) -> RecoveryResult<RecoveryReport> {
    let image = load_golden_image()?;
    let mut actions = Vec::new();
    fs::create_dir_all(settings_store.root())?;
    settings_store.save(&image.default_settings)?;
    actions.push("settings restored from golden mirror".to_string());

    for directory in &image.required_directories {
        fs::create_dir_all(directory)?;
        actions.push(format!("runtime directory verified: {directory}"));
    }

    let mut restored_vault_index_from_backup = false;
    let db_path = vault_root.db_path();
    let backup_path = vault_root.db_backup_path();
    if !db_path.exists() && backup_path.exists() {
        fs::copy(&backup_path, &db_path)?;
        restored_vault_index_from_backup = true;
        actions.push("vault.db restored from shadow journal".to_string());
    }

    Ok(RecoveryReport {
        restored_settings: true,
        restored_vault_index_from_backup,
        actions,
    })
}

pub fn fail_closed(exit_code: i32) -> ! {
    let mut burn = Zeroizing::new(vec![0xA5u8; 4096]);
    burn.zeroize();
    std::process::exit(exit_code);
}

fn write_golden_image(image: &GoldenImage) -> RecoveryResult<()> {
    let plain = Zeroizing::new(serde_json::to_vec(image)?);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let key = mirror_key();
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| RecoveryError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: MIRROR_AAD,
            },
        )
        .map_err(|_| RecoveryError::Crypto)?;
    let digest = Sha256::digest(&ciphertext);
    let envelope = GoldenEnvelope {
        version: 1,
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
        sha256_b64: B64.encode(digest),
    };
    fs::write(mirror_path(), serde_json::to_vec_pretty(&envelope)?)?;
    Ok(())
}

fn load_golden_image() -> RecoveryResult<GoldenImage> {
    let bytes = fs::read(mirror_path())?;
    let envelope: GoldenEnvelope = serde_json::from_slice(&bytes)?;
    let ciphertext = B64
        .decode(envelope.ciphertext_b64)
        .map_err(|_| RecoveryError::MirrorTampered)?;
    let expected = B64
        .decode(envelope.sha256_b64)
        .map_err(|_| RecoveryError::MirrorTampered)?;
    let actual = Sha256::digest(&ciphertext);
    if actual[..] != expected[..] {
        return Err(RecoveryError::MirrorTampered);
    }
    let nonce = B64
        .decode(envelope.nonce_b64)
        .map_err(|_| RecoveryError::MirrorTampered)?;
    if nonce.len() != 12 {
        return Err(RecoveryError::MirrorTampered);
    }
    let key = mirror_key();
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| RecoveryError::Crypto)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: MIRROR_AAD,
            },
        )
        .map_err(|_| RecoveryError::MirrorTampered)?;
    serde_json::from_slice(&plain).map_err(RecoveryError::from)
}

fn mirror_key() -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(MIRROR_KEY_LABEL);
    if let Ok(exe) = std::env::current_exe() {
        hasher.update(exe.to_string_lossy().as_bytes());
    }
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Zeroizing::new(key)
}

fn mirror_dir() -> PathBuf {
    config::app_data_dir().join(MIRROR_DIR)
}

fn mirror_path() -> PathBuf {
    mirror_dir().join(MIRROR_FILE)
}
