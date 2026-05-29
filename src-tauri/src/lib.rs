mod core;
mod error;
mod security;
mod shield;
mod threat;
mod updates;
mod vanguard;
mod vault;

use crate::core::config::{self, AppSettings, SettingsStore, SettingsUpdate, SettingsView};
use crate::core::firewall;
use crate::core::secure_fs::secure_wipe_path;
use security::StartupCheck;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use tauri::Manager;
use threat::ThreatFeedStatus;
use vault::{
    ConsistencyReport, EntryKind, EntryOperationResult, EntryStatus, FolderOperationResult,
    VaultEntry, VaultRoot, VaultSession,
};

pub(crate) struct AppState {
    pub(crate) vault_root: VaultRoot,
    pub(crate) settings_store: SettingsStore,
    pub(crate) settings: Mutex<AppSettings>,
    pub(crate) session: Mutex<Option<VaultSession>>,
    pub(crate) last_activity: Mutex<Instant>,
    pub(crate) last_threat_sync: Mutex<Option<Instant>>,
    pub(crate) binary_hash: Option<String>,
    pub(crate) last_vanguard_scan: Mutex<Instant>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryView {
    id: String,
    parent_id: Option<String>,
    name: String,
    kind: String,
    size: u64,
    chunk_count: usize,
    created_utc: String,
    status: String,
    locked_folder_path: Option<String>,
}

#[tauri::command]
fn startup_checks() -> Vec<StartupCheck> {
    security::run_startup_checks()
}

#[tauri::command]
fn ecosystem_shield_status() -> shield::ShieldStatus {
    shield::status()
}

#[tauri::command]
fn ecosystem_shield_challenge_response(
    challenge_b64: String,
) -> Result<shield::ChallengeResponse, String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    firewall_gate("ecosystem_shield_challenge_response")?;
    let challenge = B64
        .decode(challenge_b64.trim())
        .map_err(|_| "챌린지 데이터 형식이 올바르지 않습니다.".to_string())?;
    shield::challenge_response(&challenge).map_err(|error| error.to_string())
}

#[tauri::command]
async fn check_secure_update(app: tauri::AppHandle) -> Result<updates::UpdateStatus, String> {
    firewall_gate("check_secure_update")?;
    updates::check(app).await
}

#[tauri::command]
async fn install_secure_update(app: tauri::AppHandle) -> Result<(), String> {
    firewall_gate("install_secure_update")?;
    updates::install(app).await
}

#[tauri::command]
fn vanguard_scan_now(
    state: tauri::State<'_, AppState>,
) -> Result<vanguard::VanguardScanReport, String> {
    firewall_gate("vanguard_scan_now")?;
    vanguard::scan_state(state.inner(), "manual command").map_err(|error| error.to_string())
}

#[tauri::command]
fn get_settings(state: tauri::State<'_, AppState>) -> Result<SettingsView, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())?
        .clone();
    Ok(SettingsView::from(&settings))
}

#[tauri::command]
fn update_settings(
    state: tauri::State<'_, AppState>,
    update: SettingsUpdate,
) -> Result<SettingsView, String> {
    let settings = state
        .settings_store
        .update(update)
        .map_err(|error| error.to_string())?;
    *state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())? = settings.clone();
    Ok(SettingsView::from(&settings))
}

#[tauri::command]
fn set_decoy_password(
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<SettingsView, String> {
    let settings = state
        .settings_store
        .set_decoy_password(password)
        .map_err(|error| error.to_string())?;
    *state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())? = settings.clone();
    Ok(SettingsView::from(&settings))
}

#[tauri::command]
fn clear_decoy_password(state: tauri::State<'_, AppState>) -> Result<SettingsView, String> {
    let settings = state
        .settings_store
        .clear_decoy_password()
        .map_err(|error| error.to_string())?;
    *state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())? = settings.clone();
    Ok(SettingsView::from(&settings))
}

#[tauri::command]
fn threat_feed_status(state: tauri::State<'_, AppState>) -> Result<ThreatFeedStatus, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())?
        .clone();
    Ok(threat::status(&settings))
}

#[tauri::command]
fn sync_threat_intelligence(state: tauri::State<'_, AppState>) -> Result<ThreatFeedStatus, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())?
        .clone();
    let result = threat::sync(&settings).map_err(|error| error.to_string())?;
    *state
        .last_threat_sync
        .lock()
        .map_err(|_| "위협 피드 동기화 시간 잠금 오류".to_string())? = Some(Instant::now());
    Ok(result)
}

#[tauri::command]
fn sync_threat_intelligence_from_url(feed_url: String) -> Result<ThreatFeedStatus, String> {
    firewall_gate("sync_threat_intelligence_from_url")?;
    threat::sync_url(feed_url.trim(), true).map_err(|error| error.to_string())
}

#[tauri::command]
fn vault_exists(state: tauri::State<'_, AppState>) -> bool {
    state.vault_root.exists()
}

#[tauri::command]
fn create_vault(state: tauri::State<'_, AppState>, password: String) -> Result<(), String> {
    firewall_gate("create_vault")?;
    state
        .vault_root
        .create(&password)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn unlock_vault(
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<ConsistencyReport, String> {
    firewall_gate("unlock_vault")?;
    let (session, report) = state
        .vault_root
        .unlock(&password)
        .map_err(|error| error.to_string())?;
    *state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())? = Some(session);
    *state
        .last_activity
        .lock()
        .map_err(|_| "활동 시간 갱신 오류".to_string())? = Instant::now();
    Ok(report)
}

#[tauri::command]
fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    if let Some(session) = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?
        .take()
    {
        session.lock().map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn touch_session(state: tauri::State<'_, AppState>) -> Result<(), String> {
    *state
        .last_activity
        .lock()
        .map_err(|_| "활동 시간 갱신 오류".to_string())? = Instant::now();
    Ok(())
}

#[tauri::command]
fn list_entries(state: tauri::State<'_, AppState>) -> Result<Vec<EntryView>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    Ok(session
        .list_entries()
        .into_iter()
        .map(entry_to_view)
        .collect())
}

#[tauri::command]
fn import_paths(
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
    remove_original: bool,
) -> Result<Vec<EntryView>, String> {
    firewall_gate("import_paths")?;
    action_scan_if_enabled(&state, "import paths")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    let mut imported = Vec::new();
    for path in paths {
        let entries = session
            .import_path(&PathBuf::from(path), remove_original)
            .map_err(|error| error.to_string())?;
        imported.extend(entries.into_iter().map(entry_to_view));
    }
    Ok(imported)
}

#[tauri::command]
fn lock_folders_in_place(
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
    secure_delete_originals: bool,
) -> Result<Vec<FolderOperationResult>, String> {
    firewall_gate("lock_folders_in_place")?;
    action_scan_if_enabled(&state, "lock folders in place")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    let folders: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    let results = session.lock_folders_in_place(&folders, secure_delete_originals);
    let locked_paths: Vec<PathBuf> = results
        .iter()
        .filter(|result| result.ok)
        .map(|result| PathBuf::from(&result.path))
        .collect();
    config::register_external_locks(&locked_paths).map_err(|error| error.to_string())?;
    Ok(results)
}

#[tauri::command]
fn unlock_folders_in_place(
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
) -> Result<Vec<FolderOperationResult>, String> {
    firewall_gate("unlock_folders_in_place")?;
    action_scan_if_enabled(&state, "unlock folders in place")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    let folders: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    let results = session.unlock_folders_in_place(&folders);
    let unlocked_paths: Vec<PathBuf> = results
        .iter()
        .filter(|result| result.ok)
        .map(|result| PathBuf::from(&result.path))
        .collect();
    config::unregister_external_locks(&unlocked_paths).map_err(|error| error.to_string())?;
    Ok(results)
}

#[tauri::command]
fn unlock_locked_entries_to_original_paths(
    state: tauri::State<'_, AppState>,
    entry_ids: Vec<String>,
) -> Result<Vec<EntryOperationResult>, String> {
    firewall_gate("unlock_locked_entries_to_original_paths")?;
    action_scan_if_enabled(&state, "restore protected folders to original paths")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    let original_paths = session.locked_folder_paths_for_entries(&entry_ids);
    let results = session.unlock_locked_entries_to_original_paths(&entry_ids);
    let restored_paths: Vec<PathBuf> = original_paths
        .into_iter()
        .zip(results.iter())
        .filter_map(|(path, result)| result.ok.then_some(path))
        .collect();
    if !restored_paths.is_empty() {
        config::unregister_external_locks(&restored_paths).map_err(|error| error.to_string())?;
    }
    Ok(results)
}

#[tauri::command]
fn check_folders_in_place(
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
) -> Result<Vec<FolderOperationResult>, String> {
    firewall_gate("check_folders_in_place")?;
    action_scan_if_enabled(&state, "check locked folders")?;
    let guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    let folders: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    Ok(session.check_folders_in_place(&folders))
}

#[tauri::command]
fn restore_entry(
    state: tauri::State<'_, AppState>,
    entry_id: String,
    destination: String,
) -> Result<String, String> {
    firewall_gate("restore_entry")?;
    action_scan_if_enabled(&state, "restore entry")?;
    let guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    let restored = session
        .restore_entry(&entry_id, &PathBuf::from(destination))
        .map_err(|error| error.to_string())?;
    Ok(restored.display().to_string())
}

#[tauri::command]
fn restore_entries(
    state: tauri::State<'_, AppState>,
    entry_ids: Vec<String>,
    destination: String,
) -> Result<Vec<EntryOperationResult>, String> {
    firewall_gate("restore_entries")?;
    action_scan_if_enabled(&state, "restore entries")?;
    let guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    Ok(session.restore_entries(&entry_ids, &PathBuf::from(destination)))
}

#[tauri::command]
fn check_entries(
    state: tauri::State<'_, AppState>,
    entry_ids: Vec<String>,
) -> Result<Vec<EntryOperationResult>, String> {
    firewall_gate("check_entries")?;
    action_scan_if_enabled(&state, "check entries")?;
    let guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_ref()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    Ok(session.check_entries(&entry_ids))
}

#[tauri::command]
fn delete_entries(
    state: tauri::State<'_, AppState>,
    entry_ids: Vec<String>,
) -> Result<Vec<EntryOperationResult>, String> {
    firewall_gate("delete_entries")?;
    action_scan_if_enabled(&state, "delete entries")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "금고가 잠겨 있습니다.".to_string())?;
    Ok(session.delete_entries(&entry_ids))
}

#[tauri::command]
fn destroy_all_vault_data(
    state: tauri::State<'_, AppState>,
    confirm_delete_all: bool,
) -> Result<(), String> {
    firewall_gate("destroy_all_vault_data")?;
    if !confirm_delete_all {
        return Err("전체 데이터 삭제 확인 체크가 필요합니다.".to_string());
    }

    let registry_locks = config::tracked_external_locks().map_err(|error| error.to_string())?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "세션 잠금 오류".to_string())?;
    if let Some(session) = guard.as_ref() {
        session
            .destroy_tracked_external_locks()
            .map_err(|error| error.to_string())?;
    }
    for folder in registry_locks {
        let lock_root = folder.join(".svu_lock");
        if lock_root.exists() {
            secure_wipe_path(&lock_root).map_err(|error| error.to_string())?;
        }
    }
    guard.take();
    drop(guard);

    state
        .vault_root
        .destroy_all_data()
        .map_err(|error| error.to_string())?;
    config::clear_external_locks().map_err(|error| error.to_string())?;
    *state
        .settings
        .lock()
        .map_err(|_| "설정 잠금 오류".to_string())? = AppSettings::default();
    *state
        .last_threat_sync
        .lock()
        .map_err(|_| "위협 피드 동기화 시간 잠금 오류".to_string())? = None;
    Ok(())
}

fn entry_to_view(entry: VaultEntry) -> EntryView {
    EntryView {
        id: entry.id,
        parent_id: entry.parent_id,
        name: entry.name,
        kind: match entry.kind {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
        }
        .to_string(),
        size: entry.size,
        chunk_count: entry.chunks.len(),
        created_utc: entry.created_utc,
        status: match entry.status {
            EntryStatus::Ok => "ok",
            EntryStatus::Missing => "missing",
            EntryStatus::Partial => "partial",
        }
        .to_string(),
        locked_folder_path: entry.locked_folder_path,
    }
}

fn firewall_gate(command: &'static str) -> Result<(), String> {
    firewall::guard_ipc(command).map_err(|error| error.to_string())
}

fn action_scan_if_enabled(
    state: &tauri::State<'_, AppState>,
    trigger: &'static str,
) -> Result<(), String> {
    let enabled = state
        .settings
        .lock()
        .map(|settings| settings.scan_on_action_integrity)
        .map_err(|_| "설정 잠금 오류".to_string())?;
    if enabled {
        vanguard::scan_state(state.inner(), trigger).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn run_secure_uninstall_wipe() -> Result<(), String> {
    let settings_store = SettingsStore::default();
    let settings = settings_store.load().map_err(|error| error.to_string())?;
    if !settings.secure_wipe_on_uninstall {
        return Ok(());
    }

    for folder in config::tracked_external_locks().map_err(|error| error.to_string())? {
        let lock_root = folder.join(".svu_lock");
        if lock_root.exists() {
            secure_wipe_path(&lock_root).map_err(|error| error.to_string())?;
        }
    }
    let root = config::app_data_dir();
    if root.exists() {
        secure_wipe_path(&root).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let settings_store = SettingsStore::default();
    let settings = settings_store.load().unwrap_or_default();
    let binary_hash = security::current_exe_sha256().ok();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState {
            vault_root: VaultRoot::default(),
            settings_store,
            settings: Mutex::new(settings),
            session: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            last_threat_sync: Mutex::new(None),
            binary_hash,
            last_vanguard_scan: Mutex::new(Instant::now()),
        })
        .setup(|app| {
            if let Some(reason) = security::release_integrity_failure() {
                #[cfg(debug_assertions)]
                eprintln!("안전 시뮬레이션 모드 구동 중: {reason}");
                #[cfg(not(debug_assertions))]
                {
                    eprintln!("{reason}");
                    std::process::exit(177);
                }
            }
            if let Some(state) = app.handle().try_state::<AppState>() {
                vanguard::install_master_mirror(&state.settings_store, &state.vault_root).map_err(
                    |error| -> Box<dyn std::error::Error> {
                        Box::new(std::io::Error::other(error.to_string()))
                    },
                )?;
            }
            vanguard::spawn(app);
            shield::spawn(app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            startup_checks,
            ecosystem_shield_status,
            ecosystem_shield_challenge_response,
            check_secure_update,
            install_secure_update,
            vanguard_scan_now,
            get_settings,
            update_settings,
            set_decoy_password,
            clear_decoy_password,
            threat_feed_status,
            sync_threat_intelligence,
            sync_threat_intelligence_from_url,
            vault_exists,
            create_vault,
            unlock_vault,
            lock_vault,
            touch_session,
            list_entries,
            import_paths,
            lock_folders_in_place,
            unlock_folders_in_place,
            unlock_locked_entries_to_original_paths,
            check_folders_in_place,
            restore_entry,
            restore_entries,
            check_entries,
            delete_entries,
            destroy_all_vault_data
        ])
        .run(tauri::generate_context!())
        .expect("failed to run SecureVault Ultimate");
}
