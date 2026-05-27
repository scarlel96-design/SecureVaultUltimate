use crate::security;
use thiserror::Error;

const IPC_ALLOWLIST: &[&str] = &[
    "startup_checks",
    "get_settings",
    "update_settings",
    "set_decoy_password",
    "clear_decoy_password",
    "threat_feed_status",
    "sync_threat_intelligence",
    "vanguard_scan_now",
    "vault_exists",
    "create_vault",
    "unlock_vault",
    "lock_vault",
    "touch_session",
    "list_entries",
    "import_paths",
    "lock_folders_in_place",
    "unlock_folders_in_place",
    "check_folders_in_place",
    "restore_entry",
    "restore_entries",
    "check_entries",
    "delete_entries",
    "destroy_all_vault_data",
];

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("허용되지 않은 IPC 명령입니다: {0}")]
    UnexpectedIpc(String),
    #[error("디버거가 감지되어 요청을 차단했습니다.")]
    DebuggerDetected,
}

pub type FirewallResult<T> = Result<T, FirewallError>;

pub fn guard_ipc(command: &'static str) -> FirewallResult<()> {
    if !IPC_ALLOWLIST.contains(&command) {
        return Err(FirewallError::UnexpectedIpc(command.to_string()));
    }
    if security::debugger_detected() {
        return Err(FirewallError::DebuggerDetected);
    }
    Ok(())
}
