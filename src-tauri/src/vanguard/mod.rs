pub mod recovery;

use crate::core::config::{AppSettings, SettingsStore};
use crate::security;
use crate::threat;
use crate::vault::VaultRoot;
use crate::AppState;
use chrono::Utc;
use recovery::{RecoveryError, RecoveryReport};
use serde::Serialize;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VanguardError {
    #[error("디버거 감지")]
    DebuggerDetected,
    #[error("실행 파일 해시 변조 감지")]
    BinaryTamper,
    #[error("세션 잠금 오류")]
    SessionLock,
    #[error("설정 잠금 오류")]
    SettingsLock,
    #[error("활동 시간 잠금 오류")]
    ActivityLock,
    #[error("위협 피드 동기화 시간 잠금 오류")]
    ThreatSyncLock,
    #[error("금고 데이터 오염 감지: {0}")]
    VaultContamination(String),
    #[error("복구 엔진 오류: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("IO 오류: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VanguardLog {
    pub utc: String,
    pub level: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VanguardScanReport {
    pub trigger: String,
    pub ok: bool,
    pub logs: Vec<String>,
}

pub fn install_master_mirror(
    settings_store: &SettingsStore,
    vault_root: &VaultRoot,
) -> Result<(), VanguardError> {
    recovery::ensure_master_mirror(settings_store, vault_root)?;
    Ok(())
}

pub fn spawn(app: &tauri::App) {
    let handle = app.handle().clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let Some(state) = handle.try_state::<AppState>() else {
            continue;
        };

        if let Err(error) = tick(&handle, &state) {
            critical_recover_or_exit(&handle, &state, error);
        }
    });
}

pub fn scan_state(state: &AppState, trigger: &str) -> Result<VanguardScanReport, VanguardError> {
    let mut logs = vec![format!("[SELF-PROTECTION] {trigger} 자체 보호 스캔 시작")];
    if security::debugger_detected() {
        if cfg!(debug_assertions) {
            logs.push(
                "[SELF-PROTECTION] 개발 빌드 경고: 디버거가 감지되었지만 세션을 유지합니다."
                    .to_string(),
            );
        } else {
            return Err(VanguardError::DebuggerDetected);
        }
    } else {
        logs.push("[SELF-PROTECTION] anti-debug probe clear".to_string());
    }

    if binary_changed(state)? {
        if cfg!(debug_assertions) {
            logs.push(
                "[SELF-PROTECTION] 개발 빌드 경고: 실행 파일 해시 앵커가 일치하지 않습니다."
                    .to_string(),
            );
        } else {
            return Err(VanguardError::BinaryTamper);
        }
    } else {
        logs.push("[SELF-PROTECTION] executable hash anchor verified".to_string());
    }

    let guard = state
        .session
        .lock()
        .map_err(|_| VanguardError::SessionLock)?;
    if let Some(session) = guard.as_ref() {
        session
            .vanguard_guard_tick()
            .map_err(|error| VanguardError::VaultContamination(error.to_string()))?;
        logs.push("[SELF-PROTECTION] protected data blocks and guard files verified".to_string());
    } else {
        logs.push("[SELF-PROTECTION] vault session locked; key material absent".to_string());
    }

    Ok(VanguardScanReport {
        trigger: trigger.to_string(),
        ok: true,
        logs,
    })
}

fn tick(
    handle: &tauri::AppHandle,
    state: &tauri::State<'_, AppState>,
) -> Result<(), VanguardError> {
    if security::debugger_detected() {
        drop_session(state)?;
        if cfg!(debug_assertions) {
            emit_log(
                handle,
                "info",
                "[SELF-PROTECTION] 개발 빌드 경고: 디버거 감지, 강제 종료 생략",
            );
        } else {
            emit_log(
                handle,
                "critical",
                "[SELF-PROTECTION] 디버거 감지 -> 세션 키 파기",
            );
            return Err(VanguardError::DebuggerDetected);
        }
    }

    enforce_idle_lock(state)?;
    maybe_run_interval_scan(handle, state)?;
    maybe_sync_threat_feed(state)?;
    Ok(())
}

fn maybe_run_interval_scan(
    handle: &tauri::AppHandle,
    state: &tauri::State<'_, AppState>,
) -> Result<(), VanguardError> {
    let settings = current_settings(state)?;
    let interval = Duration::from_secs(settings.vanguard_scan_interval_minutes * 60);
    let due = state
        .last_vanguard_scan
        .lock()
        .map(|mut last| {
            if last.elapsed() < interval {
                return false;
            }
            *last = Instant::now();
            true
        })
        .map_err(|_| VanguardError::ActivityLock)?;

    if due {
        let report = scan_state(state.inner(), "scheduled watchdog")?;
        for log in report.logs {
            emit_log(handle, "info", &log);
        }
    }
    Ok(())
}

fn enforce_idle_lock(state: &tauri::State<'_, AppState>) -> Result<(), VanguardError> {
    let auto_lock_minutes = current_settings(state)?.auto_lock_minutes;
    let idle = state
        .last_activity
        .lock()
        .map(|last| last.elapsed().as_secs() >= auto_lock_minutes * 60)
        .map_err(|_| VanguardError::ActivityLock)?;
    if idle {
        drop_session(state)?;
    }
    Ok(())
}

fn maybe_sync_threat_feed(state: &tauri::State<'_, AppState>) -> Result<(), VanguardError> {
    let settings = current_settings(state)?;
    if settings.threat_feed_url.is_empty() {
        return Ok(());
    }
    let should_sync = state
        .last_threat_sync
        .lock()
        .map(|mut last| {
            let due = last
                .map(|instant| instant.elapsed().as_secs() >= settings.threat_update_hours * 3600)
                .unwrap_or(true);
            if due {
                *last = Some(Instant::now());
            }
            due
        })
        .map_err(|_| VanguardError::ThreatSyncLock)?;
    if should_sync {
        if let Err(error) = threat::sync(&settings) {
            eprintln!("위협 인텔리전스 동기화 실패: {error}");
        }
    }
    Ok(())
}

fn current_settings(state: &tauri::State<'_, AppState>) -> Result<AppSettings, VanguardError> {
    state
        .settings
        .lock()
        .map(|settings| settings.clone())
        .map_err(|_| VanguardError::SettingsLock)
}

fn binary_changed(state: &AppState) -> Result<bool, VanguardError> {
    if security::release_integrity_failure().is_some() {
        return Ok(true);
    }
    Ok(state
        .binary_hash
        .as_ref()
        .and_then(|expected| {
            security::current_exe_sha256()
                .ok()
                .map(|actual| !actual.eq_ignore_ascii_case(expected))
        })
        .unwrap_or(false))
}

fn drop_session(state: &tauri::State<'_, AppState>) -> Result<(), VanguardError> {
    state
        .session
        .lock()
        .map(|mut guard| {
            let _ = guard.take();
        })
        .map_err(|_| VanguardError::SessionLock)
}

fn critical_recover_or_exit(
    handle: &tauri::AppHandle,
    state: &tauri::State<'_, AppState>,
    error: VanguardError,
) -> ! {
    let _ = drop_session(state);
    emit_log(
        handle,
        "critical",
        &format!(
            "[SELF-PROTECTION] 코어 손상 감지 -> 지능형 복구 프로토콜 직접 통제 개시: {error}"
        ),
    );
    match recovery::flash_rollback(&state.settings_store, &state.vault_root) {
        Ok(report) => {
            emit_recovery_report(handle, &report);
            std::process::exit(176);
        }
        Err(recovery_error) => {
            emit_log(
                handle,
                "critical",
                &format!(
                    "[SELF-PROTECTION] 마스터 미러 복구 실패 -> fail-closed: {recovery_error}"
                ),
            );
            recovery::fail_closed(1);
        }
    }
}

fn emit_recovery_report(handle: &tauri::AppHandle, report: &RecoveryReport) {
    emit_log(
        handle,
        "critical",
        "[SELF-PROTECTION] 마스터 미러 복원 완료 -> 오염 세션 종료",
    );
    for action in &report.actions {
        emit_log(handle, "critical", &format!("[RECOVERY] {action}"));
    }
}

fn emit_log(handle: &tauri::AppHandle, level: &'static str, message: &str) {
    let _ = handle.emit(
        "vanguard-log",
        VanguardLog {
            utc: Utc::now().to_rfc3339(),
            level,
            message: message.to_string(),
        },
    );
}
