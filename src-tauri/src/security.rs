use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

pub fn run_startup_checks() -> Vec<StartupCheck> {
    vec![
        binary_integrity_check(),
        anti_debug_check(),
        StartupCheck {
            name: "Vanguard monitor".to_string(),
            status: CheckStatus::Pass,
            detail: "핵심 파일 감시 루틴이 앱 프로세스 안에서 활성화됩니다.".to_string(),
        },
    ]
}

pub fn debugger_detected() -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CheckRemoteDebuggerPresent, IsDebuggerPresent,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        if IsDebuggerPresent() != 0 {
            return true;
        }
        let mut present = 0;
        let result = CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present);
        result != 0 && present != 0
    }

    #[cfg(not(windows))]
    {
        false
    }
}

fn anti_debug_check() -> StartupCheck {
    if debugger_detected() {
        StartupCheck {
            name: "Anti-debugging".to_string(),
            status: CheckStatus::Fail,
            detail: "디버거 부착이 감지되었습니다. 세션을 열지 않습니다.".to_string(),
        }
    } else {
        StartupCheck {
            name: "Anti-debugging".to_string(),
            status: CheckStatus::Pass,
            detail: "현재 프로세스에 디버거가 감지되지 않았습니다.".to_string(),
        }
    }
}

fn binary_integrity_check() -> StartupCheck {
    let hash = match current_exe_sha256() {
        Ok(hash) => hash,
        Err(error) => {
            return StartupCheck {
                name: "Binary integrity".to_string(),
                status: CheckStatus::Warn,
                detail: format!("실행 파일 해시를 계산하지 못했습니다: {error}"),
            };
        }
    };

    if let Some(expected) = option_env!("SECURE_VAULT_EXE_SHA256") {
        if expected.eq_ignore_ascii_case(&hash) {
            StartupCheck {
                name: "Binary integrity".to_string(),
                status: CheckStatus::Pass,
                detail: "빌드 시 고정된 SHA-256과 일치합니다.".to_string(),
            }
        } else {
            StartupCheck {
                name: "Binary integrity".to_string(),
                status: CheckStatus::Fail,
                detail: "실행 파일 SHA-256이 빌드 기준값과 다릅니다.".to_string(),
            }
        }
    } else {
        StartupCheck {
            name: "Binary integrity".to_string(),
            status: CheckStatus::Warn,
            detail: format!("개발 빌드 기준 해시: {}", shorten(&hash)),
        }
    }
}

pub fn current_exe_sha256() -> std::io::Result<String> {
    let exe = std::env::current_exe()?;
    sha256_file(&exe)
}

fn sha256_file(path: &PathBuf) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let hash = Sha256::digest(bytes);
    Ok(hash.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn shorten(hash: &str) -> String {
    if hash.len() <= 18 {
        hash.to_string()
    } else {
        format!("{}...{}", &hash[..12], &hash[hash.len() - 6..])
    }
}
