use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const EXPECTED_EXE_SHA256: &str = env!("SECURE_VAULT_EXE_SHA256_VALUE");
const EMPTY_EXE_SHA256_ANCHOR: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
        self_protection_monitor_check(),
    ]
}

pub fn release_integrity_failure() -> Option<String> {
    #[cfg(debug_assertions)]
    {
        None
    }

    #[cfg(not(debug_assertions))]
    {
        match binary_integrity_state() {
            IntegrityState::Verified => None,
            IntegrityState::MissingExpected => Some(
                "SECURE_VAULT_EXE_SHA256 빌드 앵커가 없어 배포 빌드를 시작할 수 없습니다."
                    .to_string(),
            ),
            IntegrityState::HashUnavailable(error) => Some(format!(
                "실행 파일 무결성 해시를 계산하지 못했습니다: {error}"
            )),
            IntegrityState::Mismatch { .. } => {
                Some("실행 파일 SHA-256이 배포 기준값과 다릅니다.".to_string())
            }
        }
    }
}

pub fn debugger_detected() -> bool {
    #[cfg(windows)]
    unsafe {
        // SAFETY: These Windows APIs only query the current process debug state.
        // We pass GetCurrentProcess() directly and provide a valid mutable BOOL
        // storage for CheckRemoteDebuggerPresent. No pointer is retained.
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
    match binary_integrity_state() {
        IntegrityState::Verified => StartupCheck {
            name: "Binary Integrity".to_string(),
            status: CheckStatus::Pass,
            detail: "빌드 기준 SHA-256 앵커와 일치합니다.".to_string(),
        },
        IntegrityState::Mismatch { actual, .. } => {
            let status = if cfg!(debug_assertions) {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            };
            StartupCheck {
                name: "Binary Integrity".to_string(),
                status,
                detail: format!(
                    "실행 파일 해시가 빌드 앵커와 다릅니다. 현재 해시: {}",
                    shorten(&actual)
                ),
            }
        }
        IntegrityState::MissingExpected => {
            let status = if cfg!(debug_assertions) {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            };
            StartupCheck {
                name: "Binary Integrity".to_string(),
                status,
                detail: if cfg!(debug_assertions) {
                    "개발 빌드라 배포용 해시 앵커 없이 경고 모드로 통과합니다.".to_string()
                } else {
                    "배포 빌드에 실행 파일 해시 앵커가 포함되지 않았습니다.".to_string()
                },
            }
        }
        IntegrityState::HashUnavailable(error) => StartupCheck {
            name: "Binary Integrity".to_string(),
            status: if cfg!(debug_assertions) {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            detail: format!("실행 파일 해시를 계산하지 못했습니다: {error}"),
        },
    }
}

fn self_protection_monitor_check() -> StartupCheck {
    StartupCheck {
        name: "Self-Protection Monitor".to_string(),
        status: CheckStatus::Pass,
        detail: "자체 보호 스캔과 복구 앵커가 백그라운드에서 활성화됩니다.".to_string(),
    }
}

enum IntegrityState {
    Verified,
    MissingExpected,
    HashUnavailable(String),
    Mismatch { actual: String },
}

fn binary_integrity_state() -> IntegrityState {
    let hash = match current_exe_sha256() {
        Ok(hash) => hash,
        Err(error) => return IntegrityState::HashUnavailable(error.to_string()),
    };
    let expected = std::hint::black_box(EXPECTED_EXE_SHA256).trim();
    if expected == EMPTY_EXE_SHA256_ANCHOR || expected.len() != 64 {
        return IntegrityState::MissingExpected;
    }
    if expected.eq_ignore_ascii_case(&hash) {
        IntegrityState::Verified
    } else {
        IntegrityState::Mismatch { actual: hash }
    }
}

pub fn current_exe_sha256() -> std::io::Result<String> {
    let exe = std::env::current_exe()?;
    sha256_file(&exe)
}

fn sha256_file(path: &PathBuf) -> std::io::Result<String> {
    let mut bytes = fs::read(path)?;
    normalize_exe_bytes(&mut bytes);
    let hash = Sha256::digest(bytes);
    Ok(hash.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn normalize_exe_bytes(bytes: &mut [u8]) {
    normalize_embedded_hash_anchor(bytes);
    normalize_pe_mutable_fields(bytes);
    normalize_codeview_records(bytes);
}

fn normalize_embedded_hash_anchor(bytes: &mut [u8]) {
    let expected = std::hint::black_box(EXPECTED_EXE_SHA256).as_bytes();
    if expected.len() != 64 || expected == EMPTY_EXE_SHA256_ANCHOR.as_bytes() {
        return;
    }
    let replacement = EMPTY_EXE_SHA256_ANCHOR.as_bytes();
    for window_start in 0..=bytes.len().saturating_sub(expected.len()) {
        if &bytes[window_start..window_start + expected.len()] == expected {
            bytes[window_start..window_start + expected.len()].copy_from_slice(replacement);
        }
    }
}

fn normalize_pe_mutable_fields(bytes: &mut [u8]) {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return;
    }
    let Some(pe_offset) = read_u32_le(bytes, 0x3c).map(|value| value as usize) else {
        return;
    };
    if pe_offset
        .checked_add(0x18)
        .is_none_or(|end| end > bytes.len())
        || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0"
    {
        return;
    }

    let file_header = pe_offset + 4;
    let section_count = read_u16_le(bytes, file_header + 2).unwrap_or(0) as usize;
    let optional_header_size = read_u16_le(bytes, file_header + 16).unwrap_or(0) as usize;
    let optional_header = file_header + 20;
    if optional_header
        .checked_add(optional_header_size)
        .is_none_or(|end| end > bytes.len())
    {
        return;
    }

    zero_range(bytes, file_header + 4, 4);
    zero_range(bytes, optional_header + 64, 4);

    let data_directory = match read_u16_le(bytes, optional_header) {
        Some(0x10b) => optional_header + 96,
        Some(0x20b) => optional_header + 112,
        _ => return,
    };
    if data_directory
        .checked_add(16 * 8)
        .is_none_or(|end| end > optional_header + optional_header_size)
    {
        return;
    }

    let debug_rva = read_u32_le(bytes, data_directory + 6 * 8).unwrap_or(0);
    let debug_size = read_u32_le(bytes, data_directory + 6 * 8 + 4).unwrap_or(0);
    zero_range(bytes, data_directory + 4 * 8, 8);
    zero_range(bytes, data_directory + 6 * 8, 8);

    let section_table = optional_header + optional_header_size;
    if let Some(debug_offset) =
        rva_to_file_offset(bytes, section_table, section_count, debug_rva, debug_size)
    {
        zero_range(bytes, debug_offset, debug_size as usize);
    }
}

fn rva_to_file_offset(
    bytes: &[u8],
    section_table: usize,
    section_count: usize,
    rva: u32,
    size: u32,
) -> Option<usize> {
    if rva == 0 || size == 0 {
        return None;
    }
    for index in 0..section_count {
        let section = section_table.checked_add(index.checked_mul(40)?)?;
        if section.checked_add(40)? > bytes.len() {
            return None;
        }
        let virtual_size = read_u32_le(bytes, section + 8)?;
        let virtual_address = read_u32_le(bytes, section + 12)?;
        let raw_size = read_u32_le(bytes, section + 16)?;
        let raw_pointer = read_u32_le(bytes, section + 20)?;
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva < virtual_address.saturating_add(span) {
            let offset = raw_pointer.checked_add(rva - virtual_address)? as usize;
            if offset.checked_add(size as usize)? <= bytes.len() {
                return Some(offset);
            }
        }
    }
    None
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let range = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([range[0], range[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let range = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([range[0], range[1], range[2], range[3]]))
}

fn zero_range(bytes: &mut [u8], offset: usize, len: usize) {
    if let Some(range) = offset
        .checked_add(len)
        .and_then(|end| bytes.get_mut(offset..end))
    {
        range.fill(0);
    }
}

fn normalize_codeview_records(bytes: &mut [u8]) {
    let mut offset = 0usize;
    while let Some(position) = find_signature(&bytes[offset..], b"RSDS") {
        let start = offset + position;
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|nul| start + nul + 1)
            .unwrap_or_else(|| start.saturating_add(512).min(bytes.len()));
        zero_range(bytes, start, end.saturating_sub(start));
        offset = end;
    }

    offset = 0;
    while let Some(position) = find_signature(&bytes[offset..], b"NB10") {
        let start = offset + position;
        let end = start.saturating_add(512).min(bytes.len());
        zero_range(bytes, start, end.saturating_sub(start));
        offset = end;
    }
}

fn find_signature(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn shorten(hash: &str) -> String {
    if hash.len() <= 18 {
        hash.to_string()
    } else {
        format!("{}...{}", &hash[..12], &hash[hash.len() - 6..])
    }
}
