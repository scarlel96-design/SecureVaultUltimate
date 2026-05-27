use crate::core::config::{app_data_dir, ensure_parent, AppSettings};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FEED_FILE: &str = "threat_feed.json";
const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
const ED25519_REQUIRED: usize = 1;
const ML_DSA_REQUIRED: usize = 1;
const THRESHOLD_REQUIRED: usize = 2;
const THRESHOLD_TOTAL: usize = 3;

// Production release keys must be provisioned by the publisher pipeline.
// Empty anchors deliberately make remote updates fail closed.
const ED25519_VERIFYING_KEY_IDS: [&str; 0] = [];
const ML_DSA_VERIFYING_KEY_IDS: [&str; 0] = [];

#[derive(Debug, Error)]
pub enum ThreatError {
    #[error("위협 피드 URL이 설정되지 않았습니다.")]
    NotConfigured,
    #[error("위협 피드 IO 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("위협 피드 JSON 오류: {0}")]
    Json(#[from] serde_json::Error),
    #[error("위협 피드 네트워크 오류: {0}")]
    Network(String),
    #[error("위협 피드 형식 오류: {0}")]
    InvalidFeed(String),
}

pub type ThreatResult<T> = Result<T, ThreatError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatFeedStatus {
    pub configured: bool,
    pub last_checked_utc: Option<String>,
    pub version: Option<String>,
    pub ransomware_extension_count: usize,
    pub yara_rule_count: usize,
    pub trusted_process_count: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedThreatFeed {
    version: String,
    generated_utc: String,
    payload_b64: String,
    payload_sha256: String,
    threshold: SignatureThreshold,
    signatures: Vec<FeedSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureThreshold {
    required: usize,
    total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FeedSignature {
    algorithm: String,
    key_id: String,
    signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatFeedPayload {
    version: String,
    generated_utc: String,
    ransomware_extensions: Vec<String>,
    yara_rules: Vec<YaraRule>,
    trusted_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraRule {
    id: String,
    name: String,
    rule: String,
}

pub fn status(settings: &AppSettings) -> ThreatFeedStatus {
    match read_local_payload() {
        Ok(Some(payload)) => ThreatFeedStatus {
            configured: !settings.threat_feed_url.is_empty(),
            last_checked_utc: Some(payload.generated_utc.clone()),
            version: Some(payload.version.clone()),
            ransomware_extension_count: payload.ransomware_extensions.len(),
            yara_rule_count: payload.yara_rules.len(),
            trusted_process_count: payload.trusted_processes.len(),
            detail: "로컬 위협 인텔리전스 DB가 준비되어 있습니다.".to_string(),
        },
        Ok(None) => ThreatFeedStatus {
            configured: !settings.threat_feed_url.is_empty(),
            last_checked_utc: None,
            version: None,
            ransomware_extension_count: 0,
            yara_rule_count: 0,
            trusted_process_count: 0,
            detail: if settings.threat_feed_url.is_empty() {
                "피드 URL이 비어 있어 오프라인 모드로 동작합니다.".to_string()
            } else {
                "아직 내려받은 피드가 없습니다.".to_string()
            },
        },
        Err(error) => ThreatFeedStatus {
            configured: !settings.threat_feed_url.is_empty(),
            last_checked_utc: None,
            version: None,
            ransomware_extension_count: 0,
            yara_rule_count: 0,
            trusted_process_count: 0,
            detail: format!("로컬 피드를 읽지 못했습니다: {error}"),
        },
    }
}

pub fn sync(settings: &AppSettings) -> ThreatResult<ThreatFeedStatus> {
    if settings.threat_feed_url.is_empty() {
        return Err(ThreatError::NotConfigured);
    }

    let mut downloaded = Zeroizing::new(download_feed(&settings.threat_feed_url)?);
    let payload = match verify_and_decode(&downloaded) {
        Ok(payload) => payload,
        Err(_) => fail_fast(downloaded),
    };
    downloaded.zeroize();
    write_local_payload(&payload)?;
    Ok(ThreatFeedStatus {
        configured: true,
        last_checked_utc: Some(Utc::now().to_rfc3339()),
        version: Some(payload.version.clone()),
        ransomware_extension_count: payload.ransomware_extensions.len(),
        yara_rule_count: payload.yara_rules.len(),
        trusted_process_count: payload.trusted_processes.len(),
        detail: "하이브리드 임계치 서명 검증을 통과한 피드를 반영했습니다.".to_string(),
    })
}

fn verify_and_decode(bytes: &[u8]) -> ThreatResult<ThreatFeedPayload> {
    let signed: SignedThreatFeed = serde_json::from_slice(bytes)?;
    if signed.threshold.required != THRESHOLD_REQUIRED || signed.threshold.total != THRESHOLD_TOTAL
    {
        return Err(ThreatError::InvalidFeed(
            "임계치 서명 정책이 앱 고정 정책과 다릅니다.".to_string(),
        ));
    }

    let mut payload = Zeroizing::new(
        B64.decode(signed.payload_b64.as_bytes())
            .map_err(|_| ThreatError::InvalidFeed("payload_b64 디코딩 실패".to_string()))?,
    );
    let actual_hash = hex_lower(&Sha256::digest(&payload));
    if actual_hash != signed.payload_sha256 {
        return Err(ThreatError::InvalidFeed(
            "payload SHA-256 체크섬이 일치하지 않습니다.".to_string(),
        ));
    }

    if !hybrid_threshold_verified(&payload, &signed.signatures) {
        payload.zeroize();
        return Err(ThreatError::InvalidFeed(
            "하이브리드 임계치 서명 검증 실패".to_string(),
        ));
    }

    let parsed = serde_json::from_slice(&payload)?;
    payload.zeroize();
    Ok(parsed)
}

fn hybrid_threshold_verified(payload: &[u8], signatures: &[FeedSignature]) -> bool {
    let mut ed25519_valid = 0usize;
    let mut ml_dsa_valid = 0usize;
    let mut total_valid = 0usize;

    for signature in signatures {
        let Ok(signature_bytes) = B64.decode(signature.signature_b64.as_bytes()) else {
            return false;
        };
        let valid = match signature.algorithm.as_str() {
            "ed25519" => verify_ed25519(payload, &signature.key_id, &signature_bytes),
            "ml-dsa-65" => verify_ml_dsa(payload, &signature.key_id, &signature_bytes),
            _ => false,
        };
        if !valid {
            return false;
        }
        total_valid += 1;
        if signature.algorithm == "ed25519" {
            ed25519_valid += 1;
        }
        if signature.algorithm == "ml-dsa-65" {
            ml_dsa_valid += 1;
        }
    }

    total_valid >= THRESHOLD_REQUIRED
        && signatures.len() <= THRESHOLD_TOTAL
        && ed25519_valid >= ED25519_REQUIRED
        && ml_dsa_valid >= ML_DSA_REQUIRED
}

fn verify_ed25519(_payload: &[u8], key_id: &str, _signature: &[u8]) -> bool {
    let _anchor_is_known = ED25519_VERIFYING_KEY_IDS.contains(&key_id);
    false
}

fn verify_ml_dsa(_payload: &[u8], key_id: &str, _signature: &[u8]) -> bool {
    let _anchor_is_known = ML_DSA_VERIFYING_KEY_IDS.contains(&key_id);
    false
}

fn read_local_payload() -> ThreatResult<Option<ThreatFeedPayload>> {
    let path = feed_path();
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn write_local_payload(payload: &ThreatFeedPayload) -> ThreatResult<()> {
    let path = feed_path();
    ensure_parent(&path)?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, serde_json::to_vec_pretty(payload)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn feed_path() -> PathBuf {
    app_data_dir().join(FEED_FILE)
}

fn fail_fast(mut buffer: Zeroizing<Vec<u8>>) -> ! {
    buffer.zeroize();
    std::process::exit(1);
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(windows)]
fn download_feed(url: &str) -> ThreatResult<Vec<u8>> {
    use std::ffi::c_void;
    use std::ptr::null;
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
        WinHttpQueryDataAvailable, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE,
    };

    let parsed = parse_https_url(url)?;
    let agent = wide("SecureVaultUltimate/0.1");
    let host = wide(&parsed.host);
    let path = wide(&parsed.path);
    let get = wide("GET");

    unsafe {
        let session = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            null(),
            null(),
            0,
        );
        if session.is_null() {
            return Err(ThreatError::Network("WinHttpOpen 실패".to_string()));
        }
        let connection = WinHttpConnect(session, host.as_ptr(), parsed.port, 0);
        if connection.is_null() {
            WinHttpCloseHandle(session);
            return Err(ThreatError::Network("WinHttpConnect 실패".to_string()));
        }
        let request = WinHttpOpenRequest(
            connection,
            get.as_ptr(),
            path.as_ptr(),
            null(),
            null(),
            null(),
            WINHTTP_FLAG_SECURE,
        );
        if request.is_null() {
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return Err(ThreatError::Network("WinHttpOpenRequest 실패".to_string()));
        }
        let sent = WinHttpSendRequest(request, null(), 0, null::<c_void>(), 0, 0, 0);
        if sent == 0 || WinHttpReceiveResponse(request, std::ptr::null_mut()) == 0 {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return Err(ThreatError::Network("WinHTTP 요청 실패".to_string()));
        }

        let mut output = Vec::new();
        loop {
            let mut available = 0u32;
            if WinHttpQueryDataAvailable(request, &mut available) == 0 {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connection);
                WinHttpCloseHandle(session);
                return Err(ThreatError::Network("응답 크기 조회 실패".to_string()));
            }
            if available == 0 {
                break;
            }
            if output.len() + available as usize > MAX_FEED_BYTES {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connection);
                WinHttpCloseHandle(session);
                return Err(ThreatError::InvalidFeed(
                    "위협 피드가 허용 크기를 초과했습니다.".to_string(),
                ));
            }
            let mut chunk = vec![0u8; available as usize];
            let mut read = 0u32;
            if WinHttpReadData(request, chunk.as_mut_ptr().cast(), available, &mut read) == 0 {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connection);
                WinHttpCloseHandle(session);
                return Err(ThreatError::Network("응답 읽기 실패".to_string()));
            }
            chunk.truncate(read as usize);
            output.extend_from_slice(&chunk);
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        Ok(output)
    }
}

#[cfg(not(windows))]
fn download_feed(_url: &str) -> ThreatResult<Vec<u8>> {
    Err(ThreatError::Network(
        "현재 빌드에서는 Windows WinHTTP만 지원합니다.".to_string(),
    ))
}

#[cfg(windows)]
struct ParsedHttpsUrl {
    host: String,
    port: u16,
    path: String,
}

#[cfg(windows)]
fn parse_https_url(url: &str) -> ThreatResult<ParsedHttpsUrl> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| ThreatError::InvalidFeed("https URL만 허용됩니다.".to_string()))?;
    let (host_port, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if host_port.is_empty()
        || host_port
            .chars()
            .any(|ch| matches!(ch, '\r' | '\n' | '\t' | '@'))
    {
        return Err(ThreatError::InvalidFeed(
            "피드 호스트가 안전하지 않습니다.".to_string(),
        ));
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => {
            let port = port.parse::<u16>().map_err(|_| {
                ThreatError::InvalidFeed("포트 번호가 올바르지 않습니다.".to_string())
            })?;
            (host.to_string(), port)
        }
        _ => (host_port.to_string(), 443),
    };
    if host.is_empty() || path.chars().any(|ch| matches!(ch, '\r' | '\n' | '\t')) {
        return Err(ThreatError::InvalidFeed(
            "피드 URL 경로가 안전하지 않습니다.".to_string(),
        ));
    }
    Ok(ParsedHttpsUrl { host, port, path })
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
