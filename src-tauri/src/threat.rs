use crate::core::config::{app_data_dir, ensure_parent, AppSettings};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{
    Signature as Ed25519Signature, Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::signature::Verifier as MlDsaVerifier;
use ml_dsa::{KeyInit as MlDsaKeyInit, MlDsa65, Signature as MlDsaSignature};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FEED_FILE: &str = "threat_feed.json";
const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
const FEED_SCHEMA_VERSION: u32 = 1;
const SIGNING_PROFILE: &str = "secure-vault-threat-feed/v1";
const DOMAIN_SEPARATOR: &[u8] = b"SecureVaultUltimate:ThreatFeed:v1\n";
const ED25519_ALGORITHM: &str = "Ed25519";
const ML_DSA_ALGORITHM: &str = "ML-DSA-65";

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
    #[error("위협 피드 서명 검증 실패: {0}")]
    Signature(String),
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
struct SignedFeedEnvelope {
    schema_version: u32,
    signing_profile: String,
    feed_version: String,
    canonicalization: String,
    payload_sha256_b64: String,
    payload: ThreatFeedPayload,
    signatures: Vec<SignatureRecord>,
    threshold_policy: ThresholdPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureRecord {
    algorithm: String,
    key_id: String,
    signature_b64: String,
    message_sha256_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdPolicy {
    required_algorithms: Vec<String>,
    m_of_n: ThresholdRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdRule {
    m: u8,
    n: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatFeedPayload {
    schema_version: u32,
    feed_version: String,
    published_utc: String,
    ransomware_extensions: Vec<RansomwareExtension>,
    yara_rules: Vec<YaraRule>,
    trusted_processes: Vec<TrustedProcess>,
    #[serde(default)]
    revoked_feed_versions: Vec<String>,
    minimum_client_schema_version: u32,
    #[serde(default)]
    source_summary: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RansomwareExtension {
    extension: String,
    family: String,
    severity: String,
    first_seen_utc: Option<String>,
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraRule {
    id: String,
    name: String,
    severity: String,
    rule: String,
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedProcess {
    name: String,
    publisher: Option<String>,
    sha256: Option<String>,
    allowed_operations: Vec<String>,
    notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyFile {
    algorithm: String,
    key_id: String,
    public_key_b64: String,
}

struct PublicKeyAnchor {
    key_id: String,
    public_key: Vec<u8>,
}

pub fn status(settings: &AppSettings) -> ThreatFeedStatus {
    match read_local_payload() {
        Ok(Some(payload)) => ThreatFeedStatus {
            configured: !settings.threat_feed_url.is_empty(),
            last_checked_utc: Some(payload.published_utc.clone()),
            version: Some(payload.feed_version.clone()),
            ransomware_extension_count: payload.ransomware_extensions.len(),
            yara_rule_count: payload.yara_rules.len(),
            trusted_process_count: payload.trusted_processes.len(),
            detail: "로컬 위협 인텔리전스 데이터베이스가 준비되어 있습니다.".to_string(),
        },
        Ok(None) => ThreatFeedStatus {
            configured: !settings.threat_feed_url.is_empty(),
            last_checked_utc: None,
            version: None,
            ransomware_extension_count: 0,
            yara_rule_count: 0,
            trusted_process_count: 0,
            detail: if settings.threat_feed_url.is_empty() {
                "원격 보안 피드가 설정되지 않아 오프라인 보호 모드로 동작합니다.".to_string()
            } else {
                "아직 내려받은 보안 피드가 없습니다.".to_string()
            },
        },
        Err(error) => ThreatFeedStatus {
            configured: !settings.threat_feed_url.is_empty(),
            last_checked_utc: None,
            version: None,
            ransomware_extension_count: 0,
            yara_rule_count: 0,
            trusted_process_count: 0,
            detail: format!("로컬 보안 피드를 읽지 못했습니다: {error}"),
        },
    }
}

pub fn sync(settings: &AppSettings) -> ThreatResult<ThreatFeedStatus> {
    if settings.threat_feed_url.is_empty() {
        return Err(ThreatError::NotConfigured);
    }
    sync_url(&settings.threat_feed_url, true)
}

pub fn sync_url(url: &str, configured: bool) -> ThreatResult<ThreatFeedStatus> {
    validate_https_url(url)?;
    let mut downloaded = Zeroizing::new(download_feed(url)?);
    let payload = verify_and_decode(&downloaded)?;
    downloaded.zeroize();
    write_local_payload(&payload)?;
    Ok(ThreatFeedStatus {
        configured,
        last_checked_utc: Some(Utc::now().to_rfc3339()),
        version: Some(payload.feed_version.clone()),
        ransomware_extension_count: payload.ransomware_extensions.len(),
        yara_rule_count: payload.yara_rules.len(),
        trusted_process_count: payload.trusted_processes.len(),
        detail: "하이브리드 서명 검증을 통과한 보안 피드를 반영했습니다.".to_string(),
    })
}

fn verify_and_decode(bytes: &[u8]) -> ThreatResult<ThreatFeedPayload> {
    if bytes.len() > MAX_FEED_BYTES {
        return Err(ThreatError::InvalidFeed(
            "보안 피드가 허용 크기를 초과했습니다.".to_string(),
        ));
    }

    let envelope: SignedFeedEnvelope = serde_json::from_slice(bytes)?;
    validate_envelope_shape(&envelope)?;

    let canonical_payload = Zeroizing::new(serde_json::to_vec(&envelope.payload)?);
    let payload_digest = Sha256::digest(&canonical_payload);
    let expected_payload_digest = B64
        .decode(envelope.payload_sha256_b64.as_bytes())
        .map_err(|_| ThreatError::InvalidFeed("payloadSha256B64 디코딩 실패".to_string()))?;
    if payload_digest.as_slice() != expected_payload_digest.as_slice() {
        return Err(ThreatError::InvalidFeed(
            "보안 피드 체크섬이 일치하지 않습니다.".to_string(),
        ));
    }

    let signing_message = signing_message(&canonical_payload, &payload_digest);
    let message_digest = Sha256::digest(&signing_message);
    verify_threshold_signatures(&envelope.signatures, &signing_message, &message_digest)?;
    Ok(envelope.payload)
}

fn validate_envelope_shape(envelope: &SignedFeedEnvelope) -> ThreatResult<()> {
    if envelope.schema_version != FEED_SCHEMA_VERSION
        || envelope.payload.schema_version != FEED_SCHEMA_VERSION
        || envelope.signing_profile != SIGNING_PROFILE
    {
        return Err(ThreatError::InvalidFeed(
            "지원하지 않는 보안 피드 버전입니다.".to_string(),
        ));
    }
    if envelope.canonicalization != "serde_json-minified-sorted-map" {
        return Err(ThreatError::InvalidFeed(
            "지원하지 않는 정규화 방식입니다.".to_string(),
        ));
    }
    if envelope.feed_version != envelope.payload.feed_version {
        return Err(ThreatError::InvalidFeed(
            "봉투 버전과 페이로드 버전이 일치하지 않습니다.".to_string(),
        ));
    }
    if envelope.threshold_policy.m_of_n.m != 2
        || envelope.threshold_policy.m_of_n.n != 2
        || envelope.threshold_policy.required_algorithms
            != [ED25519_ALGORITHM.to_string(), ML_DSA_ALGORITHM.to_string()]
    {
        return Err(ThreatError::InvalidFeed(
            "서명 임계치 정책이 앱 정책과 다릅니다.".to_string(),
        ));
    }
    if envelope.payload.minimum_client_schema_version > FEED_SCHEMA_VERSION {
        return Err(ThreatError::InvalidFeed(
            "현재 앱보다 최신 보안 피드 스키마입니다.".to_string(),
        ));
    }
    Ok(())
}

fn verify_threshold_signatures(
    signatures: &[SignatureRecord],
    message: &[u8],
    message_digest: &[u8],
) -> ThreatResult<()> {
    let mut ed25519_ok = false;
    let mut ml_dsa_ok = false;

    for signature in signatures {
        let declared_digest = B64
            .decode(signature.message_sha256_b64.as_bytes())
            .map_err(|_| ThreatError::Signature("messageSha256B64 디코딩 실패".to_string()))?;
        if declared_digest.as_slice() != message_digest {
            return Err(ThreatError::Signature(
                "서명 메시지 체크섬이 일치하지 않습니다.".to_string(),
            ));
        }

        match signature.algorithm.as_str() {
            ED25519_ALGORITHM => {
                verify_ed25519(signature, message)?;
                ed25519_ok = true;
            }
            ML_DSA_ALGORITHM => {
                verify_ml_dsa(signature, message)?;
                ml_dsa_ok = true;
            }
            _ => {
                return Err(ThreatError::Signature(
                    "허용되지 않은 서명 알고리즘입니다.".to_string(),
                ));
            }
        }
    }

    if ed25519_ok && ml_dsa_ok && signatures.len() == 2 {
        Ok(())
    } else {
        Err(ThreatError::Signature(
            "필수 하이브리드 서명이 모두 존재하지 않습니다.".to_string(),
        ))
    }
}

fn verify_ed25519(signature: &SignatureRecord, message: &[u8]) -> ThreatResult<()> {
    let anchors = ed25519_anchors()?;
    let anchor = anchors
        .iter()
        .find(|anchor| anchor.key_id == signature.key_id)
        .ok_or_else(|| ThreatError::Signature("알 수 없는 Ed25519 공개키입니다.".to_string()))?;
    let public_key: [u8; 32] = anchor.public_key.as_slice().try_into().map_err(|_| {
        ThreatError::Signature("Ed25519 공개키 길이가 올바르지 않습니다.".to_string())
    })?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ThreatError::Signature("Ed25519 공개키를 해석하지 못했습니다.".to_string()))?;
    let signature_bytes = B64
        .decode(signature.signature_b64.as_bytes())
        .map_err(|_| ThreatError::Signature("Ed25519 서명 디코딩 실패".to_string()))?;
    let signature = Ed25519Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| ThreatError::Signature("Ed25519 서명 형식 오류".to_string()))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| ThreatError::Signature("Ed25519 검증 실패".to_string()))
}

fn verify_ml_dsa(signature: &SignatureRecord, message: &[u8]) -> ThreatResult<()> {
    let anchors = ml_dsa_anchors()?;
    let anchor = anchors
        .iter()
        .find(|anchor| anchor.key_id == signature.key_id)
        .ok_or_else(|| ThreatError::Signature("알 수 없는 ML-DSA 공개키입니다.".to_string()))?;
    let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(&anchor.public_key)
        .map_err(|_| ThreatError::Signature("ML-DSA 공개키를 해석하지 못했습니다.".to_string()))?;
    let signature_bytes = B64
        .decode(signature.signature_b64.as_bytes())
        .map_err(|_| ThreatError::Signature("ML-DSA 서명 디코딩 실패".to_string()))?;
    let signature = MlDsaSignature::<MlDsa65>::try_from(signature_bytes.as_slice())
        .map_err(|_| ThreatError::Signature("ML-DSA 서명 형식 오류".to_string()))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| ThreatError::Signature("ML-DSA 검증 실패".to_string()))
}

fn ed25519_anchors() -> ThreatResult<Vec<PublicKeyAnchor>> {
    read_public_key_anchors(
        ED25519_ALGORITHM,
        option_env!("SECURE_VAULT_FEED_ED25519_PUBLIC_JSON"),
        option_env!("SECURE_VAULT_FEED_ED25519_PUBLIC_JSON_B64"),
    )
}

fn ml_dsa_anchors() -> ThreatResult<Vec<PublicKeyAnchor>> {
    read_public_key_anchors(
        ML_DSA_ALGORITHM,
        option_env!("SECURE_VAULT_FEED_ML_DSA_65_PUBLIC_JSON"),
        option_env!("SECURE_VAULT_FEED_ML_DSA_65_PUBLIC_JSON_B64"),
    )
}

fn read_public_key_anchors(
    algorithm: &str,
    raw_json: Option<&'static str>,
    b64_json: Option<&'static str>,
) -> ThreatResult<Vec<PublicKeyAnchor>> {
    let Some(json) = raw_json.or(b64_json) else {
        return Err(ThreatError::Signature(format!(
            "{algorithm} 공개키 앵커가 빌드에 포함되지 않았습니다."
        )));
    };
    let decoded;
    let json = if raw_json.is_none() {
        decoded = B64
            .decode(json.trim().as_bytes())
            .map_err(|_| ThreatError::Signature(format!("{algorithm} 공개키 앵커 디코딩 실패")))?;
        std::str::from_utf8(&decoded)
            .map_err(|_| ThreatError::Signature(format!("{algorithm} 공개키 앵커 UTF-8 오류")))?
    } else {
        json
    };
    let file: PublicKeyFile = serde_json::from_str(json)?;
    if file.algorithm != algorithm {
        return Err(ThreatError::Signature(format!(
            "{algorithm} 공개키 앵커 알고리즘이 일치하지 않습니다."
        )));
    }
    let public_key = B64
        .decode(file.public_key_b64.as_bytes())
        .map_err(|_| ThreatError::Signature(format!("{algorithm} 공개키 디코딩 실패")))?;
    Ok(vec![PublicKeyAnchor {
        key_id: file.key_id,
        public_key,
    }])
}

fn signing_message(canonical_payload: &[u8], payload_digest: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DOMAIN_SEPARATOR.len() + payload_digest.len() + canonical_payload.len());
    message.extend_from_slice(DOMAIN_SEPARATOR);
    message.extend_from_slice(payload_digest);
    message.extend_from_slice(canonical_payload);
    message
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

fn validate_https_url(url: &str) -> ThreatResult<()> {
    if !url.starts_with("https://") {
        return Err(ThreatError::InvalidFeed(
            "보안 피드는 https 주소만 허용됩니다.".to_string(),
        ));
    }
    if url.len() > 2048 || url.chars().any(|ch| matches!(ch, '\r' | '\n' | '\t' | '@')) {
        return Err(ThreatError::InvalidFeed(
            "보안 피드 URL 형식이 안전하지 않습니다.".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn download_feed(url: &str) -> ThreatResult<Vec<u8>> {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
        WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
        WinHttpSendRequest, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_FLAG_SECURE,
        WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
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
        if sent == 0 || WinHttpReceiveResponse(request, null_mut()) == 0 {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return Err(ThreatError::Network("보안 피드 요청 실패".to_string()));
        }

        let mut status_code = 0u32;
        let mut status_size = std::mem::size_of::<u32>() as u32;
        let mut index = 0u32;
        if WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status_code as *mut u32).cast(),
            &mut status_size,
            &mut index,
        ) == 0
        {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return Err(ThreatError::Network(
                "HTTP 상태 코드를 확인하지 못했습니다.".to_string(),
            ));
        }
        if !(200..300).contains(&status_code) {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return Err(ThreatError::Network(format!(
                "HTTP {status_code} 응답으로 보안 피드를 받을 수 없습니다."
            )));
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
                    "보안 피드가 허용 크기를 초과했습니다.".to_string(),
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
        "현재 빌드는 Windows WinHTTP 보안 피드 다운로드만 지원합니다.".to_string(),
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
    validate_https_url(url)?;
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
            "보안 피드 호스트가 안전하지 않습니다.".to_string(),
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
            "보안 피드 경로가 안전하지 않습니다.".to_string(),
        ));
    }
    Ok(ParsedHttpsUrl { host, port, path })
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
