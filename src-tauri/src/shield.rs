use aes_gcm::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::RngCore;
use serde::Serialize;
use sha3::{Digest, Sha3_512};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tauri::{Emitter, Manager};
use thiserror::Error;
use zeroize::Zeroizing;

#[allow(dead_code)]
mod build_config {
    include!(concat!(env!("OUT_DIR"), "/secure_vault_build_config.rs"));
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_AAD: &[u8] = b"SecureVaultUltimate:EcosystemShield:heartbeat:v1";
const TOKEN_DOMAIN: &[u8] = b"SecureVaultUltimate:EcosystemShield:challenge-response:v1";
const CREDENTIAL_DOMAIN: &[u8] = b"SecureVaultUltimate:EcosystemShield:credential-integrity:v1";
const MAX_AGENT_ACK_BYTES: usize = 4096;

static HEARTBEAT_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("Ecosystem Shield seed is not configured for this build.")]
    MissingSeed,
    #[error("Ecosystem Shield agent pipe is unavailable.")]
    AgentUnavailable,
    #[error("Ecosystem Shield transport IO failed.")]
    TransportIo,
    #[error("Ecosystem Shield heartbeat encryption failed.")]
    Crypto,
    #[error("Ecosystem Shield agent rejected the heartbeat.")]
    Rejected,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldStatus {
    pub configured: bool,
    pub required: bool,
    pub transport: String,
    pub mode: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldLog {
    pub level: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub response_b64: String,
    pub credential_sha3_512_b64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatPlaintext<'a> {
    schema: &'static str,
    pid: u32,
    counter: u64,
    challenge_b64: &'a str,
    response_b64: &'a str,
    credential_sha3_512_b64: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatEnvelope {
    schema: &'static str,
    algorithm: &'static str,
    nonce_b64: String,
    ciphertext_b64: String,
}

trait ShieldTransport {
    fn exchange(&self, frame: &[u8]) -> Result<Vec<u8>, ShieldError>;
}

struct NamedPipeTransport;

impl ShieldTransport for NamedPipeTransport {
    fn exchange(&self, frame: &[u8]) -> Result<Vec<u8>, ShieldError> {
        #[cfg(windows)]
        {
            let mut pipe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(build_config::SHIELD_PIPE)
                .map_err(|_| ShieldError::AgentUnavailable)?;
            pipe.write_all(frame)
                .map_err(|_| ShieldError::TransportIo)?;
            pipe.write_all(b"\n")
                .map_err(|_| ShieldError::TransportIo)?;
            pipe.flush().map_err(|_| ShieldError::TransportIo)?;
            let mut ack = vec![0u8; MAX_AGENT_ACK_BYTES];
            let read = pipe.read(&mut ack).map_err(|_| ShieldError::TransportIo)?;
            ack.truncate(read);
            Ok(ack)
        }

        #[cfg(not(windows))]
        {
            let _ = frame;
            Err(ShieldError::AgentUnavailable)
        }
    }
}

pub fn status() -> ShieldStatus {
    let configured = seed_configured();
    let required = build_config::SHIELD_REQUIRED;
    let mode = if cfg!(debug_assertions) {
        "debug-simulation"
    } else if configured && required {
        "strict-fail-closed"
    } else if configured {
        "opportunistic-heartbeat"
    } else {
        "not-configured"
    };
    let detail = if configured {
        "Ecosystem Shield challenge-response material is present in an obfuscated build slot."
    } else if required {
        "Ecosystem Shield is required, but this build has no shield seed."
    } else {
        "Ecosystem Shield is not required for this build."
    };
    ShieldStatus {
        configured,
        required,
        transport: "windows-named-pipe".to_string(),
        mode: mode.to_string(),
        detail: detail.to_string(),
    }
}

pub fn challenge_response(challenge: &[u8]) -> Result<ChallengeResponse, ShieldError> {
    let seed = recover_seed()?;
    let response = derive_response(&seed, challenge, 0);
    let credential = credential_fingerprint(&seed);
    Ok(ChallengeResponse {
        response_b64: B64.encode(response.as_bytes()),
        credential_sha3_512_b64: B64.encode(credential),
    })
}

pub fn spawn(app: &tauri::App) {
    if HEARTBEAT_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let app_handle = app.handle().clone();
    thread::spawn(move || heartbeat_loop(app_handle));
}

fn heartbeat_loop(app: tauri::AppHandle) {
    let transport = NamedPipeTransport;
    let mut counter = 0u64;
    loop {
        thread::sleep(HEARTBEAT_INTERVAL);
        counter = counter.wrapping_add(1);
        match send_heartbeat(&transport, counter) {
            Ok(()) => emit_log(&app, "info", "Ecosystem Shield heartbeat accepted."),
            Err(error) => handle_heartbeat_error(&app, error),
        }
    }
}

fn send_heartbeat(transport: &dyn ShieldTransport, counter: u64) -> Result<(), ShieldError> {
    let seed = recover_seed()?;
    let mut challenge = Zeroizing::new(vec![0u8; 32]);
    AeadOsRng.fill_bytes(&mut challenge);
    let response = derive_response(&seed, &challenge, counter);
    let credential = credential_fingerprint(&seed);
    let key = derive_aes_key(&seed, &challenge, response.as_bytes());
    let plaintext = HeartbeatPlaintext {
        schema: "secure-vault-ecosystem-shield-heartbeat/v1",
        pid: std::process::id(),
        counter,
        challenge_b64: &B64.encode(&challenge),
        response_b64: &B64.encode(response.as_bytes()),
        credential_sha3_512_b64: &B64.encode(credential),
    };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&plaintext).map_err(|_| ShieldError::Crypto)?);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| ShieldError::Crypto)?;
    let mut nonce = [0u8; 12];
    AeadOsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: HEARTBEAT_AAD,
            },
        )
        .map_err(|_| ShieldError::Crypto)?;
    let frame = serde_json::to_vec(&HeartbeatEnvelope {
        schema: "secure-vault-ecosystem-shield-envelope/v1",
        algorithm: "AES-256-GCM",
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
    })
    .map_err(|_| ShieldError::Crypto)?;
    let ack = transport.exchange(&frame)?;
    validate_ack(&ack)
}

fn validate_ack(ack: &[u8]) -> Result<(), ShieldError> {
    let text = std::str::from_utf8(ack).map_err(|_| ShieldError::Rejected)?;
    let normalized = text.trim().to_ascii_lowercase();
    if normalized == "ok"
        || normalized.contains("\"ok\":true")
        || normalized.contains("\"status\":\"ok\"")
    {
        Ok(())
    } else {
        Err(ShieldError::Rejected)
    }
}

fn handle_heartbeat_error(app: &tauri::AppHandle, error: ShieldError) {
    let required = build_config::SHIELD_REQUIRED;
    if cfg!(debug_assertions) || !required {
        emit_log(
            app,
            "warn",
            format!("Ecosystem Shield safe simulation: {error}"),
        );
        return;
    }
    emit_log(app, "critical", "Ecosystem Shield fail-closed trigger.");
    emergency_zeroize_and_exit(app);
}

fn emergency_zeroize_and_exit(app: &tauri::AppHandle) -> ! {
    if let Some(state) = app.try_state::<crate::AppState>() {
        if let Ok(mut session) = state.session.lock() {
            if let Some(active) = session.take() {
                let _ = active.lock();
            }
        }
    }
    std::process::exit(190);
}

fn emit_log(app: &tauri::AppHandle, level: &'static str, message: impl Into<String>) {
    let _ = app.emit(
        "shield-log",
        ShieldLog {
            level,
            message: message.into(),
        },
    );
}

fn seed_configured() -> bool {
    build_config::SHIELD_SEED_MASKED.len() == build_config::SHIELD_SEED_MASK.len()
        && !build_config::SHIELD_SEED_MASKED.is_empty()
}

fn recover_seed() -> Result<Zeroizing<Vec<u8>>, ShieldError> {
    if !seed_configured() {
        return Err(ShieldError::MissingSeed);
    }
    let mut seed = Zeroizing::new(Vec::with_capacity(build_config::SHIELD_SEED_MASKED.len()));
    for (&masked, &mask) in build_config::SHIELD_SEED_MASKED
        .iter()
        .zip(build_config::SHIELD_SEED_MASK.iter())
    {
        seed.push(masked ^ mask);
    }
    Ok(seed)
}

fn derive_response(seed: &[u8], challenge: &[u8], counter: u64) -> blake3::Hash {
    let keyed = blake3::hash(seed);
    let mut hasher = blake3::Hasher::new_keyed(keyed.as_bytes());
    hasher.update(TOKEN_DOMAIN);
    hasher.update(challenge);
    hasher.update(&counter.to_le_bytes());
    hasher.finalize()
}

fn credential_fingerprint(seed: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hasher = Sha3_512::new();
    hasher.update(CREDENTIAL_DOMAIN);
    hasher.update(seed);
    Zeroizing::new(hasher.finalize().to_vec())
}

fn derive_aes_key(seed: &[u8], challenge: &[u8], response: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_512::new();
    hasher.update(HEARTBEAT_AAD);
    hasher.update(seed);
    hasher.update(challenge);
    hasher.update(response);
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_seed_is_explicit() {
        if !seed_configured() {
            assert!(matches!(recover_seed(), Err(ShieldError::MissingSeed)));
        }
    }
}
