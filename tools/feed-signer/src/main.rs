use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer as EdSigner, SigningKey as EdSigningKey};
use ml_dsa::signature::{SignatureEncoding, Signer as MlSigner};
use ml_dsa::{Generate, KeyExport, KeyInit, Keypair, MlDsa65, SigningKey as MlSigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const FEED_SCHEMA_VERSION: u32 = 1;
const SIGNING_PROFILE: &str = "secure-vault-threat-feed/v1";
const ED25519_ALGORITHM: &str = "Ed25519";
const ML_DSA_ALGORITHM: &str = "ML-DSA-65";
const DOMAIN_SEPARATOR: &[u8] = b"SecureVaultUltimate:ThreatFeed:v1\n";

#[derive(Debug, Parser)]
#[command(name = "feed-signer")]
#[command(about = "Offline key generation and signing for SecureVault threat feeds")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenerateKeys {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        force: bool,
    },
    SignFeed {
        #[arg(long)]
        payload: PathBuf,
        #[arg(
            long,
            required_unless_present = "keys_env_prefix",
            conflicts_with = "keys_env_prefix"
        )]
        keys: Option<PathBuf>,
        #[arg(long = "keys-env-prefix", required_unless_present = "keys")]
        keys_env_prefix: Option<String>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        feed_version: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretKeyFile {
    schema_version: u32,
    tool: String,
    algorithm: String,
    key_id: String,
    created_utc: String,
    encoding: String,
    secret_key_b64: String,
    public_key_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyFile {
    schema_version: u32,
    tool: String,
    algorithm: String,
    key_id: String,
    created_utc: String,
    encoding: String,
    public_key_b64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicTrustBundle {
    schema_version: u32,
    signing_profile: String,
    threshold_policy: ThresholdPolicy,
    generated_utc: String,
    keys: Vec<PublicKeyFile>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdPolicy {
    required_algorithms: Vec<String>,
    m_of_n: ThresholdRule,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdRule {
    m: u8,
    n: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedFeedEnvelope {
    schema_version: u32,
    signing_profile: String,
    tool: String,
    created_utc: String,
    feed_version: String,
    canonicalization: String,
    payload_sha256_b64: String,
    payload: Value,
    signatures: Vec<SignatureRecord>,
    threshold_policy: ThresholdPolicy,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureRecord {
    algorithm: String,
    key_id: String,
    signature_b64: String,
    message_sha256_b64: String,
}

fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("feed-signer-worker".to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(run_cli)
        .context("starting feed-signer worker thread")?
        .join()
        .map_err(|_| anyhow!("feed-signer worker thread panicked"))?
}

fn run_cli() -> Result<()> {
    match Cli::parse().command {
        Command::GenerateKeys { out, force } => generate_keys(&out, force),
        Command::SignFeed {
            payload,
            keys,
            keys_env_prefix,
            out,
            feed_version,
        } => {
            let key_source = match (keys, keys_env_prefix) {
                (Some(keys), None) => KeySource::Directory(keys),
                (None, Some(prefix)) => KeySource::Environment { prefix },
                _ => bail!("provide exactly one key source: --keys or --keys-env-prefix"),
            };
            sign_feed(&payload, &key_source, &out, feed_version)
        }
    }
}

#[derive(Debug)]
enum KeySource {
    Directory(PathBuf),
    Environment { prefix: String },
}

fn generate_keys(out: &Path, force: bool) -> Result<()> {
    if out.exists() && !force && out.read_dir()?.next().is_some() {
        bail!(
            "output directory is not empty. Use --force only for an intentionally isolated key directory: {}",
            out.display()
        );
    }

    fs::create_dir_all(out).with_context(|| format!("creating key directory {}", out.display()))?;

    let now = Utc::now().to_rfc3339();
    let mut rng = OsRng;

    let ed_sk = EdSigningKey::generate(&mut rng);
    let ed_secret = Zeroizing::new(ed_sk.to_bytes());
    let ed_public = ed_sk.verifying_key().to_bytes();
    let ed_key_id = key_id(ED25519_ALGORITHM, &ed_public);
    let ed_secret_file = SecretKeyFile {
        schema_version: FEED_SCHEMA_VERSION,
        tool: tool_name(),
        algorithm: ED25519_ALGORITHM.to_string(),
        key_id: ed_key_id.clone(),
        created_utc: now.clone(),
        encoding: "raw-base64".to_string(),
        secret_key_b64: B64.encode(ed_secret.as_slice()),
        public_key_b64: B64.encode(ed_public),
    };
    let ed_public_file = PublicKeyFile {
        schema_version: FEED_SCHEMA_VERSION,
        tool: tool_name(),
        algorithm: ED25519_ALGORITHM.to_string(),
        key_id: ed_key_id,
        created_utc: now.clone(),
        encoding: "raw-base64".to_string(),
        public_key_b64: B64.encode(ed_public),
    };

    let ml_sk = MlSigningKey::<MlDsa65>::generate();
    let ml_secret = Zeroizing::new(ml_sk.to_bytes());
    let ml_public = ml_sk.verifying_key().to_bytes();
    let ml_key_id = key_id(ML_DSA_ALGORITHM, ml_public.as_slice());
    let ml_secret_file = SecretKeyFile {
        schema_version: FEED_SCHEMA_VERSION,
        tool: tool_name(),
        algorithm: ML_DSA_ALGORITHM.to_string(),
        key_id: ml_key_id.clone(),
        created_utc: now.clone(),
        encoding: "raw-base64".to_string(),
        secret_key_b64: B64.encode(ml_secret.as_slice()),
        public_key_b64: B64.encode(ml_public.as_slice()),
    };
    let ml_public_file = PublicKeyFile {
        schema_version: FEED_SCHEMA_VERSION,
        tool: tool_name(),
        algorithm: ML_DSA_ALGORITHM.to_string(),
        key_id: ml_key_id,
        created_utc: now.clone(),
        encoding: "raw-base64".to_string(),
        public_key_b64: B64.encode(ml_public.as_slice()),
    };

    write_json_private(&out.join("ed25519.private.json"), &ed_secret_file, force)?;
    write_json_public(&out.join("ed25519.public.json"), &ed_public_file, force)?;
    write_json_private(&out.join("ml-dsa-65.private.json"), &ml_secret_file, force)?;
    write_json_public(&out.join("ml-dsa-65.public.json"), &ml_public_file, force)?;

    let trust_bundle = PublicTrustBundle {
        schema_version: FEED_SCHEMA_VERSION,
        signing_profile: SIGNING_PROFILE.to_string(),
        threshold_policy: threshold_policy(),
        generated_utc: now,
        keys: vec![ed_public_file, ml_public_file],
    };
    write_json_public(&out.join("trust-bundle.public.json"), &trust_bundle, force)?;

    println!(
        "generated isolated feed signing material in {}",
        out.display()
    );
    println!("keep *.private.json offline and never ship them with the app");
    Ok(())
}

fn sign_feed(
    payload_path: &Path,
    key_source: &KeySource,
    out: &Path,
    feed_version: Option<String>,
) -> Result<()> {
    let payload_bytes = fs::read(payload_path)
        .with_context(|| format!("reading payload {}", payload_path.display()))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .with_context(|| format!("parsing payload JSON {}", payload_path.display()))?;
    validate_payload_shape(&payload)?;

    let canonical_payload = canonical_json(&payload)?;
    let payload_digest = Sha256::digest(&canonical_payload);
    let signing_message = signing_message(&canonical_payload, &payload_digest);
    let message_digest = Sha256::digest(&signing_message);

    let ed_secret = read_secret_key(key_source, "ed25519.private.json", ED25519_ALGORITHM)?;
    let ed_secret_bytes = Zeroizing::new(decode_fixed_key::<32>(
        &ed_secret.secret_key_b64,
        "Ed25519 secret key",
    )?);
    let ed_sk = EdSigningKey::from_bytes(&ed_secret_bytes);
    let ed_signature = EdSigner::sign(&ed_sk, &signing_message);

    let ml_secret = read_secret_key(key_source, "ml-dsa-65.private.json", ML_DSA_ALGORITHM)?;
    let ml_secret_bytes = Zeroizing::new(
        B64.decode(&ml_secret.secret_key_b64)
            .context("decoding ML-DSA-65 secret key")?,
    );
    let ml_sk = MlSigningKey::<MlDsa65>::new_from_slice(&ml_secret_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 secret key length"))?;
    let ml_signature = MlSigner::sign(&ml_sk, &signing_message);

    let envelope = SignedFeedEnvelope {
        schema_version: FEED_SCHEMA_VERSION,
        signing_profile: SIGNING_PROFILE.to_string(),
        tool: tool_name(),
        created_utc: Utc::now().to_rfc3339(),
        feed_version: feed_version.unwrap_or_else(|| payload_version(&payload)),
        canonicalization: "serde_json-minified-sorted-map".to_string(),
        payload_sha256_b64: B64.encode(payload_digest),
        payload,
        signatures: vec![
            SignatureRecord {
                algorithm: ED25519_ALGORITHM.to_string(),
                key_id: ed_secret.key_id,
                signature_b64: B64.encode(ed_signature.to_bytes()),
                message_sha256_b64: B64.encode(message_digest),
            },
            SignatureRecord {
                algorithm: ML_DSA_ALGORITHM.to_string(),
                key_id: ml_secret.key_id,
                signature_b64: B64.encode(ml_signature.to_bytes()),
                message_sha256_b64: B64.encode(message_digest),
            },
        ],
        threshold_policy: threshold_policy(),
    };

    write_json_public(out, &envelope, true)?;
    println!("signed feed written to {}", out.display());
    Ok(())
}

fn validate_payload_shape(payload: &Value) -> Result<()> {
    let object = payload
        .as_object()
        .ok_or_else(|| anyhow!("payload root must be a JSON object"))?;
    for required in [
        "schemaVersion",
        "feedVersion",
        "ransomwareExtensions",
        "yaraRules",
        "trustedProcesses",
    ] {
        if !object.contains_key(required) {
            bail!("payload is missing required field: {required}");
        }
    }
    Ok(())
}

fn read_secret_key(
    key_source: &KeySource,
    file_name: &str,
    expected_algorithm: &str,
) -> Result<SecretKeyFile> {
    let file = match key_source {
        KeySource::Directory(keys_dir) => {
            let path = keys_dir.join(file_name);
            let bytes = fs::read(&path)
                .with_context(|| format!("reading private key {}", path.display()))?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing private key {}", path.display()))?
        }
        KeySource::Environment { prefix } => read_secret_key_from_env(prefix, expected_algorithm)?,
    };
    if file.algorithm != expected_algorithm {
        bail!(
            "private key source has algorithm {}, expected {}",
            file.algorithm,
            expected_algorithm
        );
    }
    Ok(file)
}

fn read_secret_key_from_env(prefix: &str, expected_algorithm: &str) -> Result<SecretKeyFile> {
    let suffix = match expected_algorithm {
        ED25519_ALGORITHM => "ED25519_PRIVATE_JSON",
        ML_DSA_ALGORITHM => "ML_DSA_65_PRIVATE_JSON",
        _ => bail!("unsupported key algorithm: {expected_algorithm}"),
    };
    let raw_name = format!("{prefix}{suffix}");
    let b64_name = format!("{raw_name}_B64");

    let key_json = match env::var(&raw_name) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => {
            let encoded = env::var(&b64_name)
                .with_context(|| format!("missing environment secret {raw_name} or {b64_name}"))?;
            let decoded = B64
                .decode(encoded.trim())
                .with_context(|| format!("decoding environment secret {b64_name}"))?;
            Zeroizing::new(
                String::from_utf8(decoded)
                    .with_context(|| format!("environment secret {b64_name} is not UTF-8 JSON"))?,
            )
        }
    };

    serde_json::from_str(&key_json)
        .with_context(|| format!("parsing environment key material for {expected_algorithm}"))
}

fn decode_fixed_key<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N]> {
    let bytes = B64
        .decode(encoded)
        .with_context(|| format!("decoding {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be exactly {N} bytes"))
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("serializing canonical payload")
}

fn signing_message(canonical_payload: &[u8], payload_digest: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DOMAIN_SEPARATOR.len() + payload_digest.len() + canonical_payload.len());
    message.extend_from_slice(DOMAIN_SEPARATOR);
    message.extend_from_slice(payload_digest);
    message.extend_from_slice(canonical_payload);
    message
}

fn payload_version(payload: &Value) -> String {
    payload
        .get("feedVersion")
        .and_then(Value::as_str)
        .unwrap_or("unversioned")
        .to_string()
}

fn threshold_policy() -> ThresholdPolicy {
    ThresholdPolicy {
        required_algorithms: vec![ED25519_ALGORITHM.to_string(), ML_DSA_ALGORITHM.to_string()],
        m_of_n: ThresholdRule { m: 2, n: 2 },
    }
}

fn write_json_private<T: Serialize>(path: &Path, value: &T, force: bool) -> Result<()> {
    write_json(path, value, force)?;
    lock_down_private_file(path)?;
    Ok(())
}

fn write_json_public<T: Serialize>(path: &Path, value: &T, force: bool) -> Result<()> {
    write_json(path, value, force)
}

fn write_json<T: Serialize>(path: &Path, value: &T, force: bool) -> Result<()> {
    if path.exists() {
        if !force {
            bail!(
                "refusing to overwrite existing file without --force: {}",
                path.display()
            );
        }
        unlock_if_needed(path)?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn lock_down_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }
}

fn unlock_if_needed(path: &Path) -> Result<()> {
    unlock_platform(path)
}

#[cfg(unix)]
fn unlock_platform(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn unlock_platform(path: &Path) -> Result<()> {
    clear_windows_readonly(path)
}

#[cfg(not(any(unix, windows)))]
fn unlock_platform(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn clear_windows_readonly(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_NORMAL};

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let ok = unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("clearing read-only attribute on {}", path.display()));
    }
    Ok(())
}

fn key_id(algorithm: &str, public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(algorithm.as_bytes());
    hasher.update(b"\0");
    hasher.update(public_key);
    let digest = hasher.finalize();
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{}-{hex}", algorithm.to_ascii_lowercase().replace('-', ""))
}

fn tool_name() -> String {
    format!("feed-signer/{TOOL_VERSION}")
}
