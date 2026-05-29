fn main() {
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_EXE_SHA256");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_SHIELD_SEED");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_SHIELD_REQUIRED");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_SHIELD_PIPE");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_UPDATER_PUBLIC_KEY");
    let exe_hash = std::env::var("SECURE_VAULT_EXE_SHA256")
        .ok()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "0".repeat(64));
    println!("cargo:rustc-env=SECURE_VAULT_EXE_SHA256_VALUE={exe_hash}");
    write_shield_build_config();
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_FEED_ED25519_PUBLIC_JSON");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_FEED_ED25519_PUBLIC_JSON_B64");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_FEED_ML_DSA_65_PUBLIC_JSON");
    println!("cargo:rerun-if-env-changed=SECURE_VAULT_FEED_ML_DSA_65_PUBLIC_JSON_B64");
    tauri_build::build()
}

fn write_shield_build_config() {
    let seed = std::env::var("SECURE_VAULT_SHIELD_SEED").unwrap_or_default();
    let required = matches!(
        std::env::var("SECURE_VAULT_SHIELD_REQUIRED")
            .unwrap_or_default()
            .as_str(),
        "1" | "true" | "TRUE" | "yes" | "YES"
    );
    let pipe = std::env::var("SECURE_VAULT_SHIELD_PIPE")
        .unwrap_or_else(|_| r"\\.\pipe\SecureVaultEcosystemShield".to_string());
    let updater_key = std::env::var("SECURE_VAULT_UPDATER_PUBLIC_KEY").unwrap_or_default();

    let (masked, mask) = mask_seed(seed.as_bytes());
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR missing"));
    let source = format!(
        "pub const SHIELD_SEED_MASKED: &[u8] = &{:?};\n\
         pub const SHIELD_SEED_MASK: &[u8] = &{:?};\n\
         pub const SHIELD_REQUIRED: bool = {};\n\
         pub const SHIELD_PIPE: &str = {:?};\n\
         pub const UPDATER_PUBLIC_KEY: &str = {:?};\n",
        masked, mask, required, pipe, updater_key
    );
    std::fs::write(out_dir.join("secure_vault_build_config.rs"), source)
        .expect("failed to write generated SecureVault build config");
}

fn mask_seed(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ seed.len() as u64;
    for &byte in seed {
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(13) ^ u64::from(byte);
    }
    let mut masked = Vec::with_capacity(seed.len());
    let mut mask = Vec::with_capacity(seed.len());
    for &byte in seed {
        state = splitmix64(state);
        let pad = (state & 0xff) as u8;
        masked.push(byte ^ pad);
        mask.push(pad);
    }
    (masked, mask)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
