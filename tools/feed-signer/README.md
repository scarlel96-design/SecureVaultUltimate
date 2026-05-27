# feed-signer

Detached offline signing utility for future SecureVault threat-intelligence
feeds.

This crate is intentionally outside the Tauri application. It does not modify,
import, or execute the main app threat-feed path.

## Build

```powershell
cargo build --manifest-path .\tools\feed-signer\Cargo.toml --release
```

## Generate Offline Keys

Use a private, non-distribution directory. Do not place private keys in the app
bundle, Git repository, public cloud folder, or web feed host.

```powershell
cargo run --manifest-path .\tools\feed-signer\Cargo.toml -- generate-keys --out C:\SecureVaultFeedKeys
```

Generated private key files are marked read-only after writing. Use `--force`
only when intentionally rotating keys in an isolated directory.

## Sign A Feed

```powershell
cargo run --manifest-path .\tools\feed-signer\Cargo.toml -- sign-feed `
  --payload .\tools\feed-signer\spec\threat_payload.sample.json `
  --keys C:\SecureVaultFeedKeys `
  --out .\tools\feed-signer\secure-vault-feed.json
```

The output is a signed envelope containing the payload, an Ed25519 signature,
an ML-DSA-65 signature, and a strict `2-of-2` threshold policy.

## Sign From Environment Secrets

CI systems can inject private keys through environment variables instead of
writing key files. The signer accepts either raw JSON or Base64-encoded JSON:

- `SECURE_VAULT_FEED_ED25519_PRIVATE_JSON`
- `SECURE_VAULT_FEED_ED25519_PRIVATE_JSON_B64`
- `SECURE_VAULT_FEED_ML_DSA_65_PRIVATE_JSON`
- `SECURE_VAULT_FEED_ML_DSA_65_PRIVATE_JSON_B64`

```powershell
cargo run --manifest-path .\tools\feed-signer\Cargo.toml -- sign-feed `
  --payload .\tools\feed-signer\spec\threat_payload.sample.json `
  --keys-env-prefix SECURE_VAULT_FEED_ `
  --out .\tools\feed-signer\secure-vault-feed.json
```
