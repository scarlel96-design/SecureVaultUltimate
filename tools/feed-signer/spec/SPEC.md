# SecureVault Threat Feed Signing Spec

This directory is intentionally isolated from the Tauri application. Nothing in
this folder is imported by the app runtime until a future integration step is
explicitly requested.

## Payload

Unsigned input file name:

```text
threat_payload.json
```

Required top-level fields:

- `schemaVersion`: integer, currently `1`.
- `feedVersion`: monotonic human-readable feed version.
- `publishedUtc`: ISO-8601 UTC timestamp.
- `ransomwareExtensions`: array of extension intelligence records.
- `yaraRules`: array of YARA behavior/signature records.
- `trustedProcesses`: array of process allow-list records.
- `revokedFeedVersions`: array of feed versions that must no longer be trusted.
- `minimumClientSchemaVersion`: minimum supported client-side schema version.

## Signed Envelope

Output file name:

```text
secure-vault-feed.json
```

The signer parses the payload JSON and serializes it using minified JSON before
signing. The message signed by both algorithms is:

```text
"SecureVaultUltimate:ThreatFeed:v1\n" || SHA256(canonical_payload) || canonical_payload
```

The generated envelope contains:

- `payloadSha256B64`: SHA-256 of the canonical payload.
- `payload`: original parsed payload object.
- `signatures`: one `Ed25519` record and one `ML-DSA-65` record.
- `thresholdPolicy`: currently strict `2-of-2`; both signatures are required.

## Key Files

`feed-signer generate-keys --out <isolated-key-dir>` creates:

- `ed25519.private.json`
- `ed25519.public.json`
- `ml-dsa-65.private.json`
- `ml-dsa-65.public.json`
- `trust-bundle.public.json`

Only `*.public.json` and `trust-bundle.public.json` are intended for future app
integration. Keep `*.private.json` offline and outside any distribution path.

## Commands

```powershell
cargo run --manifest-path .\tools\feed-signer\Cargo.toml -- generate-keys --out C:\SecureVaultFeedKeys
```

```powershell
cargo run --manifest-path .\tools\feed-signer\Cargo.toml -- sign-feed `
  --payload .\tools\feed-signer\spec\threat_payload.sample.json `
  --keys C:\SecureVaultFeedKeys `
  --out .\tools\feed-signer\secure-vault-feed.json
```

CI environments may use `--keys-env-prefix SECURE_VAULT_FEED_` instead of
`--keys`. The signer reads raw JSON or Base64-encoded JSON from:

- `SECURE_VAULT_FEED_ED25519_PRIVATE_JSON`
- `SECURE_VAULT_FEED_ED25519_PRIVATE_JSON_B64`
- `SECURE_VAULT_FEED_ML_DSA_65_PRIVATE_JSON`
- `SECURE_VAULT_FEED_ML_DSA_65_PRIVATE_JSON_B64`

## Isolation Rule

Do not import this crate from `src-tauri`, `src`, or the existing `threat.rs`.
This signer is a detached offline production tool until the main application
integration is deliberately scheduled.
