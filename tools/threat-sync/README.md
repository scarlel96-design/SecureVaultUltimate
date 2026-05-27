# threat-sync

Detached GitHub Actions collector for SecureVault threat-intelligence feeds.

This folder is not imported by the Tauri app. It builds an unsigned
`threat_payload.json`, then the workflow signs it with `tools/feed-signer` and
publishes only the signed `secure-vault-feed.json` envelope.

## Local Dry Run

```powershell
python .\tools\threat-sync\collect_threat_feed.py `
  --out .\tools\threat-sync\out\threat_payload.json
```

For a production-like run, set a URLHaus auth key and require at least one
remote source to succeed:

```powershell
$env:URLHAUS_AUTH_KEY = "YOUR-AUTH-KEY"
python .\tools\threat-sync\collect_threat_feed.py `
  --out .\tools\threat-sync\out\threat_payload.json `
  --require-remote
```

Additional ransomware extension feeds can be configured as newline- or
comma-separated URLs:

```powershell
$env:RANSOMWARE_EXTENSION_FEED_URLS = "https://example.invalid/ransomware-exts.json"
```

## GitHub Secrets

Create feed signing keys offline first:

```powershell
cargo run --manifest-path .\tools\feed-signer\Cargo.toml -- generate-keys --out C:\SecureVaultFeedKeys
```

Store private key JSON as repository secrets. Base64 form is recommended so the
workflow does not need multiline secret handling:

```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content C:\SecureVaultFeedKeys\ed25519.private.json -Raw)))
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content C:\SecureVaultFeedKeys\ml-dsa-65.private.json -Raw)))
```

Required repository secrets:

- `SECURE_VAULT_FEED_ED25519_PRIVATE_JSON_B64`
- `SECURE_VAULT_FEED_ML_DSA_65_PRIVATE_JSON_B64`
- `URLHAUS_AUTH_KEY`

Optional repository variable:

- `RANSOMWARE_EXTENSION_FEED_URLS`

## Deployment

`.github/workflows/threat-sync.yml` runs every 6 hours and can also be started
manually. It writes these files to the `gh-pages` branch:

- `secure-vault-feed.json`
- `secure-vault-feed.json.sha256`
- `health.txt`
- `.nojekyll`
