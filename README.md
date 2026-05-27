# SecureVault Ultimate

Rust + Tauri zero-knowledge encrypted vault prototype.

## Output

- App: `src-tauri/target/release/secure-vault-ultimate.exe`
- Installer: `src-tauri/target/release/bundle/nsis/SecureVault Ultimate_0.1.0_x64-setup.exe`

## Implemented Security Model

- Zero-knowledge local unlock: the master password is never stored on disk.
- Argon2id KDF:
  - memory: 256 MiB
  - time cost: 4
  - parallelism: 2
- HKDF-SHA256 subkeys:
  - encrypted `vault.db`
  - encrypted chunk files
- AES-256-GCM authenticated encryption.
- Directory flattening:
  - physical storage: `vault_data/[UUID].dat`
  - virtual file tree: encrypted inside `vault.db`
- In-place folder locking:
  - selected folder remains visible
  - original child files/folders are removed from view
  - hidden `.svu_lock` stores encrypted `folder.db` and `vault_data/[UUID].dat`
  - unlock restores the original tree back into the same folder and removes `.svu_lock`
- Chunk format:
  - `[12-byte nonce] + [ciphertext] + [16-byte GCM tag] + [Reed-Solomon ECC parity]`
- 64 KiB chunking for all imported files.
- Reed-Solomon ECC:
  - 16 data shards + 3 parity shards per encrypted chunk payload
  - per-shard SHA-256 hashes identify damaged shards
  - decrypt retries with ECC reconstruction after an AES-GCM tag failure
  - successfully repaired chunks are rewritten in repaired form
- `vault.db.bak` shadow index for rollback recovery.
- Orphan chunk quarantine on unlock.
- Missing chunk detection and entry status marking.
- Honeytoken guard for in-place locked folders:
  - hidden `.svu_lock/contacts.xlsx`
  - hidden `.svu_lock/resume.docx`
  - unlock is blocked if these canary files are missing or modified
- Locked folder integrity check without unlocking:
  - validates the hidden `.svu_lock/folder.db`
  - verifies honeytoken files
  - streams encrypted chunks through AES-GCM + ECC verification
- Batch entry operations:
  - selected or full-vault integrity check
  - selected restore
  - selected secure delete
  - parent/child duplicate selections are normalized so a selected folder is processed once
- Secure wipe routine for source deletion and temp cleanup:
  - random overwrite passes
  - truncate to zero bytes
  - OS delete
- Rust `zeroize` for key buffers and sensitive chunk buffers.
- Windows anti-debug checks:
  - `IsDebuggerPresent`
  - `CheckRemoteDebuggerPresent`
- Zero-trust idle lock:
  - frontend activity events refresh the backend session clock
  - configurable inactivity timer drops the in-memory vault session
- Integrated settings:
  - configurable auto-lock timer
  - configurable threat-intelligence update interval
  - HTTPS-only threat feed URL validation
  - decoy password record is stored only as Argon2id salt + hash
- Pull-only threat-intelligence pipeline:
  - Windows WinHTTP HTTPS downloader
  - local `%LOCALAPPDATA%\SecureVaultUltimate\threat_feed.json`
  - signed feed envelope parser
  - payload SHA-256 verification
  - strict 2-of-3 hybrid threshold policy gate
  - downloaded buffers are zeroized on signature failure before fail-fast exit
- Tauri IPC whitelist: frontend only reaches explicit Rust commands.
- Dark high-end React UI:
  - shared progress gauge and terminal-style operation logs
  - drag-and-drop glow interaction
  - multi-select table
  - settings side panel
  - restore, check, delete, lock, and threat-sync operation flows

## Important Limits

No user-space app can guarantee safety if the OS is fully compromised, if a kernel-level attacker is present, or if malware captures the password during typing. Secure wipe is also not physically guaranteed on SSDs, journaling filesystems, cloud-sync folders, or copy-on-write storage.

The current binary integrity check computes the running EXE hash and supports a build-time expected hash through `SECURE_VAULT_EXE_SHA256`. A production release should add a signed manifest or code signing pipeline.

The requested global keyboard hook, fake system-wide key injection, and clipboard poisoning pipeline is intentionally not implemented because it interferes with other applications and overlaps with malware-like behavior. The safer path is app-local paste blocking, OS credential UI integration, or hardware-backed keys.

The remote threat-intelligence pipeline is fail-closed until production Ed25519 and ML-DSA verifying keys are provisioned in the Rust core. The current code enforces the envelope, payload hash, threshold shape, zeroize-on-failure, and fail-fast behavior, but no real remote feed can be accepted without those release keys.

The requested child-process signature tracking, Tauri Isolation Pattern, and CFI hardening still need deeper release-pipeline work before they can be represented as finished protections.

## Build

From this directory:

```powershell
$nodeDir = Resolve-Path -LiteralPath '..\.node\node-v24.16.0-win-x64'
$env:Path = "$env:USERPROFILE\.cargo\bin;$($nodeDir.Path);$env:Path"
$env:CARGO_HOME = Join-Path (Resolve-Path -LiteralPath '..').Path '.cargo-home'
$env:RUSTUP_HOME = Join-Path $env:USERPROFILE '.rustup'
& "$($nodeDir.Path)\npm.cmd" run build
& "$($nodeDir.Path)\npm.cmd" run tauri build
```

The Tauri config does not run `beforeBuildCommand`; build the frontend first,
then run the Tauri bundle step. This avoids Windows `.bin` shim access issues in
the local Codex environment.

## Verification Run

Completed locally before the latest UI/backend batch-operation patch:

```powershell
cargo test --manifest-path .\src-tauri\Cargo.toml --lib
cargo fmt --manifest-path .\src-tauri\Cargo.toml -- --check
cargo clippy --manifest-path .\src-tauri\Cargo.toml --lib -- -D warnings
npm run build
npm run tauri build
```

Completed after the latest high-end UI/settings/threat-feed patch:

```powershell
cargo fmt --manifest-path .\src-tauri\Cargo.toml --check
cargo test --manifest-path .\src-tauri\Cargo.toml --lib
cargo clippy --manifest-path .\src-tauri\Cargo.toml --lib -- -D warnings
cargo build --manifest-path .\src-tauri\Cargo.toml --release --lib
node .\node_modules\typescript\bin\tsc
```

Completed after final installer regeneration:

```powershell
npm run build
node .\node_modules\@tauri-apps\cli\tauri.js build
cargo fmt --manifest-path .\src-tauri\Cargo.toml --check
```

Latest installer:

```text
src-tauri\target\release\bundle\nsis\SecureVault Ultimate_0.1.0_x64-setup.exe
SHA-256: 87D8B9879F576204FEF0CA972FDB1DE7B3D21E6F7F255BD4257116CB33C4696C
```

## Data Location

By default, vault data is stored under:

```text
%LOCALAPPDATA%\SecureVaultUltimate
```

The installer removes the application, not the encrypted vault data. This avoids accidental data loss during uninstall.

In-place locked folders store their encrypted hidden data inside the selected folder:

```text
SelectedFolder\.svu_lock
```
