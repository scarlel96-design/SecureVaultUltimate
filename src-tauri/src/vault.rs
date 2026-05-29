use crate::core::secure_fs::{delete_path_plain, secure_wipe_path};
use crate::error::{VaultError, VaultResult};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

const DB_MAGIC: &str = "SVUDB1";
const DB_AAD: &[u8] = b"SecureVaultUltimate:vault.db:v1";
const CHUNK_AAD_PREFIX: &str = "SecureVaultUltimate:chunk:v1";
const CHUNK_SIZE: usize = 64 * 1024;
const LOCK_DIR_NAME: &str = ".svu_lock";
const CANARY_NAMES: [&str; 2] = ["contacts.xlsx", "resume.docx"];
const CANARY_CONTENT: &str = "SecureVault honeytoken v1\nDo not modify this file.\n";
const NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const ECC_DATA_SHARDS: usize = 16;
const ECC_PARITY_SHARDS: usize = 3;
const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const ARGON2_TIME_COST: u32 = 4;
const ARGON2_PARALLELISM: u32 = 2;
const PBKDF2_HMAC_SHA512_ITERATIONS: u32 = 210_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfConfig {
    pub algorithm: String,
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt_b64: String,
    #[serde(default)]
    pub pbkdf2_iterations: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEnvelope {
    pub magic: String,
    pub version: u32,
    pub kdf: KdfConfig,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDb {
    pub version: u32,
    pub vault_id: String,
    pub created_utc: String,
    pub updated_utc: String,
    pub entries: BTreeMap<String, VaultEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: EntryKind,
    #[serde(default)]
    pub locked_folder_path: Option<String>,
    pub size: u64,
    pub sha256: Option<String>,
    pub chunks: Vec<ChunkRef>,
    pub created_utc: String,
    pub modified_utc: String,
    pub status: EntryStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryStatus {
    Ok,
    Missing,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkRef {
    pub id: String,
    pub index: u64,
    pub plain_len: usize,
    #[serde(default)]
    pub encrypted_len: usize,
    pub sha256: String,
    #[serde(default)]
    pub ecc: Option<ChunkEcc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkEcc {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_len: usize,
    pub shard_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyReport {
    pub missing_chunks: Vec<String>,
    pub orphan_chunks: Vec<String>,
    pub quarantined_chunks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderOperationResult {
    pub path: String,
    pub action: String,
    pub ok: bool,
    pub detail: String,
    pub processed_entries: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryOperationResult {
    pub id: String,
    pub name: String,
    pub action: String,
    pub ok: bool,
    pub detail: String,
    pub processed_entries: usize,
}

#[derive(Debug, Clone)]
pub struct VaultRoot {
    root: PathBuf,
}

pub struct VaultSession {
    root: VaultRoot,
    db_key: Zeroizing<Vec<u8>>,
    chunk_key: Zeroizing<Vec<u8>>,
    pub db: VaultDb,
    temp_extractions: Vec<PathBuf>,
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.db_key.zeroize();
        self.chunk_key.zeroize();
        let _ = self.wipe_temp_extractions();
    }
}

impl VaultRoot {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn default() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::new(base.join("SecureVaultUltimate"))
    }

    pub fn db_path(&self) -> PathBuf {
        self.root.join("vault.db")
    }

    pub fn db_backup_path(&self) -> PathBuf {
        self.root.join("vault.db.bak")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.join("vault_data")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    pub fn temp_dir(&self) -> PathBuf {
        self.root.join("temp")
    }

    pub fn exists(&self) -> bool {
        self.db_path().exists()
    }

    pub fn destroy_all_data(&self) -> VaultResult<()> {
        if self.root.exists() {
            secure_wipe_path(&self.root)
                .map_err(VaultError::from)
                .map_err(|error| {
                    error.with_context(file!(), line!(), "destroy_all_data secure wipe")
                })?;
        }
        Ok(())
    }

    pub fn create(&self, password: &str) -> VaultResult<()> {
        if self.exists() {
            return Err(VaultError::AlreadyExists);
        }

        fs::create_dir_all(self.data_dir())?;
        fs::create_dir_all(self.quarantine_dir())?;
        fs::create_dir_all(self.temp_dir())?;

        let salt = random_vec(32);
        let keys = derive_keys(password, &salt)?;
        let now = Utc::now().to_rfc3339();
        let db = VaultDb {
            version: 1,
            vault_id: Uuid::new_v4().to_string(),
            created_utc: now.clone(),
            updated_utc: now,
            entries: BTreeMap::new(),
        };
        let envelope = encrypt_db(&db, &keys.db_key, salt)?;
        write_envelope_atomic(&self.db_path(), &self.db_backup_path(), &envelope)?;
        Ok(())
    }

    pub fn unlock(&self, password: &str) -> VaultResult<(VaultSession, ConsistencyReport)> {
        if !self.exists() {
            return Err(VaultError::NotInitialized);
        }

        let (envelope, recovered) = match read_envelope(&self.db_path()) {
            Ok(envelope) => (envelope, false),
            Err(_) if self.db_backup_path().exists() => {
                (read_envelope(&self.db_backup_path())?, true)
            }
            Err(_) => return Err(VaultError::AuthenticationFailed),
        };

        let salt = B64
            .decode(envelope.kdf.salt_b64.as_bytes())
            .map_err(|_| VaultError::AuthenticationFailed)?;
        let keys = derive_keys_with_config(password, &salt, &envelope.kdf)?;
        let db = match decrypt_db(&envelope, &keys.db_key) {
            Ok(db) => db,
            Err(VaultError::AuthenticationFailed)
                if !recovered && self.db_backup_path().exists() =>
            {
                let backup = read_envelope(&self.db_backup_path())?;
                let recovered_db = decrypt_db(&backup, &keys.db_key)?;
                fs::copy(self.db_backup_path(), self.db_path())?;
                recovered_db
            }
            Err(error) => return Err(error),
        };

        let mut session = VaultSession {
            root: self.clone(),
            db_key: keys.db_key,
            chunk_key: keys.chunk_key,
            db,
            temp_extractions: Vec::new(),
        };
        let report = session.consistency_check()?;
        Ok((session, report))
    }
}

impl VaultSession {
    pub fn list_entries(&self) -> Vec<VaultEntry> {
        self.db.entries.values().cloned().collect()
    }

    pub fn import_path(
        &mut self,
        source: &Path,
        remove_original: bool,
    ) -> VaultResult<Vec<VaultEntry>> {
        if !source.exists() {
            return Err(VaultError::MissingInput(source.display().to_string()));
        }

        let mut staged_entries = Vec::new();
        let mut staged_chunks = Vec::new();
        let now = Utc::now().to_rfc3339();

        if source.is_file() {
            let entry = self.import_file(source, None, &now, &mut staged_chunks)?;
            staged_entries.push(entry);
        } else {
            let root_id = Uuid::new_v4().to_string();
            let root_name = source
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "folder".to_string());

            staged_entries.push(VaultEntry {
                id: root_id.clone(),
                parent_id: None,
                name: root_name,
                kind: EntryKind::Directory,
                locked_folder_path: None,
                size: 0,
                sha256: None,
                chunks: Vec::new(),
                created_utc: now.clone(),
                modified_utc: now.clone(),
                status: EntryStatus::Ok,
            });

            let mut dir_ids = BTreeMap::new();
            dir_ids.insert(source.to_path_buf(), root_id);

            let mut dirs = Vec::new();
            let mut files = Vec::new();
            for item in WalkDir::new(source)
                .min_depth(1)
                .into_iter()
                .filter_map(Result::ok)
            {
                if item.file_type().is_dir() {
                    dirs.push(item.path().to_path_buf());
                } else if item.file_type().is_file() {
                    files.push(item.path().to_path_buf());
                }
            }
            dirs.sort();
            files.sort();

            for dir in dirs {
                let id = Uuid::new_v4().to_string();
                let parent = dir.parent().and_then(|path| dir_ids.get(path)).cloned();
                let name = dir
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "folder".to_string());
                dir_ids.insert(dir.clone(), id.clone());
                staged_entries.push(VaultEntry {
                    id,
                    parent_id: parent,
                    name,
                    kind: EntryKind::Directory,
                    locked_folder_path: None,
                    size: 0,
                    sha256: None,
                    chunks: Vec::new(),
                    created_utc: now.clone(),
                    modified_utc: now.clone(),
                    status: EntryStatus::Ok,
                });
            }

            for file in files {
                let parent = file.parent().and_then(|path| dir_ids.get(path)).cloned();
                let entry = self.import_file(&file, parent, &now, &mut staged_chunks)?;
                staged_entries.push(entry);
            }
        }

        for entry in &staged_entries {
            self.db.entries.insert(entry.id.clone(), entry.clone());
        }
        self.save_db()?;

        if remove_original {
            secure_wipe_path(source)?;
        }

        Ok(staged_entries)
    }

    pub fn lock_folder_in_place(
        &mut self,
        folder: &Path,
        secure_delete_originals: bool,
    ) -> VaultResult<usize> {
        if !folder.is_dir() {
            return Err(VaultError::MissingInput(folder.display().to_string()));
        }

        let lock_root = folder.join(LOCK_DIR_NAME);
        if lock_root.join("folder.db").exists() {
            return Err(VaultError::FolderAlreadyLocked(
                folder.display().to_string(),
            ));
        }

        let lock_vault = VaultRoot::new(&lock_root);
        fs::create_dir_all(lock_vault.data_dir())?;
        fs::create_dir_all(lock_vault.quarantine_dir())?;
        fs::create_dir_all(lock_vault.temp_dir())?;
        prepare_canaries(&lock_root)?;
        hide_path_best_effort(&lock_root);

        let db = match build_folder_lock_db(folder, &lock_root, &lock_vault, &self.chunk_key) {
            Ok(db) => db,
            Err(error) => {
                let _ = secure_wipe_path(&lock_root);
                return Err(error);
            }
        };

        write_session_envelope_atomic(
            &lock_root.join("folder.db"),
            &lock_root.join("folder.db.bak"),
            &db,
            &self.db_key,
            b"SecureVaultUltimate:folder.db:v1",
        )?;

        let processed_entries = db.entries.len();
        let encrypted_size = db.entries.values().map(|entry| entry.size).sum();
        for item in fs::read_dir(folder)? {
            let path = item?.path();
            if path.file_name().and_then(|name| name.to_str()) == Some(LOCK_DIR_NAME) {
                continue;
            }
            if secure_delete_originals {
                secure_wipe_path(&path)?;
            } else {
                delete_path_plain(&path)?;
            }
        }

        hide_path_best_effort(&lock_root);
        self.upsert_locked_folder_marker(folder, processed_entries, encrypted_size)?;
        Ok(processed_entries)
    }

    pub fn unlock_folder_in_place(&mut self, folder: &Path) -> VaultResult<usize> {
        if !folder.is_dir() {
            return Err(VaultError::MissingInput(folder.display().to_string()));
        }

        let lock_root = folder.join(LOCK_DIR_NAME);
        let db_path = lock_root.join("folder.db");
        if !db_path.exists() {
            return Err(VaultError::FolderNotLocked(folder.display().to_string()));
        }

        let lock_vault = VaultRoot::new(&lock_root);
        check_canaries(&lock_root)?;
        let db =
            read_session_envelope(&db_path, &self.db_key, b"SecureVaultUltimate:folder.db:v1")?;
        let processed_entries = db.entries.len();
        restore_db_roots(&lock_vault, &self.chunk_key, &db, folder)?;
        secure_wipe_path(&lock_root)?;
        self.remove_locked_folder_marker(folder)?;
        Ok(processed_entries)
    }

    pub fn check_folder_in_place(&self, folder: &Path) -> VaultResult<usize> {
        if !folder.is_dir() {
            return Err(VaultError::MissingInput(folder.display().to_string()));
        }

        let lock_root = folder.join(LOCK_DIR_NAME);
        let db_path = lock_root.join("folder.db");
        if !db_path.exists() {
            return Err(VaultError::FolderNotLocked(folder.display().to_string()));
        }

        let lock_vault = VaultRoot::new(&lock_root);
        check_canaries(&lock_root)?;
        let db =
            read_session_envelope(&db_path, &self.db_key, b"SecureVaultUltimate:folder.db:v1")?;
        validate_db_roots(&lock_vault, &self.chunk_key, &db)
    }

    pub fn lock_folders_in_place(
        &mut self,
        folders: &[PathBuf],
        secure_delete_originals: bool,
    ) -> Vec<FolderOperationResult> {
        folders
            .iter()
            .map(
                |folder| match self.lock_folder_in_place(folder, secure_delete_originals) {
                    Ok(count) => FolderOperationResult {
                        path: folder.display().to_string(),
                        action: "lock".to_string(),
                        ok: true,
                        detail: "보호 폴더 격리 완료".to_string(),
                        processed_entries: count,
                    },
                    Err(error) => FolderOperationResult {
                        path: folder.display().to_string(),
                        action: "lock".to_string(),
                        ok: false,
                        detail: error.to_string(),
                        processed_entries: 0,
                    },
                },
            )
            .collect()
    }

    pub fn unlock_folders_in_place(&mut self, folders: &[PathBuf]) -> Vec<FolderOperationResult> {
        folders
            .iter()
            .map(|folder| match self.unlock_folder_in_place(folder) {
                Ok(count) => FolderOperationResult {
                    path: folder.display().to_string(),
                    action: "unlock".to_string(),
                    ok: true,
                    detail: "보호 폴더 원위치 복귀 완료".to_string(),
                    processed_entries: count,
                },
                Err(error) => FolderOperationResult {
                    path: folder.display().to_string(),
                    action: "unlock".to_string(),
                    ok: false,
                    detail: error.to_string(),
                    processed_entries: 0,
                },
            })
            .collect()
    }

    pub fn unlock_locked_entries_to_original_paths(
        &mut self,
        entry_ids: &[String],
    ) -> Vec<EntryOperationResult> {
        let ids = self.effective_entry_ids(entry_ids);
        ids.into_iter()
            .map(|id| {
                let entry = self.db.entries.get(&id).cloned();
                let name = entry
                    .as_ref()
                    .map(|entry| entry.name.clone())
                    .unwrap_or_else(|| id.clone());
                let Some(path) = entry.and_then(|entry| entry.locked_folder_path) else {
                    return EntryOperationResult {
                        id,
                        name,
                        action: "unlock".to_string(),
                        ok: false,
                        detail: "선택 항목은 원래 위치 복귀형 보호 폴더가 아닙니다.".to_string(),
                        processed_entries: 0,
                    };
                };
                match self.unlock_folder_in_place(Path::new(&path)) {
                    Ok(count) => EntryOperationResult {
                        id,
                        name,
                        action: "unlock".to_string(),
                        ok: true,
                        detail: "보호 폴더가 원래 위치로 복귀되었습니다.".to_string(),
                        processed_entries: count,
                    },
                    Err(error) => EntryOperationResult {
                        id,
                        name,
                        action: "unlock".to_string(),
                        ok: false,
                        detail: error.to_string(),
                        processed_entries: 0,
                    },
                }
            })
            .collect()
    }

    pub fn locked_folder_paths_for_entries(&self, entry_ids: &[String]) -> Vec<PathBuf> {
        self.effective_entry_ids(entry_ids)
            .into_iter()
            .filter_map(|id| {
                self.db
                    .entries
                    .get(&id)
                    .and_then(|entry| entry.locked_folder_path.as_deref())
                    .map(PathBuf::from)
            })
            .collect()
    }

    pub fn check_folders_in_place(&self, folders: &[PathBuf]) -> Vec<FolderOperationResult> {
        folders
            .iter()
            .map(|folder| match self.check_folder_in_place(folder) {
                Ok(count) => FolderOperationResult {
                    path: folder.display().to_string(),
                    action: "check".to_string(),
                    ok: true,
                    detail: "보호 폴더 무결성 검사 통과".to_string(),
                    processed_entries: count,
                },
                Err(error) => FolderOperationResult {
                    path: folder.display().to_string(),
                    action: "check".to_string(),
                    ok: false,
                    detail: error.to_string(),
                    processed_entries: 0,
                },
            })
            .collect()
    }

    pub fn destroy_tracked_external_locks(&self) -> VaultResult<usize> {
        let mut count = 0;
        for path in self
            .db
            .entries
            .values()
            .filter_map(|entry| entry.locked_folder_path.as_deref())
        {
            let lock_root = PathBuf::from(path).join(LOCK_DIR_NAME);
            if lock_root.exists() {
                secure_wipe_path(&lock_root)?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn vanguard_guard_tick(&self) -> VaultResult<()> {
        for entry in self.db.entries.values() {
            if let Some(path) = &entry.locked_folder_path {
                let lock_root = PathBuf::from(path).join(LOCK_DIR_NAME);
                check_canaries(&lock_root)?;
            }
            for chunk in &entry.chunks {
                let chunk_path = self.root.data_dir().join(format!("{}.dat", chunk.id));
                if !chunk_path.exists() {
                    return Err(VaultError::MissingChunk(chunk.id.clone()));
                }
            }
        }
        Ok(())
    }

    pub fn restore_entry(&self, entry_id: &str, destination: &Path) -> VaultResult<PathBuf> {
        let entry = self
            .db
            .entries
            .get(entry_id)
            .ok_or(VaultError::EntryNotFound)?;
        if let Some(path) = &entry.locked_folder_path {
            return Err(VaultError::MissingInput(format!(
                "원위치 보호 폴더는 '원래 위치로 복귀' 기능으로 해제하세요: {path}"
            )));
        }
        fs::create_dir_all(destination)?;
        self.restore_entry_recursive(entry, destination)
    }

    pub fn restore_entries(
        &self,
        entry_ids: &[String],
        destination: &Path,
    ) -> Vec<EntryOperationResult> {
        self.effective_entry_ids(entry_ids)
            .into_iter()
            .map(|id| {
                let name = self
                    .db
                    .entries
                    .get(&id)
                    .map(|entry| entry.name.clone())
                    .unwrap_or_else(|| id.clone());
                match self.restore_entry(&id, destination) {
                    Ok(_) => EntryOperationResult {
                        id,
                        name,
                        action: "restore".to_string(),
                        ok: true,
                        detail: "복원 완료".to_string(),
                        processed_entries: 1,
                    },
                    Err(error) => EntryOperationResult {
                        id,
                        name,
                        action: "restore".to_string(),
                        ok: false,
                        detail: error.to_string(),
                        processed_entries: 0,
                    },
                }
            })
            .collect()
    }

    pub fn check_entries(&self, entry_ids: &[String]) -> Vec<EntryOperationResult> {
        self.effective_entry_ids(entry_ids)
            .into_iter()
            .map(|id| {
                let name = self
                    .db
                    .entries
                    .get(&id)
                    .map(|entry| entry.name.clone())
                    .unwrap_or_else(|| id.clone());
                let result = if let Some(path) = self
                    .db
                    .entries
                    .get(&id)
                    .and_then(|entry| entry.locked_folder_path.clone())
                {
                    self.check_folder_in_place(Path::new(&path))
                } else {
                    self.validate_entry_tree(&id)
                };
                match result {
                    Ok(count) => EntryOperationResult {
                        id,
                        name,
                        action: "check".to_string(),
                        ok: true,
                        detail: "무결성 검사 통과".to_string(),
                        processed_entries: count,
                    },
                    Err(error) => EntryOperationResult {
                        id,
                        name,
                        action: "check".to_string(),
                        ok: false,
                        detail: error.to_string(),
                        processed_entries: 0,
                    },
                }
            })
            .collect()
    }

    pub fn delete_entries(&mut self, entry_ids: &[String]) -> Vec<EntryOperationResult> {
        let mut results = Vec::new();
        let mut changed = false;

        for id in self.effective_entry_ids(entry_ids) {
            let name = self
                .db
                .entries
                .get(&id)
                .map(|entry| entry.name.clone())
                .unwrap_or_else(|| id.clone());
            if let Some(path) = self
                .db
                .entries
                .get(&id)
                .and_then(|entry| entry.locked_folder_path.clone())
            {
                let lock_root = PathBuf::from(path).join(LOCK_DIR_NAME);
                if lock_root.exists() {
                    if let Err(error) = secure_wipe_path(&lock_root) {
                        results.push(EntryOperationResult {
                            id,
                            name,
                            action: "delete".to_string(),
                            ok: false,
                            detail: error.to_string(),
                            processed_entries: 0,
                        });
                        continue;
                    }
                }
                self.db.entries.remove(&id);
                changed = true;
                results.push(EntryOperationResult {
                    id,
                    name,
                    action: "delete".to_string(),
                    ok: true,
                    detail: "보호 폴더 데이터 삭제 완료".to_string(),
                    processed_entries: 1,
                });
                continue;
            }
            let tree_ids = match self.collect_entry_tree_ids(&id) {
                Ok(ids) => ids,
                Err(error) => {
                    results.push(EntryOperationResult {
                        id,
                        name,
                        action: "delete".to_string(),
                        ok: false,
                        detail: error.to_string(),
                        processed_entries: 0,
                    });
                    continue;
                }
            };

            let mut chunk_ids = Vec::new();
            for tree_id in &tree_ids {
                if let Some(entry) = self.db.entries.get(tree_id) {
                    for chunk in &entry.chunks {
                        chunk_ids.push(chunk.id.clone());
                    }
                }
            }
            for tree_id in &tree_ids {
                self.db.entries.remove(tree_id);
            }
            for chunk_id in chunk_ids {
                let chunk_path = self.root.data_dir().join(format!("{chunk_id}.dat"));
                if chunk_path.exists() {
                    let _ = secure_wipe_path(&chunk_path);
                }
            }
            changed = true;
            results.push(EntryOperationResult {
                id,
                name,
                action: "delete".to_string(),
                ok: true,
                detail: "삭제 완료".to_string(),
                processed_entries: tree_ids.len(),
            });
        }

        if changed {
            if let Err(error) = self.save_db() {
                results.push(EntryOperationResult {
                    id: "vault.db".to_string(),
                    name: "vault.db".to_string(),
                    action: "delete".to_string(),
                    ok: false,
                    detail: error.to_string(),
                    processed_entries: 0,
                });
            }
        }

        results
    }

    pub fn consistency_check(&mut self) -> VaultResult<ConsistencyReport> {
        fs::create_dir_all(self.root.data_dir())?;
        fs::create_dir_all(self.root.quarantine_dir())?;

        let mut referenced = BTreeSet::new();
        let mut missing = Vec::new();

        for entry in self.db.entries.values_mut() {
            if entry.kind == EntryKind::Directory {
                entry.status = EntryStatus::Ok;
                continue;
            }

            let mut missing_for_entry = 0;
            for chunk in &entry.chunks {
                referenced.insert(format!("{}.dat", chunk.id));
                if !self
                    .root
                    .data_dir()
                    .join(format!("{}.dat", chunk.id))
                    .exists()
                {
                    missing_for_entry += 1;
                    missing.push(chunk.id.clone());
                }
            }
            entry.status = if missing_for_entry == 0 {
                EntryStatus::Ok
            } else if missing_for_entry == entry.chunks.len() {
                EntryStatus::Missing
            } else {
                EntryStatus::Partial
            };
        }

        let mut orphan = Vec::new();
        let mut quarantined = Vec::new();
        for item in fs::read_dir(self.root.data_dir())? {
            let item = item?;
            let path = item.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("dat") {
                continue;
            }
            let name = item.file_name().to_string_lossy().to_string();
            if !referenced.contains(&name) {
                let target = self.root.quarantine_dir().join(format!(
                    "{}_{}",
                    Utc::now().timestamp_millis(),
                    name
                ));
                fs::rename(&path, &target)?;
                orphan.push(name);
                quarantined.push(target.display().to_string());
            }
        }

        if !missing.is_empty() {
            self.save_db()?;
        }

        Ok(ConsistencyReport {
            missing_chunks: missing,
            orphan_chunks: orphan,
            quarantined_chunks: quarantined,
        })
    }

    pub fn lock(mut self) -> VaultResult<()> {
        self.wipe_temp_extractions()?;
        Ok(())
    }

    fn import_file(
        &self,
        path: &Path,
        parent_id: Option<String>,
        now: &str,
        staged_chunks: &mut Vec<PathBuf>,
    ) -> VaultResult<VaultEntry> {
        let id = Uuid::new_v4().to_string();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        let mut chunks = Vec::new();
        let mut sha = Sha256::new();
        let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
        let mut index = 0u64;

        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            sha.update(&buffer[..read]);
            let chunk_id = Uuid::new_v4().to_string();
            let chunk_hash = Sha256::digest(&buffer[..read]);
            let storage = write_chunk(
                &self.root.data_dir().join(format!("{chunk_id}.dat")),
                &self.chunk_key,
                &id,
                &chunk_id,
                index,
                read,
                &buffer[..read],
            )?;
            staged_chunks.push(self.root.data_dir().join(format!("{chunk_id}.dat")));
            chunks.push(ChunkRef {
                id: chunk_id,
                index,
                plain_len: read,
                encrypted_len: storage.encrypted_len,
                sha256: hex_lower(&chunk_hash),
                ecc: Some(storage.ecc),
            });
            index += 1;
        }

        Ok(VaultEntry {
            id,
            parent_id,
            name,
            kind: EntryKind::File,
            locked_folder_path: None,
            size,
            sha256: Some(hex_lower(&sha.finalize())),
            chunks,
            created_utc: now.to_string(),
            modified_utc: now.to_string(),
            status: EntryStatus::Ok,
        })
    }

    fn restore_entry_recursive(
        &self,
        entry: &VaultEntry,
        destination: &Path,
    ) -> VaultResult<PathBuf> {
        let target = destination.join(&entry.name);
        match entry.kind {
            EntryKind::Directory => {
                fs::create_dir_all(&target)?;
                let mut children: Vec<_> = self
                    .db
                    .entries
                    .values()
                    .filter(|candidate| candidate.parent_id.as_deref() == Some(&entry.id))
                    .collect();
                children.sort_by(|a, b| a.name.cmp(&b.name));
                for child in children {
                    self.restore_entry_recursive(child, &target)?;
                }
            }
            EntryKind::File => {
                if entry.status == EntryStatus::Missing {
                    return Err(VaultError::MissingChunk(entry.id.clone()));
                }
                let mut output = File::create(&target)?;
                let mut file_sha = Sha256::new();
                for chunk in &entry.chunks {
                    let chunk_path = self.root.data_dir().join(format!("{}.dat", chunk.id));
                    if !chunk_path.exists() {
                        return Err(VaultError::MissingChunk(chunk.id.clone()));
                    }
                    let plain = read_chunk(&chunk_path, &self.chunk_key, &entry.id, chunk)?;
                    if hex_lower(&Sha256::digest(&plain)) != chunk.sha256 {
                        return Err(VaultError::AuthenticationFailed);
                    }
                    file_sha.update(&plain);
                    output.write_all(&plain)?;
                }
                output.sync_all()?;
                if let Some(expected) = &entry.sha256 {
                    if hex_lower(&file_sha.finalize()) != *expected {
                        return Err(VaultError::AuthenticationFailed);
                    }
                }
            }
        }
        Ok(target)
    }

    fn top_level_entry_ids(&self) -> Vec<String> {
        self.db
            .entries
            .values()
            .filter(|entry| entry.parent_id.is_none())
            .map(|entry| entry.id.clone())
            .collect()
    }

    fn upsert_locked_folder_marker(
        &mut self,
        folder: &Path,
        processed_entries: usize,
        encrypted_size: u64,
    ) -> VaultResult<()> {
        let marker_path = normalized_path_string(folder);
        let now = Utc::now().to_rfc3339();
        if let Some(entry) = self
            .db
            .entries
            .values_mut()
            .find(|entry| entry.locked_folder_path.as_deref() == Some(marker_path.as_str()))
        {
            entry.size = encrypted_size;
            entry.modified_utc = now;
            entry.status = EntryStatus::Ok;
        } else {
            let id = Uuid::new_v4().to_string();
            let name = folder
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| marker_path.clone());
            self.db.entries.insert(
                id.clone(),
                VaultEntry {
                    id,
                    parent_id: None,
                    name,
                    kind: EntryKind::Directory,
                    locked_folder_path: Some(marker_path),
                    size: encrypted_size,
                    sha256: Some(format!("external-lock:{processed_entries}")),
                    chunks: Vec::new(),
                    created_utc: now.clone(),
                    modified_utc: now,
                    status: EntryStatus::Ok,
                },
            );
        }
        self.save_db()
    }

    fn remove_locked_folder_marker(&mut self, folder: &Path) -> VaultResult<()> {
        let marker_path = normalized_path_string(folder);
        let ids: Vec<_> = self
            .db
            .entries
            .values()
            .filter(|entry| entry.locked_folder_path.as_deref() == Some(marker_path.as_str()))
            .map(|entry| entry.id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        for id in ids {
            self.db.entries.remove(&id);
        }
        self.save_db()
    }

    fn effective_entry_ids(&self, entry_ids: &[String]) -> Vec<String> {
        let mut ids = if entry_ids.is_empty() {
            self.top_level_entry_ids()
        } else {
            let mut seen = BTreeSet::new();
            entry_ids
                .iter()
                .filter(|id| seen.insert((*id).clone()))
                .cloned()
                .collect()
        };
        let selected: BTreeSet<_> = ids.iter().cloned().collect();
        ids.retain(|id| !self.has_selected_ancestor(id, &selected));
        ids
    }

    fn has_selected_ancestor(&self, entry_id: &str, selected: &BTreeSet<String>) -> bool {
        let mut parent = self
            .db
            .entries
            .get(entry_id)
            .and_then(|entry| entry.parent_id.clone());
        while let Some(parent_id) = parent {
            if selected.contains(&parent_id) {
                return true;
            }
            parent = self
                .db
                .entries
                .get(&parent_id)
                .and_then(|entry| entry.parent_id.clone());
        }
        false
    }

    fn collect_entry_tree_ids(&self, entry_id: &str) -> VaultResult<Vec<String>> {
        let entry = self
            .db
            .entries
            .get(entry_id)
            .ok_or(VaultError::EntryNotFound)?;
        let mut ids = vec![entry.id.clone()];
        let mut children: Vec<_> = self
            .db
            .entries
            .values()
            .filter(|candidate| candidate.parent_id.as_deref() == Some(entry_id))
            .map(|candidate| candidate.id.clone())
            .collect();
        children.sort();
        for child_id in children {
            ids.extend(self.collect_entry_tree_ids(&child_id)?);
        }
        Ok(ids)
    }

    fn validate_entry_tree(&self, entry_id: &str) -> VaultResult<usize> {
        let entry = self
            .db
            .entries
            .get(entry_id)
            .ok_or(VaultError::EntryNotFound)?;
        match entry.kind {
            EntryKind::Directory => {
                let mut count = 1;
                let mut children: Vec<_> = self
                    .db
                    .entries
                    .values()
                    .filter(|candidate| candidate.parent_id.as_deref() == Some(&entry.id))
                    .map(|candidate| candidate.id.clone())
                    .collect();
                children.sort();
                for child_id in children {
                    count += self.validate_entry_tree(&child_id)?;
                }
                Ok(count)
            }
            EntryKind::File => {
                let mut file_sha = Sha256::new();
                for chunk in &entry.chunks {
                    let chunk_path = self.root.data_dir().join(format!("{}.dat", chunk.id));
                    if !chunk_path.exists() {
                        return Err(VaultError::MissingChunk(chunk.id.clone()));
                    }
                    let plain = read_chunk(&chunk_path, &self.chunk_key, &entry.id, chunk)?;
                    if hex_lower(&Sha256::digest(&plain)) != chunk.sha256 {
                        return Err(VaultError::AuthenticationFailed);
                    }
                    file_sha.update(&plain);
                }
                if let Some(expected) = &entry.sha256 {
                    if hex_lower(&file_sha.finalize()) != *expected {
                        return Err(VaultError::AuthenticationFailed);
                    }
                }
                Ok(1)
            }
        }
    }

    fn save_db(&mut self) -> VaultResult<()> {
        self.db.updated_utc = Utc::now().to_rfc3339();
        let current = read_envelope(&self.root.db_path())?;
        let envelope = encrypt_db_with_kdf(&self.db, &self.db_key, current.kdf)?;
        write_envelope_atomic(&self.root.db_path(), &self.root.db_backup_path(), &envelope)?;
        Ok(())
    }

    fn wipe_temp_extractions(&mut self) -> VaultResult<()> {
        for path in self.temp_extractions.drain(..) {
            if path.exists() {
                secure_wipe_path(&path)?;
            }
        }
        Ok(())
    }
}

struct VaultKeys {
    db_key: Zeroizing<Vec<u8>>,
    chunk_key: Zeroizing<Vec<u8>>,
}

fn derive_keys(password: &str, salt: &[u8]) -> VaultResult<VaultKeys> {
    let config = KdfConfig {
        algorithm: "argon2id+pbkdf2-hmac-sha512".to_string(),
        memory_kib: ARGON2_MEMORY_KIB,
        time_cost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        salt_b64: B64.encode(salt),
        pbkdf2_iterations: Some(PBKDF2_HMAC_SHA512_ITERATIONS),
    };
    derive_keys_with_config(password, salt, &config)
}

fn derive_keys_with_config(
    password: &str,
    salt: &[u8],
    config: &KdfConfig,
) -> VaultResult<VaultKeys> {
    if config.algorithm != "argon2id" && config.algorithm != "argon2id+pbkdf2-hmac-sha512" {
        return Err(VaultError::UnsupportedFormat);
    }
    let params = Params::new(
        config.memory_kib,
        config.time_cost,
        config.parallelism,
        Some(KEY_SIZE),
    )
    .map_err(|error| VaultError::Argon2(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let mut root_key = Zeroizing::new(vec![0u8; KEY_SIZE]);
    argon2
        .hash_password_into(&password_bytes, salt, &mut root_key)
        .map_err(|error| VaultError::Argon2(error.to_string()))?;
    if config.algorithm == "argon2id+pbkdf2-hmac-sha512" {
        let iterations = config
            .pbkdf2_iterations
            .unwrap_or(PBKDF2_HMAC_SHA512_ITERATIONS)
            .max(100_000);
        let pbkdf2_key = pbkdf2_hmac_sha512(&password_bytes, salt, iterations, KEY_SIZE)?;
        let mut combiner = Sha512::new();
        combiner.update(b"SecureVaultUltimate:hybrid-kdf:v2");
        combiner.update(&root_key);
        combiner.update(&pbkdf2_key);
        let digest = combiner.finalize();
        root_key.copy_from_slice(&digest[..KEY_SIZE]);
    }
    let hk = Hkdf::<Sha256>::new(Some(b"SVU-HKDF-v1"), &root_key);
    let mut db_key = Zeroizing::new(vec![0u8; KEY_SIZE]);
    let mut chunk_key = Zeroizing::new(vec![0u8; KEY_SIZE]);
    hk.expand(b"vault-db-key", &mut db_key)
        .map_err(|_| VaultError::Crypto)?;
    hk.expand(b"vault-chunk-key", &mut chunk_key)
        .map_err(|_| VaultError::Crypto)?;
    Ok(VaultKeys { db_key, chunk_key })
}

fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> VaultResult<Zeroizing<Vec<u8>>> {
    type HmacSha512 = Hmac<Sha512>;

    let mut output = Zeroizing::new(vec![0u8; output_len]);
    let mut block_index = 1u32;
    let mut offset = 0usize;
    while offset < output_len {
        let mut mac =
            <HmacSha512 as Mac>::new_from_slice(password).map_err(|_| VaultError::Crypto)?;
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = Zeroizing::new(mac.finalize().into_bytes().to_vec());
        let mut t = Zeroizing::new(u.clone());

        for _ in 1..iterations {
            let mut mac =
                <HmacSha512 as Mac>::new_from_slice(password).map_err(|_| VaultError::Crypto)?;
            mac.update(&u);
            u = Zeroizing::new(mac.finalize().into_bytes().to_vec());
            for (target, source) in t.iter_mut().zip(u.iter()) {
                *target ^= *source;
            }
        }

        let take = (output_len - offset).min(t.len());
        output[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block_index = block_index.checked_add(1).ok_or(VaultError::Crypto)?;
    }
    Ok(output)
}

fn encrypt_db(db: &VaultDb, db_key: &[u8], salt: Vec<u8>) -> VaultResult<VaultEnvelope> {
    encrypt_db_with_kdf(
        db,
        db_key,
        KdfConfig {
            algorithm: "argon2id+pbkdf2-hmac-sha512".to_string(),
            memory_kib: ARGON2_MEMORY_KIB,
            time_cost: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
            salt_b64: B64.encode(salt),
            pbkdf2_iterations: Some(PBKDF2_HMAC_SHA512_ITERATIONS),
        },
    )
}

fn encrypt_db_with_kdf(db: &VaultDb, db_key: &[u8], kdf: KdfConfig) -> VaultResult<VaultEnvelope> {
    let nonce = random_vec(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(db_key).map_err(|_| VaultError::Crypto)?;
    let mut plain = Zeroizing::new(serde_json::to_vec(db)?);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: DB_AAD,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    plain.zeroize();
    Ok(VaultEnvelope {
        magic: DB_MAGIC.to_string(),
        version: 1,
        kdf,
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn decrypt_db(envelope: &VaultEnvelope, db_key: &[u8]) -> VaultResult<VaultDb> {
    if envelope.magic != DB_MAGIC || envelope.version != 1 {
        return Err(VaultError::UnsupportedFormat);
    }
    let nonce = B64
        .decode(envelope.nonce_b64.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let ciphertext = B64
        .decode(envelope.ciphertext_b64.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let cipher = Aes256Gcm::new_from_slice(db_key).map_err(|_| VaultError::Crypto)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: DB_AAD,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    serde_json::from_slice(&plain).map_err(VaultError::Json)
}

fn read_envelope(path: &Path) -> VaultResult<VaultEnvelope> {
    let bytes = fs::read(path)?;
    let envelope = serde_json::from_slice::<VaultEnvelope>(&bytes)?;
    Ok(envelope)
}

fn write_envelope_atomic(
    path: &Path,
    backup_path: &Path,
    envelope: &VaultEnvelope,
) -> VaultResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    {
        let mut temp = File::create(&temp_path)?;
        temp.write_all(&serde_json::to_vec_pretty(envelope)?)?;
        temp.sync_all()?;
    }

    if path.exists() {
        fs::copy(path, backup_path)?;
        fs::remove_file(path)?;
    }
    fs::rename(temp_path, path)?;
    Ok(())
}

fn write_session_envelope_atomic(
    path: &Path,
    backup_path: &Path,
    db: &VaultDb,
    db_key: &[u8],
    aad: &[u8],
) -> VaultResult<()> {
    let nonce = random_vec(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(db_key).map_err(|_| VaultError::Crypto)?;
    let mut plain = Zeroizing::new(serde_json::to_vec(db)?);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad })
        .map_err(|_| VaultError::Crypto)?;
    plain.zeroize();
    let envelope = VaultEnvelope {
        magic: DB_MAGIC.to_string(),
        version: 1,
        kdf: KdfConfig {
            algorithm: "session-key".to_string(),
            memory_kib: 0,
            time_cost: 0,
            parallelism: 0,
            salt_b64: String::new(),
            pbkdf2_iterations: None,
        },
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
    };
    write_envelope_atomic(path, backup_path, &envelope)
}

fn read_session_envelope(path: &Path, db_key: &[u8], aad: &[u8]) -> VaultResult<VaultDb> {
    let envelope = read_envelope(path)?;
    if envelope.magic != DB_MAGIC || envelope.version != 1 {
        return Err(VaultError::UnsupportedFormat);
    }
    let nonce = B64
        .decode(envelope.nonce_b64.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let ciphertext = B64
        .decode(envelope.ciphertext_b64.as_bytes())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let cipher = Aes256Gcm::new_from_slice(db_key).map_err(|_| VaultError::Crypto)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    serde_json::from_slice(&plain).map_err(VaultError::Json)
}

fn build_folder_lock_db(
    folder: &Path,
    lock_root: &Path,
    lock_vault: &VaultRoot,
    chunk_key: &[u8],
) -> VaultResult<VaultDb> {
    let now = Utc::now().to_rfc3339();
    let mut db = VaultDb {
        version: 1,
        vault_id: Uuid::new_v4().to_string(),
        created_utc: now.clone(),
        updated_utc: now.clone(),
        entries: BTreeMap::new(),
    };
    let mut dir_ids = BTreeMap::new();
    dir_ids.insert(folder.to_path_buf(), None::<String>);

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for item in WalkDir::new(folder)
        .min_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = item.path();
        if path.starts_with(lock_root) {
            continue;
        }
        if item.file_type().is_dir() {
            dirs.push(path.to_path_buf());
        } else if item.file_type().is_file() {
            files.push(path.to_path_buf());
        }
    }
    dirs.sort();
    files.sort();

    for dir in dirs {
        let id = Uuid::new_v4().to_string();
        let parent = dir
            .parent()
            .and_then(|path| dir_ids.get(path))
            .cloned()
            .flatten();
        let name = dir
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".to_string());
        dir_ids.insert(dir.clone(), Some(id.clone()));
        db.entries.insert(
            id.clone(),
            VaultEntry {
                id,
                parent_id: parent,
                name,
                kind: EntryKind::Directory,
                locked_folder_path: None,
                size: 0,
                sha256: None,
                chunks: Vec::new(),
                created_utc: now.clone(),
                modified_utc: now.clone(),
                status: EntryStatus::Ok,
            },
        );
    }

    for file in files {
        let parent = file
            .parent()
            .and_then(|path| dir_ids.get(path))
            .cloned()
            .flatten();
        let entry = import_file_to_root(lock_vault, chunk_key, &file, parent, &now)?;
        db.entries.insert(entry.id.clone(), entry);
    }

    Ok(db)
}

fn import_file_to_root(
    root: &VaultRoot,
    chunk_key: &[u8],
    path: &Path,
    parent_id: Option<String>,
    now: &str,
) -> VaultResult<VaultEntry> {
    let id = Uuid::new_v4().to_string();
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut chunks = Vec::new();
    let mut sha = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut index = 0u64;

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sha.update(&buffer[..read]);
        let chunk_id = Uuid::new_v4().to_string();
        let chunk_hash = Sha256::digest(&buffer[..read]);
        let storage = write_chunk(
            &root.data_dir().join(format!("{chunk_id}.dat")),
            chunk_key,
            &id,
            &chunk_id,
            index,
            read,
            &buffer[..read],
        )?;
        chunks.push(ChunkRef {
            id: chunk_id,
            index,
            plain_len: read,
            encrypted_len: storage.encrypted_len,
            sha256: hex_lower(&chunk_hash),
            ecc: Some(storage.ecc),
        });
        index += 1;
    }

    Ok(VaultEntry {
        id,
        parent_id,
        name,
        kind: EntryKind::File,
        locked_folder_path: None,
        size,
        sha256: Some(hex_lower(&sha.finalize())),
        chunks,
        created_utc: now.to_string(),
        modified_utc: now.to_string(),
        status: EntryStatus::Ok,
    })
}

fn restore_db_roots(
    root: &VaultRoot,
    chunk_key: &[u8],
    db: &VaultDb,
    destination: &Path,
) -> VaultResult<()> {
    let mut roots: Vec<_> = db
        .entries
        .values()
        .filter(|entry| entry.parent_id.is_none())
        .collect();
    roots.sort_by(|a, b| a.name.cmp(&b.name));
    for entry in roots {
        restore_db_entry(root, chunk_key, db, entry, destination)?;
    }
    Ok(())
}

fn normalized_path_string(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn validate_db_roots(root: &VaultRoot, chunk_key: &[u8], db: &VaultDb) -> VaultResult<usize> {
    let mut count = 0;
    let mut roots: Vec<_> = db
        .entries
        .values()
        .filter(|entry| entry.parent_id.is_none())
        .collect();
    roots.sort_by(|a, b| a.name.cmp(&b.name));
    for entry in roots {
        count += validate_db_entry(root, chunk_key, db, entry)?;
    }
    Ok(count)
}

fn validate_db_entry(
    root: &VaultRoot,
    chunk_key: &[u8],
    db: &VaultDb,
    entry: &VaultEntry,
) -> VaultResult<usize> {
    match entry.kind {
        EntryKind::Directory => {
            let mut count = 1;
            let mut children: Vec<_> = db
                .entries
                .values()
                .filter(|candidate| candidate.parent_id.as_deref() == Some(&entry.id))
                .collect();
            children.sort_by(|a, b| a.name.cmp(&b.name));
            for child in children {
                count += validate_db_entry(root, chunk_key, db, child)?;
            }
            Ok(count)
        }
        EntryKind::File => {
            let mut file_sha = Sha256::new();
            for chunk in &entry.chunks {
                let chunk_path = root.data_dir().join(format!("{}.dat", chunk.id));
                if !chunk_path.exists() {
                    return Err(VaultError::MissingChunk(chunk.id.clone()));
                }
                let plain = read_chunk(&chunk_path, chunk_key, &entry.id, chunk)?;
                if hex_lower(&Sha256::digest(&plain)) != chunk.sha256 {
                    return Err(VaultError::AuthenticationFailed);
                }
                file_sha.update(&plain);
            }
            if let Some(expected) = &entry.sha256 {
                if hex_lower(&file_sha.finalize()) != *expected {
                    return Err(VaultError::AuthenticationFailed);
                }
            }
            Ok(1)
        }
    }
}

fn restore_db_entry(
    root: &VaultRoot,
    chunk_key: &[u8],
    db: &VaultDb,
    entry: &VaultEntry,
    destination: &Path,
) -> VaultResult<PathBuf> {
    let target = destination.join(&entry.name);
    if target.exists() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("복원 대상이 이미 존재합니다: {}", target.display()),
        )));
    }
    match entry.kind {
        EntryKind::Directory => {
            fs::create_dir_all(&target)?;
            let mut children: Vec<_> = db
                .entries
                .values()
                .filter(|candidate| candidate.parent_id.as_deref() == Some(&entry.id))
                .collect();
            children.sort_by(|a, b| a.name.cmp(&b.name));
            for child in children {
                restore_db_entry(root, chunk_key, db, child, &target)?;
            }
        }
        EntryKind::File => {
            let mut output = File::create(&target)?;
            let mut file_sha = Sha256::new();
            for chunk in &entry.chunks {
                let chunk_path = root.data_dir().join(format!("{}.dat", chunk.id));
                if !chunk_path.exists() {
                    return Err(VaultError::MissingChunk(chunk.id.clone()));
                }
                let plain = read_chunk(&chunk_path, chunk_key, &entry.id, chunk)?;
                if hex_lower(&Sha256::digest(&plain)) != chunk.sha256 {
                    return Err(VaultError::AuthenticationFailed);
                }
                file_sha.update(&plain);
                output.write_all(&plain)?;
            }
            output.sync_all()?;
            if let Some(expected) = &entry.sha256 {
                if hex_lower(&file_sha.finalize()) != *expected {
                    return Err(VaultError::AuthenticationFailed);
                }
            }
        }
    }
    Ok(target)
}

fn write_chunk(
    path: &Path,
    chunk_key: &[u8],
    entry_id: &str,
    chunk_id: &str,
    index: u64,
    plain_len: usize,
    plain: &[u8],
) -> VaultResult<ChunkStorage> {
    let nonce = random_vec(NONCE_SIZE);
    let aad = chunk_aad(entry_id, chunk_id, index, plain_len);
    let cipher = Aes256Gcm::new_from_slice(chunk_key).map_err(|_| VaultError::Crypto)?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    if encrypted.len() < GCM_TAG_SIZE {
        return Err(VaultError::Crypto);
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - GCM_TAG_SIZE);
    let encrypted_len = encrypted.len();
    let ecc = build_ecc(&encrypted)?;
    let parity = ecc.parity_bytes.clone();
    let mut file = File::create(path)?;
    file.write_all(&nonce)?;
    file.write_all(ciphertext)?;
    file.write_all(tag)?;
    file.write_all(&parity)?;
    file.sync_all()?;
    Ok(ChunkStorage {
        encrypted_len,
        ecc: ecc.metadata,
    })
}

fn read_chunk(
    path: &Path,
    chunk_key: &[u8],
    entry_id: &str,
    chunk: &ChunkRef,
) -> VaultResult<Zeroizing<Vec<u8>>> {
    let bytes = fs::read(path)?;
    if bytes.len() < NONCE_SIZE + GCM_TAG_SIZE {
        return Err(VaultError::AuthenticationFailed);
    }
    let nonce = &bytes[..NONCE_SIZE];
    let encrypted_len = if chunk.encrypted_len == 0 {
        bytes.len() - NONCE_SIZE
    } else {
        chunk.encrypted_len
    };
    if bytes.len() < NONCE_SIZE + encrypted_len {
        return Err(VaultError::AuthenticationFailed);
    }
    let encrypted = &bytes[NONCE_SIZE..NONCE_SIZE + encrypted_len];
    let parity = &bytes[NONCE_SIZE + encrypted_len..];
    let mut combined = encrypted.to_vec();
    let aad = chunk_aad(entry_id, &chunk.id, chunk.index, chunk.plain_len);
    let cipher = Aes256Gcm::new_from_slice(chunk_key).map_err(|_| VaultError::Crypto)?;
    let plain = match cipher.decrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: &combined,
            aad: &aad,
        },
    ) {
        Ok(plain) => plain,
        Err(_) => {
            let ecc = chunk.ecc.as_ref().ok_or(VaultError::AuthenticationFailed)?;
            combined = recover_encrypted_payload(&combined, parity, ecc)?;
            let plain = cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError::AuthenticationFailed)?;
            let storage = build_ecc(&combined)?;
            let mut repaired = File::create(path)?;
            repaired.write_all(nonce)?;
            repaired.write_all(&combined)?;
            repaired.write_all(&storage.parity_bytes)?;
            repaired.sync_all()?;
            plain
        }
    };
    Ok(Zeroizing::new(plain))
}

struct ChunkStorage {
    encrypted_len: usize,
    ecc: ChunkEcc,
}

struct BuiltEcc {
    metadata: ChunkEcc,
    parity_bytes: Vec<u8>,
}

fn chunk_aad(entry_id: &str, chunk_id: &str, index: u64, plain_len: usize) -> Vec<u8> {
    format!("{CHUNK_AAD_PREFIX}|{entry_id}|{chunk_id}|{index}|{plain_len}").into_bytes()
}

fn build_ecc(encrypted: &[u8]) -> VaultResult<BuiltEcc> {
    let shard_len = encrypted.len().div_ceil(ECC_DATA_SHARDS).max(1);
    let mut shards = vec![vec![0u8; shard_len]; ECC_DATA_SHARDS + ECC_PARITY_SHARDS];
    for (index, byte) in encrypted.iter().enumerate() {
        shards[index / shard_len][index % shard_len] = *byte;
    }
    let rs = ReedSolomon::new(ECC_DATA_SHARDS, ECC_PARITY_SHARDS)
        .map_err(|error| VaultError::RecoveryFailed(error.to_string()))?;
    rs.encode(&mut shards)
        .map_err(|error| VaultError::RecoveryFailed(error.to_string()))?;
    let shard_hashes = shards
        .iter()
        .map(|shard| hex_lower(&Sha256::digest(shard)))
        .collect();
    let parity_bytes = shards[ECC_DATA_SHARDS..].concat();
    Ok(BuiltEcc {
        metadata: ChunkEcc {
            data_shards: ECC_DATA_SHARDS,
            parity_shards: ECC_PARITY_SHARDS,
            shard_len,
            shard_hashes,
        },
        parity_bytes,
    })
}

fn recover_encrypted_payload(
    encrypted: &[u8],
    parity: &[u8],
    ecc: &ChunkEcc,
) -> VaultResult<Vec<u8>> {
    if ecc.data_shards == 0 || ecc.parity_shards == 0 || ecc.shard_len == 0 {
        return Err(VaultError::AuthenticationFailed);
    }
    let expected_parity = ecc.parity_shards * ecc.shard_len;
    if parity.len() < expected_parity {
        return Err(VaultError::AuthenticationFailed);
    }
    let total_shards = ecc.data_shards + ecc.parity_shards;
    if ecc.shard_hashes.len() != total_shards {
        return Err(VaultError::AuthenticationFailed);
    }

    let mut shards = Vec::with_capacity(total_shards);
    for index in 0..ecc.data_shards {
        let start = index * ecc.shard_len;
        let end = (start + ecc.shard_len).min(encrypted.len());
        let mut shard = vec![0u8; ecc.shard_len];
        if start < encrypted.len() {
            shard[..end - start].copy_from_slice(&encrypted[start..end]);
        }
        let hash = hex_lower(&Sha256::digest(&shard));
        shards.push((hash == ecc.shard_hashes[index]).then_some(shard));
    }

    for index in 0..ecc.parity_shards {
        let start = index * ecc.shard_len;
        let end = start + ecc.shard_len;
        let mut shard = vec![0u8; ecc.shard_len];
        shard.copy_from_slice(&parity[start..end]);
        let hash = hex_lower(&Sha256::digest(&shard));
        shards.push((hash == ecc.shard_hashes[ecc.data_shards + index]).then_some(shard));
    }

    let rs = ReedSolomon::new(ecc.data_shards, ecc.parity_shards)
        .map_err(|error| VaultError::RecoveryFailed(error.to_string()))?;
    rs.reconstruct(&mut shards)
        .map_err(|error| VaultError::RecoveryFailed(error.to_string()))?;

    let mut recovered = Vec::with_capacity(encrypted.len());
    for shard in shards.into_iter().take(ecc.data_shards) {
        let shard = shard.ok_or_else(|| VaultError::RecoveryFailed("missing shard".to_string()))?;
        recovered.extend_from_slice(&shard);
    }
    recovered.truncate(encrypted.len());
    Ok(recovered)
}

fn prepare_canaries(lock_root: &Path) -> VaultResult<()> {
    for name in CANARY_NAMES {
        let path = lock_root.join(name);
        if !path.exists() {
            fs::write(&path, CANARY_CONTENT)?;
        }
    }
    Ok(())
}

fn check_canaries(lock_root: &Path) -> VaultResult<()> {
    for name in CANARY_NAMES {
        let path = lock_root.join(name);
        if !path.exists() || fs::read_to_string(&path).unwrap_or_default() != CANARY_CONTENT {
            return Err(VaultError::RecoveryFailed(format!(
                "보호 감시 파일 변조 감지: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn hide_path_best_effort(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        FILE_ATTRIBUTE_SYSTEM,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let _ = SetFileAttributesW(
            wide.as_ptr(),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        );
    }
}

#[cfg(not(windows))]
fn hide_path_best_effort(_path: &Path) {}

fn random_vec(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn vault_round_trip_flattens_chunks_and_restores_tree() {
        let temp = tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output");
        fs::create_dir_all(input.join("nested")).unwrap();
        fs::write(input.join("note.txt"), b"secret text").unwrap();
        fs::write(
            input.join("nested").join("large.bin"),
            vec![7u8; CHUNK_SIZE + 77],
        )
        .unwrap();

        let root = VaultRoot::new(temp.path().join("vault"));
        root.create("Correct Horse Battery Staple 2026!").unwrap();
        let (mut session, report) = root.unlock("Correct Horse Battery Staple 2026!").unwrap();
        assert!(report.missing_chunks.is_empty());

        session.import_path(&input, false).unwrap();
        let dat_files: Vec<_> = fs::read_dir(root.data_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!(dat_files
            .iter()
            .all(|path| path.extension().unwrap() == "dat"));
        assert!(dat_files.len() >= 3);

        let folder = session
            .list_entries()
            .into_iter()
            .find(|entry| entry.parent_id.is_none() && entry.kind == EntryKind::Directory)
            .unwrap();
        let restored = session.restore_entry(&folder.id, &output).unwrap();
        assert_eq!(fs::read(restored.join("note.txt")).unwrap(), b"secret text");
        assert_eq!(
            fs::read(restored.join("nested").join("large.bin")).unwrap(),
            vec![7u8; CHUNK_SIZE + 77]
        );
    }

    #[test]
    fn tampered_db_fails_authentication() {
        let temp = tempdir().unwrap();
        let root = VaultRoot::new(temp.path().join("vault"));
        root.create("Correct Horse Battery Staple 2026!").unwrap();
        let db_path = root.db_path();
        let mut db = fs::read(&db_path).unwrap();
        let last = db.len() - 5;
        db[last] ^= 0x01;
        fs::write(&db_path, db).unwrap();
        let result = root.unlock("Correct Horse Battery Staple 2026!");
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn orphan_chunk_is_quarantined() {
        let temp = tempdir().unwrap();
        let root = VaultRoot::new(temp.path().join("vault"));
        root.create("Correct Horse Battery Staple 2026!").unwrap();
        fs::write(root.data_dir().join("orphan.dat"), b"noise").unwrap();
        let (_session, report) = root.unlock("Correct Horse Battery Staple 2026!").unwrap();
        assert_eq!(report.orphan_chunks, vec!["orphan.dat"]);
        assert!(!root.data_dir().join("orphan.dat").exists());
    }

    #[test]
    fn folder_lock_hides_originals_and_unlock_restores_in_place() {
        let temp = tempdir().unwrap();
        let folder = temp.path().join("visible-folder");
        fs::create_dir_all(folder.join("nested")).unwrap();
        fs::write(folder.join("note.txt"), b"folder secret").unwrap();
        fs::write(
            folder.join("nested").join("deep.txt"),
            b"deep folder secret",
        )
        .unwrap();

        let root = VaultRoot::new(temp.path().join("vault"));
        root.create("Correct Horse Battery Staple 2026!").unwrap();
        let (mut session, _) = root.unlock("Correct Horse Battery Staple 2026!").unwrap();
        let locked = session.lock_folder_in_place(&folder, false).unwrap();
        assert!(locked >= 3);
        assert!(folder.exists());
        assert!(folder.join(LOCK_DIR_NAME).join("folder.db").exists());
        assert!(!folder.join("note.txt").exists());
        assert!(!folder.join("nested").exists());
        let marker_path = normalized_path_string(&folder);
        assert!(session
            .list_entries()
            .iter()
            .any(|entry| entry.locked_folder_path.as_deref() == Some(marker_path.as_str())));

        let unlocked = session.unlock_folder_in_place(&folder).unwrap();
        assert_eq!(locked, unlocked);
        assert_eq!(fs::read(folder.join("note.txt")).unwrap(), b"folder secret");
        assert_eq!(
            fs::read(folder.join("nested").join("deep.txt")).unwrap(),
            b"deep folder secret"
        );
        assert!(!folder.join(LOCK_DIR_NAME).exists());
        assert!(session
            .list_entries()
            .iter()
            .all(|entry| entry.locked_folder_path.is_none()));
    }

    #[test]
    fn ecc_repairs_corrupted_ciphertext_shard() {
        let temp = tempdir().unwrap();
        let input = temp.path().join("input.bin");
        let output = temp.path().join("output");
        fs::create_dir_all(&output).unwrap();
        fs::write(&input, vec![42u8; CHUNK_SIZE]).unwrap();

        let root = VaultRoot::new(temp.path().join("vault"));
        root.create("Correct Horse Battery Staple 2026!").unwrap();
        let (mut session, _) = root.unlock("Correct Horse Battery Staple 2026!").unwrap();
        let entries = session.import_path(&input, false).unwrap();
        let entry = entries
            .into_iter()
            .find(|entry| entry.kind == EntryKind::File)
            .unwrap();
        let chunk = &entry.chunks[0];
        let chunk_path = root.data_dir().join(format!("{}.dat", chunk.id));
        let mut bytes = fs::read(&chunk_path).unwrap();
        bytes[NONCE_SIZE + 3] ^= 0xA5;
        fs::write(&chunk_path, bytes).unwrap();

        session.restore_entry(&entry.id, &output).unwrap();
        assert_eq!(
            fs::read(output.join("input.bin")).unwrap(),
            vec![42u8; CHUNK_SIZE]
        );
    }

    #[test]
    fn honeytoken_tamper_blocks_unlock() {
        let temp = tempdir().unwrap();
        let folder = temp.path().join("visible-folder");
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("note.txt"), b"folder secret").unwrap();

        let root = VaultRoot::new(temp.path().join("vault"));
        root.create("Correct Horse Battery Staple 2026!").unwrap();
        let (mut session, _) = root.unlock("Correct Horse Battery Staple 2026!").unwrap();
        session.lock_folder_in_place(&folder, false).unwrap();
        fs::write(
            folder.join(LOCK_DIR_NAME).join("contacts.xlsx"),
            b"tampered",
        )
        .unwrap();

        let result = session.unlock_folder_in_place(&folder);
        assert!(matches!(result, Err(VaultError::RecoveryFailed(_))));
        assert!(!folder.join("note.txt").exists());
    }
}
