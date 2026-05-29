#[cfg(any(not(debug_assertions), test))]
use rand::rngs::OsRng;
#[cfg(any(not(debug_assertions), test))]
use rand::RngCore;
use std::fs;
#[cfg(any(not(debug_assertions), test))]
use std::fs::OpenOptions;
#[cfg(any(not(debug_assertions), test))]
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
#[cfg(any(not(debug_assertions), test))]
use std::path::PathBuf;
use thiserror::Error;
#[cfg(any(not(debug_assertions), test))]
use walkdir::WalkDir;
#[cfg(any(not(debug_assertions), test))]
use zeroize::Zeroizing;

#[cfg(any(not(debug_assertions), test))]
const WIPE_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum SecureFsError {
    #[error("파일 시스템 IO 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("디렉터리 순회 오류: {0}")]
    WalkDir(#[from] walkdir::Error),
}

pub type SecureFsResult<T> = Result<T, SecureFsError>;

#[allow(dead_code)]
pub fn secure_wipe_path(path: &Path) -> SecureFsResult<()> {
    #[cfg(all(debug_assertions, not(test)))]
    {
        println!(
            "안전 시뮬레이션 모드 구동 중: secure wipe path would target {}",
            path.display()
        );
        Ok(())
    }

    #[cfg(any(not(debug_assertions), test))]
    {
        if path.is_file() {
            secure_wipe_file(path)?;
            return Ok(());
        }

        if !path.is_dir() {
            return Ok(());
        }

        let mut files = Vec::new();
        let mut dirs = Vec::new();
        for item in WalkDir::new(path).contents_first(true) {
            let item = item?;
            if item.file_type().is_file() {
                files.push(item.path().to_path_buf());
            } else if item.file_type().is_dir() {
                dirs.push(item.path().to_path_buf());
            }
        }

        for file in files {
            secure_wipe_file(&file)?;
        }
        for dir in dirs {
            remove_dir_if_exists(&dir)?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub fn secure_wipe_file(path: &Path) -> SecureFsResult<()> {
    #[cfg(all(debug_assertions, not(test)))]
    {
        println!(
            "안전 시뮬레이션 모드 구동 중: 2-pass overwrite would target {}",
            path.display()
        );
        Ok(())
    }

    #[cfg(any(not(debug_assertions), test))]
    {
        let len = fs::metadata(path)?.len();
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        overwrite_with_zeroes(&mut file, len)?;
        overwrite_with_random(&mut file, len)?;
        file.set_len(0)?;
        file.sync_all()?;
        drop(file);
        fs::remove_file(path)?;
        Ok(())
    }
}

pub fn delete_path_plain(path: &Path) -> SecureFsResult<()> {
    if path.is_file() {
        fs::remove_file(path)?;
    } else if path.is_dir() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[cfg(any(not(debug_assertions), test))]
fn overwrite_with_zeroes(file: &mut std::fs::File, len: u64) -> SecureFsResult<()> {
    file.seek(SeekFrom::Start(0))?;
    let buffer = Zeroizing::new(vec![0u8; WIPE_BUFFER_SIZE]);
    write_pass(file, len, &buffer)?;
    file.sync_data()?;
    Ok(())
}

#[cfg(any(not(debug_assertions), test))]
fn overwrite_with_random(file: &mut std::fs::File, len: u64) -> SecureFsResult<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = len;
    let mut buffer = Zeroizing::new(vec![0u8; WIPE_BUFFER_SIZE]);
    while remaining > 0 {
        OsRng.fill_bytes(&mut buffer);
        let to_write = remaining.min(buffer.len() as u64) as usize;
        file.write_all(&buffer[..to_write])?;
        remaining -= to_write as u64;
    }
    file.sync_data()?;
    Ok(())
}

#[cfg(any(not(debug_assertions), test))]
fn write_pass(file: &mut std::fs::File, len: u64, buffer: &[u8]) -> SecureFsResult<()> {
    let mut remaining = len;
    while remaining > 0 {
        let to_write = remaining.min(buffer.len() as u64) as usize;
        file.write_all(&buffer[..to_write])?;
        remaining -= to_write as u64;
    }
    Ok(())
}

#[cfg(any(not(debug_assertions), test))]
fn remove_dir_if_exists(path: &PathBuf) -> SecureFsResult<()> {
    if path.exists() {
        fs::remove_dir(path)?;
    }
    Ok(())
}
