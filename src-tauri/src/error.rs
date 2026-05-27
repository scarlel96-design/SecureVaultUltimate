use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("금고가 이미 존재합니다.")]
    AlreadyExists,
    #[error("금고가 아직 생성되지 않았습니다.")]
    NotInitialized,
    #[error("마스터 비밀번호가 틀렸거나 vault.db가 변조되었습니다.")]
    AuthenticationFailed,
    #[error("지원하지 않는 금고 형식입니다.")]
    UnsupportedFormat,
    #[error("항목을 찾을 수 없습니다.")]
    EntryNotFound,
    #[error("데이터 청크가 누락되었습니다: {0}")]
    MissingChunk(String),
    #[error("입력 경로를 찾을 수 없습니다: {0}")]
    MissingInput(String),
    #[error("이미 잠긴 폴더입니다: {0}")]
    FolderAlreadyLocked(String),
    #[error("잠긴 폴더가 아닙니다: {0}")]
    FolderNotLocked(String),
    #[error("ECC 복구에 실패했습니다: {0}")]
    RecoveryFailed(String),
    #[error("시큐어 파일 시스템 오류: {0}")]
    SecureFs(#[from] crate::core::secure_fs::SecureFsError),
    #[error("설정 저장소 오류: {0}")]
    Config(#[from] crate::core::config::ConfigError),
    #[error("스마트 방벽 오류: {0}")]
    Firewall(#[from] crate::core::firewall::FirewallError),
    #[error("IO 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON 오류: {0}")]
    Json(#[from] serde_json::Error),
    #[error("암호화 오류")]
    Crypto,
    #[error("Argon2 오류: {0}")]
    Argon2(String),
    #[error("{file}:{line} {context}: {source}")]
    Context {
        file: &'static str,
        line: u32,
        context: String,
        #[source]
        source: Box<VaultError>,
    },
}

pub type VaultResult<T> = Result<T, VaultError>;

impl VaultError {
    pub fn with_context(self, file: &'static str, line: u32, context: impl Into<String>) -> Self {
        Self::Context {
            file,
            line,
            context: context.into(),
            source: Box::new(self),
        }
    }
}

#[macro_export]
macro_rules! vault_context {
    ($expr:expr, $context:expr) => {
        $expr.map_err(|error| {
            $crate::error::VaultError::with_context(error, file!(), line!(), $context)
        })
    };
}
