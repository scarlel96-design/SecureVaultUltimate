use serde::Serialize;
use tauri_plugin_updater::UpdaterExt;

#[allow(dead_code)]
mod build_config {
    include!(concat!(env!("OUT_DIR"), "/secure_vault_build_config.rs"));
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub available: bool,
    pub current_version: String,
    pub version: Option<String>,
    pub date: Option<String>,
    pub body: Option<String>,
    pub detail: String,
}

pub fn updater_public_key() -> Option<&'static str> {
    let key = build_config::UPDATER_PUBLIC_KEY.trim();
    (!key.is_empty()).then_some(key)
}

pub async fn check(app: tauri::AppHandle) -> Result<UpdateStatus, String> {
    let updater = configured_updater(&app)?;
    match updater.check().await.map_err(|error| error.to_string())? {
        Some(update) => Ok(UpdateStatus {
            available: true,
            current_version: update.current_version.clone(),
            version: Some(update.version.clone()),
            date: update.date.map(|date| date.to_string()),
            body: update.body.clone(),
            detail: format!("새로운 업데이트가 존재합니다: {}", update.version),
        }),
        None => Ok(UpdateStatus {
            available: false,
            current_version: app.package_info().version.to_string(),
            version: None,
            date: None,
            body: None,
            detail: "현재 버전이 최신입니다.".to_string(),
        }),
    }
}

pub async fn install(app: tauri::AppHandle) -> Result<(), String> {
    let updater = configured_updater(&app)?;
    let update = updater
        .check()
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "설치할 업데이트가 없습니다.".to_string())?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| error.to_string())?;
    app.restart();
}

fn configured_updater(app: &tauri::AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    let builder = app.updater_builder();
    let builder = if let Some(key) = updater_public_key() {
        builder.pubkey(key)
    } else {
        builder
    };
    builder.build().map_err(|error| error.to_string())
}
