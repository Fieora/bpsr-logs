// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod live;
mod packets;

use std::path::PathBuf;
use std::time::SystemTime;
use log::{error, info};
use tauri::{Builder, Manager};
use tauri::ipc::Origin::Local;
use std::time::{UNIX_EPOCH};

#[tokio::main]
async fn main() {
    info!("testtesttest");
    tauri::Builder::default()
        .setup(|app| {
            info!("starting app v{}", app.package_info().version);

            let app = app.app_handle().clone();
            tokio::task::spawn_blocking(move || {
                // only start listening when there's no update, otherwise unable to remove driver
                info!("listening...");
                live::start(app).map_err(|e| {
                    error!("unexpected error occurred in parser: {e}");
                })
            });
            Ok(())
        })
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}))
        .plugin(tauri_plugin_log::Builder::new()
            .target(tauri_plugin_log::Target::new(
                tauri_plugin_log::TargetKind::Folder {
                    path: PathBuf::from(std::env::current_dir().unwrap().join(".logs")),
                    file_name: Some(format!("{:?}", chrono::Utc::now().timestamp_nanos_opt().expect("time should move forward"))),
                },
            ))
            .build())
        .run(tauri::generate_context!())
        .unwrap();
}
