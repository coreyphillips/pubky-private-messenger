pub mod commands;
pub mod messaging;

pub use commands::*;
pub use messaging::*;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Create the app state
    let app_state = AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            init_client,
            sign_in_with_recovery,
            restore_session,
            send_message,
            get_new_messages,
            get_conversation,
            get_user_profile,
            sign_out,
            scan_followed_users
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}