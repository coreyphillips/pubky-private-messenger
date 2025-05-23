use crate::messaging::{AppState, ChatMessage, Contact, UserProfile, PrivateMessageHandler};
use anyhow::Result;
use pkarr::{Keypair, PublicKey};
use pubky_common::recovery_file;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{command, State};
use tokio::task;

#[command]
pub async fn init_client() -> Result<String, String> {
    task::spawn_blocking(|| -> Result<String, String> {
        match pubky::Client::builder().build() {
            Ok(_) => Ok("Client initialized successfully".to_string()),
            Err(e) => Err(format!("Failed to initialize client: {}", e)),
        }
    }).await.map_err(|e| format!("Task failed: {}", e))?
}

#[command]
pub async fn sign_in_with_recovery(
    recovery_file_b64: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<UserProfile, String> {
    let result = task::spawn_blocking(move || -> Result<Keypair, String> {
        // Decode and decrypt recovery file
        let recovery_file_bytes = base64::decode(&recovery_file_b64)
            .map_err(|e| format!("Failed to decode recovery file: {}", e))?;

        let keypair = recovery_file::decrypt_recovery_file(&recovery_file_bytes, &passphrase)
            .map_err(|_| "Failed to decrypt recovery file - check your passphrase".to_string())?;

        Ok(keypair)
    }).await.map_err(|e| format!("Task failed: {}", e))??;

    // Test sign in
    let keypair_clone = result.clone();
    let _sign_in_result = task::spawn_blocking(move || -> Result<(), String> {
        let client = pubky::Client::builder().build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        let handler = PrivateMessageHandler::new(client, keypair_clone);

        // Use a blocking runtime for the async sign_in call
        let rt = tokio::runtime::Handle::current();
        rt.block_on(handler.sign_in())
            .map_err(|e| format!("Failed to sign in: {}", e))?;

        Ok(())
    }).await.map_err(|e| format!("Task failed: {}", e))??;

    // Store keypair in state
    let mut keypair_guard = state.keypair.lock().await;
    *keypair_guard = Some(result.clone());

    Ok(UserProfile {
        public_key: result.public_key().to_string(),
        signed_in: true,
    })
}

#[command]
pub async fn send_message(
    recipient_pubkey: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let keypair = {
        let keypair_guard = state.keypair.lock().await;
        keypair_guard.clone().ok_or("Not signed in")?
    };

    println!("📤 send_message command called");
    println!("   Sender: {}", keypair.public_key().to_string().chars().take(8).collect::<String>());
    println!("   Recipient: {}", recipient_pubkey.chars().take(8).collect::<String>());

    // Create client and handler
    let client = pubky::Client::builder().build()
        .map_err(|e| format!("Failed to create client: {}", e))?;

    let handler = PrivateMessageHandler::new(client, keypair);

    let recipient = PublicKey::try_from(recipient_pubkey.as_str())
        .map_err(|e| format!("Invalid recipient public key: {}", e))?;

    // Sign in first with detailed logging
    println!("🔐 Attempting to sign in...");
    match handler.sign_in().await {
        Ok(session) => {
            println!("✅ Sign in successful!");
            println!("   Session details: {:?}", session);
        }
        Err(e) => {
            println!("❌ Sign in failed: {}", e);
            return Err(format!("Failed to sign in: {}", e));
        }
    }

    // Add a small delay to ensure session is established
    println!("⏳ Waiting for session to stabilize...");
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    // Send the message
    println!("📤 Attempting to send message...");
    handler.send_message(&recipient, &content)
        .await
        .map_err(|e| format!("Failed to send message: {}", e))?;

    Ok("Message sent successfully".to_string())
}

#[command]
pub async fn get_new_messages(
    state: State<'_, AppState>,
) -> Result<Vec<ChatMessage>, String> {
    let _keypair = {
        let keypair_guard = state.keypair.lock().await;
        keypair_guard.clone().ok_or("Not signed in")?
    };

    // Temporarily return empty array since notifications are disabled
    // Individual conversations still work via get_conversation
    println!("📭 New message polling disabled (notifications system disabled)");
    Ok(vec![])
}

#[command]
pub async fn get_conversation(
    other_pubkey: String,
    state: State<'_, AppState>,
) -> Result<Vec<ChatMessage>, String> {
    let keypair = {
        let keypair_guard = state.keypair.lock().await;
        keypair_guard.clone().ok_or("Not signed in")?
    };

    let current_user = keypair.public_key().to_string();

    let messages = task::spawn_blocking(move || -> Result<Vec<(crate::messaging::PrivateMessage, String, String, bool)>, String> {
        let client = pubky::Client::builder().build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        let handler = PrivateMessageHandler::new(client, keypair);

        let other_pk = PublicKey::try_from(other_pubkey.as_str())
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let rt = tokio::runtime::Handle::current();

        // Sign in first
        rt.block_on(handler.sign_in())
            .map_err(|e| format!("Failed to sign in: {}", e))?;

        // Get conversation with decrypted senders
        let raw_messages = rt.block_on(handler.get_messages(&other_pk))
            .map_err(|e| format!("Failed to get conversation: {}", e))?;

        // Transform to include decrypted sender info
        let mut processed_messages = Vec::new();
        for (msg, content, verified) in raw_messages {
            if let Ok(sender) = msg.decrypt_sender(&handler.keypair, &other_pk) {
                processed_messages.push((msg, content, sender, verified));
            }
        }

        Ok(processed_messages)
    }).await.map_err(|e| format!("Task failed: {}", e))??;

    let chat_messages = messages.into_iter().map(|(msg, content, sender, verified)| {
        ChatMessage {
            sender: sender.clone(),  // Now using decrypted sender
            content,
            timestamp: msg.timestamp,
            verified,
            is_own_message: sender == current_user,
        }
    }).collect();

    Ok(chat_messages)
}

#[command]
pub async fn get_user_profile(
    state: State<'_, AppState>,
) -> Result<Option<UserProfile>, String> {
    let keypair_guard = state.keypair.lock().await;

    if let Some(keypair) = keypair_guard.as_ref() {
        Ok(Some(UserProfile {
            public_key: keypair.public_key().to_string(),
            signed_in: true,
        }))
    } else {
        Ok(None)
    }
}

#[command]
pub async fn sign_out(state: State<'_, AppState>) -> Result<String, String> {
    let mut keypair_guard = state.keypair.lock().await;
    *keypair_guard = None;
    Ok("Signed out successfully".to_string())
}