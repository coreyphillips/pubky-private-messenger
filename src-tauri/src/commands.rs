use crate::messaging::{AppState, ChatMessage, PrivateMessageHandler, UserProfile};
use anyhow::Result;
use base64;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as ChaChaOsRng},
    ChaCha20Poly1305, Nonce
};
use hkdf::Hkdf;
use pkarr::{Keypair, PublicKey};
use pubky_common::recovery_file;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tauri::{command, State};
use tokio::task;

// Session-related structures
#[derive(Serialize, Deserialize)]
pub struct SignInResult {
    pub profile: UserProfile,
    pub encrypted_keypair: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedSession {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    salt: Vec<u8>,
}

// Secure key derivation using HKDF
fn derive_encryption_key(salt: &[u8]) -> Result<[u8; 32], String> {
    // Collect device-specific entropy
    let mut device_info = Vec::new();

    // Add hostname if available
    if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        device_info.extend_from_slice(hostname.as_bytes());
    }

    // Add username if available (additional entropy)
    if let Ok(username) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
        device_info.extend_from_slice(username.as_bytes());
    }

    // Add application identifier
    device_info.extend_from_slice(b"pubky_private_messenger_v1");

    // Use HKDF to derive a proper encryption key
    let hk = Hkdf::<Sha256>::new(Some(salt), &device_info);
    let mut key = [0u8; 32];
    hk.expand(b"session_encryption_key", &mut key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    Ok(key)
}

fn encrypt_keypair(keypair: &Keypair) -> Result<String, String> {
    // Generate random salt for key derivation
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // Derive encryption key using HKDF
    let key = derive_encryption_key(&salt)?;

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Generate random nonce
    let nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);

    // Serialize the keypair secret
    let keypair_bytes = keypair.secret_key();

    // Encrypt with authenticated encryption
    let ciphertext = cipher.encrypt(&nonce, keypair_bytes.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Package everything together
    let encrypted_session = EncryptedSession {
        ciphertext,
        nonce: nonce.to_vec(),
        salt: salt.to_vec(),
    };

    // Serialize and encode
    let serialized = serde_json::to_vec(&encrypted_session)
        .map_err(|e| format!("Serialization failed: {}", e))?;

    Ok(base64::encode(serialized))
}

fn decrypt_keypair(encrypted_data: &str) -> Result<Keypair, String> {
    // Decode and deserialize
    let serialized = base64::decode(encrypted_data)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let encrypted_session: EncryptedSession = serde_json::from_slice(&serialized)
        .map_err(|e| format!("Deserialization failed: {}", e))?;

    // Derive the same encryption key using stored salt
    let key = derive_encryption_key(&encrypted_session.salt)?;

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Reconstruct nonce
    if encrypted_session.nonce.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(&encrypted_session.nonce);
    let nonce = Nonce::from(nonce_array);

    // Decrypt and authenticate
    let decrypted = cipher.decrypt(&nonce, encrypted_session.ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed (invalid data or key): {}", e))?;

    // Ensure we have exactly 32 bytes for the secret key
    if decrypted.len() != 32 {
        return Err(format!("Invalid decrypted data length: expected 32, got {}", decrypted.len()));
    }

    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&decrypted);

    // Create keypair from decrypted secret
    Ok(Keypair::from_secret_key(&secret_key))
}

#[command]
pub async fn init_client(state: State<'_, AppState>) -> Result<String, String> {
    // Initialize the shared client in AppState
    state.get_or_create_client().await?;
    Ok("Client initialized successfully".to_string())
}

#[command]
pub async fn sign_in_with_recovery(
    recovery_file_b64: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<SignInResult, String> {
    let result = task::spawn_blocking(move || -> Result<Keypair, String> {
        // Decode and decrypt recovery file
        let recovery_file_bytes = base64::decode(&recovery_file_b64)
            .map_err(|e| format!("Failed to decode recovery file: {}", e))?;

        let keypair = recovery_file::decrypt_recovery_file(&recovery_file_bytes, &passphrase)
            .map_err(|_| "Failed to decrypt recovery file - check your passphrase".to_string())?;

        Ok(keypair)
    }).await.map_err(|e| format!("Task failed: {}", e))??;

// Store keypair in state first
    let mut keypair_guard = state.keypair.lock().await;
    *keypair_guard = Some(result.clone());
    drop(keypair_guard);

    // Create handler and sign in to get profile name
    let handler = state.create_handler_and_sign_in().await?
        .ok_or("Failed to create handler")?;

    let profile_name = task::spawn_blocking(move || -> Result<Option<String>, String> {
        let rt = tokio::runtime::Handle::current();

        // Get own profile name
        let name = rt.block_on(handler.get_own_profile())
            .map_err(|e| format!("Failed to get profile: {}", e))?;

        Ok(name)
    }).await.map_err(|e| format!("Task failed: {}", e))??;

    // Store user name in state
    let mut name_guard = state.user_name.lock().await;
    *name_guard = profile_name.clone();

    // Encrypt keypair for storage using secure AEAD
    let encrypted_keypair = encrypt_keypair(&result)?;

    Ok(SignInResult {
        profile: UserProfile {
            public_key: result.public_key().to_string(),
            signed_in: true,
            name: profile_name,
        },
        encrypted_keypair,
    })
}

#[command]
pub async fn restore_session(
    encrypted_keypair: String,
    state: State<'_, AppState>,
) -> Result<UserProfile, String> {
    // Decrypt the keypair using secure AEAD
    let keypair = decrypt_keypair(&encrypted_keypair)?;

    // Store keypair in state first
    let mut keypair_guard = state.keypair.lock().await;
    *keypair_guard = Some(keypair.clone());
    drop(keypair_guard);

    // Create handler and sign in to get profile name
    let handler = state.create_handler_and_sign_in().await?
        .ok_or("Failed to create handler")?;

    let profile_name = task::spawn_blocking(move || -> Result<Option<String>, String> {
        let rt = tokio::runtime::Handle::current();

        // Get own profile name
        let name = rt.block_on(handler.get_own_profile())
            .map_err(|e| format!("Failed to get profile: {}", e))?;

        Ok(name)
    }).await.map_err(|e| format!("Task failed: {}", e))??;

    // Store user name in state
    let mut name_guard = state.user_name.lock().await;
    *name_guard = profile_name.clone();

    Ok(UserProfile {
        public_key: keypair.public_key().to_string(),
        signed_in: true,
        name: profile_name,
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

    // Get handler (without signing in since we should already be authenticated)
    let handler = state.create_handler().await?
        .ok_or("Not signed in")?;

    let recipient = PublicKey::try_from(recipient_pubkey.as_str())
        .map_err(|e| format!("Invalid recipient public key: {}", e))?;

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

    let handler = state.create_handler().await?
        .ok_or("Not signed in")?;
    
    let messages = task::spawn_blocking(move || -> Result<Vec<(crate::messaging::PrivateMessage, String, String, bool)>, String> {
        let other_pk = PublicKey::try_from(other_pubkey.as_str())
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let rt = tokio::runtime::Handle::current();

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
    let name_guard = state.user_name.lock().await;

    if let Some(keypair) = keypair_guard.as_ref() {
        Ok(Some(UserProfile {
            public_key: keypair.public_key().to_string(),
            signed_in: true,
            name: name_guard.clone(),
        }))
    } else {
        Ok(None)
    }
}

#[command]
pub async fn sign_out(state: State<'_, AppState>) -> Result<String, String> {
    let mut keypair_guard = state.keypair.lock().await;
    *keypair_guard = None;

    let mut name_guard = state.user_name.lock().await;
    *name_guard = None;

    let mut signed_in_guard = state.is_signed_in.lock().await;
    *signed_in_guard = false;

    Ok("Signed out successfully".to_string())
}

#[command]
pub async fn scan_followed_users(state: State<'_, AppState>) -> Result<Vec<crate::messaging::FollowedUser>, String> {
    let keypair = {
        let keypair_guard = state.keypair.lock().await;
        keypair_guard.clone().ok_or("Not signed in")?
    };

    println!("🔍 Scanning for followed users...");

    let handler = state.create_handler().await?
        .ok_or("Not signed in")?;
    
    let users = task::spawn_blocking(move || -> Result<Vec<crate::messaging::FollowedUser>, String> {
        let rt = tokio::runtime::Handle::current();

        // Get followed users with profiles
        let users = rt.block_on(handler.get_followed_users_with_profiles())
            .map_err(|e| format!("Failed to get followed users: {}", e))?;

        Ok(users)
    }).await.map_err(|e| format!("Task failed: {}", e))??;

    println!("✅ Found {} followed users", users.len());
    Ok(users)
}