use std::sync::Arc;
use anyhow::{anyhow, Result};
use pkarr::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use pubky_common::crypto::{decrypt, encrypt};
use blake3::Hasher;
use sha2::{Digest, Sha512};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use pubky_common::recovery_file;
use pubky_common::session::Session;
use base64;
use hex;
use tokio::sync::Mutex;

// Function for proper Edwards to Montgomery curve conversion
fn ed25519_public_to_x25519(ed_pub: &[u8; 32]) -> Option<X25519PublicKey> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards_point = compressed.decompress()?;
    Some(X25519PublicKey::from(edwards_point.to_montgomery().to_bytes()))
}

// Function to properly convert Ed25519 secret key to X25519
fn ed25519_secret_to_x25519(ed_secret: &[u8; 32]) -> StaticSecret {
    let mut hasher = Sha512::new();
    hasher.update(ed_secret);
    let hash = hasher.finalize();

    let mut x25519_secret_bytes = [0u8; 32];
    x25519_secret_bytes.copy_from_slice(&hash[0..32]);

    // Apply clamping as per RFC 7748
    x25519_secret_bytes[0] &= 248;
    x25519_secret_bytes[31] &= 127;
    x25519_secret_bytes[31] |= 64;

    StaticSecret::from(x25519_secret_bytes)
}

fn generate_shared_secret(keypair: &Keypair, other_pubkey: &PublicKey) -> Result<String> {
    // Convert Ed25519 secret to X25519 using proper conversion
    let ed25519_secret = keypair.secret_key();
    let x25519_secret = ed25519_secret_to_x25519(&ed25519_secret);

    // Convert Ed25519 public to X25519 using proper curve conversion
    let other_pubkey_bytes = other_pubkey.as_bytes();
    if other_pubkey_bytes.len() != 32 {
        return Err(anyhow!("Invalid public key length"));
    }

    let mut other_ed_bytes = [0u8; 32];
    other_ed_bytes.copy_from_slice(other_pubkey_bytes);

    let other_x25519 = ed25519_public_to_x25519(&other_ed_bytes)
        .ok_or_else(|| anyhow!("Failed to convert pubkey to X25519"))?;

    let shared = x25519_secret.diffie_hellman(&other_x25519);
    Ok(hex::encode(shared.as_bytes()))
}

// Message structure with metadata and encrypted content
#[derive(Serialize, Deserialize)]
pub(crate) struct PrivateMessage {
    pub(crate) timestamp: u64,
    encrypted_sender: Vec<u8>,  // Changed from plaintext sender
    encrypted_content: Vec<u8>,
    signature_bytes: Vec<u8>,
}

impl PrivateMessage {
    fn new(sender_keypair: &Keypair, recipient_pk: &PublicKey, content: &str) -> Result<Self> {
        let content_bytes = content.as_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create message digest for signing (same as before)
        let mut hasher = Hasher::new();
        hasher.update(content_bytes);
        hasher.update(sender_keypair.public_key().as_bytes());
        hasher.update(&timestamp.to_be_bytes());
        let message_digest = hasher.finalize();

        // Sign the message
        let signature = sender_keypair.sign(message_digest.as_bytes());
        let signature_bytes = signature.to_bytes().to_vec();

        // Generate shared secret and encryption key
        let shared_secret = generate_shared_secret(sender_keypair, recipient_pk)?;
        let shared_secret_bytes = hex::decode(&shared_secret)
            .map_err(|e| anyhow!("Failed to decode shared secret: {}", e))?;

        if shared_secret_bytes.len() != 32 {
            return Err(anyhow!("Shared secret must be 32 bytes, got {}", shared_secret_bytes.len()));
        }

        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&shared_secret_bytes);

        // Encrypt content (same as before)
        let encrypted_content = encrypt(content_bytes, &encryption_key);

        // NEW: Encrypt sender public key
        let sender_string = sender_keypair.public_key().to_string();
        let sender_bytes = sender_string.as_bytes();
        let encrypted_sender = encrypt(sender_bytes, &encryption_key);

        Ok(Self {
            timestamp,
            encrypted_sender,    // Now encrypted!
            encrypted_content,
            signature_bytes,
        })
    }

    fn decrypt_content(&self, receiver_keypair: &Keypair, other_participant: &PublicKey) -> Result<String> {
        // Same as before - decrypt content
        let shared_secret = generate_shared_secret(receiver_keypair, other_participant)?;
        let shared_secret_bytes = hex::decode(&shared_secret)
            .map_err(|e| anyhow!("Failed to decode shared secret: {}", e))?;

        if shared_secret_bytes.len() != 32 {
            return Err(anyhow!("Shared secret must be 32 bytes, got {}", shared_secret_bytes.len()));
        }

        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&shared_secret_bytes);

        let decrypted = decrypt(&self.encrypted_content, &encryption_key)?;
        Ok(String::from_utf8(decrypted)?)
    }

    // NEW: Method to decrypt sender
    pub(crate) fn decrypt_sender(&self, receiver_keypair: &Keypair, other_participant: &PublicKey) -> Result<String> {
        let shared_secret = generate_shared_secret(receiver_keypair, other_participant)?;
        let shared_secret_bytes = hex::decode(&shared_secret)
            .map_err(|e| anyhow!("Failed to decode shared secret: {}", e))?;

        if shared_secret_bytes.len() != 32 {
            return Err(anyhow!("Shared secret must be 32 bytes, got {}", shared_secret_bytes.len()));
        }

        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&shared_secret_bytes);

        let decrypted = decrypt(&self.encrypted_sender, &encryption_key)?;
        Ok(String::from_utf8(decrypted)?)
    }

    fn verify_signature(&self, decrypted_content: &str, decrypted_sender: &str) -> Result<bool> {
        let sender_pk = PublicKey::try_from(decrypted_sender)?;

        // Recreate the message digest (same as before)
        let mut hasher = Hasher::new();
        hasher.update(decrypted_content.as_bytes());
        hasher.update(sender_pk.as_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        let message_digest = hasher.finalize();

        if self.signature_bytes.len() != 64 {
            return Err(anyhow!("Invalid signature length"));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature_bytes);
        let signature = Signature::from_bytes(&sig_bytes);

        match sender_pk.verify(message_digest.as_bytes(), &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Simple notification structure (stores sender publicly for now)
#[derive(Serialize, Deserialize)]
struct PrivateNotification {
    timestamp: u64,
    sender: String, // Store sender publicly for simplicity
    msg_id: String,
}

// Legacy notification structure for backward compatibility
#[derive(Serialize, Deserialize)]
struct LegacyPrivateNotification {
    timestamp: u64,
    encrypted_sender: Vec<u8>,
    msg_id: String,
}

pub(crate) struct PrivateMessageHandler {
    client: pubky::Client,
    pub(crate) keypair: Keypair,
}

impl PrivateMessageHandler {
    pub(crate) fn new(client: pubky::Client, keypair: Keypair) -> Self {
        Self { client, keypair }
    }

    pub(crate) async fn get_all_new_messages_from_contacts_with_timestamp(&self, contacts: &[PublicKey]) -> Result<Vec<(String, String, u64, bool)>> {
        let mut all_messages = Vec::new();

        for contact in contacts {
            let conversation_messages = self.get_messages(contact).await?;
            for (msg, content, verified) in conversation_messages {
                // Decrypt the sender field using the contact as the other participant
                match msg.decrypt_sender(&self.keypair, contact) {
                    Ok(sender) => {
                        all_messages.push((sender, content, msg.timestamp, verified));
                    }
                    Err(e) => {
                        println!("❌ Failed to decrypt sender for message: {}", e);
                        continue;
                    }
                }
            }
        }

        // Sort by timestamp (most recent first)
        all_messages.sort_by(|a, b| b.2.cmp(&a.2));

        Ok(all_messages)
    }

    // Add this debugging version to your PrivateMessageHandler in messaging.rs
    fn private_conversation_path(&self, other_pubkey: &PublicKey) -> Result<String> {
        let shared_secret = generate_shared_secret(&self.keypair, other_pubkey)?;
        let path_id = blake3::hash(shared_secret.as_bytes()).to_hex();
        let path = format!("/pub/private_messages/{}/", path_id);

        println!("🔑 Conversation path details:");
        println!("   Self pubkey:  {}", self.keypair.public_key().to_string().chars().take(8).collect::<String>());
        println!("   Other pubkey: {}", other_pubkey.to_string().chars().take(8).collect::<String>());
        println!("   Shared secret: {}", shared_secret.chars().take(16).collect::<String>());
        println!("   Path ID: {}", path_id.chars().take(16).collect::<String>());
        println!("   Full path: {}", path);

        Ok(path)
    }

    async fn create_notification(&self, recipient: &PublicKey, msg_id: &str) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let notification = PrivateNotification {
            timestamp,
            sender: self.keypair.public_key().to_string(),
            msg_id: msg_id.to_string(),
        };

        let notification_id = Uuid::new_v4().to_string();
        let notification_path = format!(
            "pubky://{}/pub/notifications/{}.json",
            recipient,
            notification_id
        );

        let notification_json = serde_json::to_string(&notification)?;
        let response = self.client
            .put(&notification_path)
            .body(notification_json)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to store notification: {}", response.status()));
        }

        Ok(())
    }

    // Add this debugging version to your PrivateMessageHandler in messaging.rs
    pub(crate) async fn send_message(&self, recipient: &PublicKey, content: &str) -> Result<()> {
        println!("📤 Sending message to {}: '{}'",
                 recipient.to_string().chars().take(8).collect::<String>(),
                 content.chars().take(30).collect::<String>());

        let message = PrivateMessage::new(&self.keypair, recipient, content)?;
        let msg_id = Uuid::new_v4().to_string();
        let serialized = serde_json::to_string(&message)?;

        let private_path = self.private_conversation_path(recipient)?;
        let path = format!("pubky://{}{}{}.json",
                           self.keypair.public_key(),
                           private_path,
                           msg_id);

        println!("💾 Storing message at path: {}", path);
        println!("📦 Message data length: {} bytes", serialized.len());

        let response = self.client
            .put(&path)
            .body(serialized)
            .send()
            .await?;

        if !response.status().is_success() {
            println!("❌ Storage failed with status: {}", response.status());
            return Err(anyhow!("Failed to store message: {}", response.status()));
        }

        println!("✅ Message stored successfully!");

        // Skip notifications for now
        // self.create_notification(recipient, &msg_id).await?;

        Ok(())
    }

    async fn check_notifications(&self) -> Result<Vec<(PublicKey, String)>> {
        let notifications_path = format!("pubky://{}/pub/notifications/", self.keypair.public_key());

        let list_builder = self.client.list(&notifications_path)?;
        let notification_urls = list_builder.send().await?;
        let mut results = Vec::new();

        for url in notification_urls {
            let response = self.client.get(&url).send().await?;
            if response.status().is_success() {
                let response_text = response.text().await?;

                // Try to parse as new format first
                if let Ok(notification) = serde_json::from_str::<PrivateNotification>(&response_text) {
                    if let Ok(sender_pk) = PublicKey::try_from(notification.sender.as_str()) {
                        results.push((sender_pk, notification.msg_id));
                        // Delete the notification after processing
                        self.client.delete(&url).send().await?;
                    }
                }
                // If that fails, try legacy format and skip (or delete)
                else if serde_json::from_str::<LegacyPrivateNotification>(&response_text).is_ok() {
                    // This is a legacy notification - just delete it
                    println!("🗑️  Deleting legacy notification");
                    self.client.delete(&url).send().await?;
                }
                // If both fail, it's an unknown format - delete it too
                else {
                    println!("🗑️  Deleting unknown notification format");
                    self.client.delete(&url).send().await?;
                }
            }
        }

        Ok(results)
    }

    pub(crate) async fn get_messages(&self, other_pubkey: &PublicKey) -> Result<Vec<(PrivateMessage, String, bool)>> {
        let mut all_messages = Vec::new();
        let private_path = self.private_conversation_path(other_pubkey)?;

        let self_path = format!("pubky://{}{}", self.keypair.public_key(), private_path);
        let other_path = format!("pubky://{}{}", other_pubkey, private_path);

        println!("🔍 Searching for messages in conversation:");
        println!("   Self path:  {}", self_path);
        println!("   Other path: {}", other_path);

        let mut urls = Vec::new();

        // Collect URLs from both paths
        if let Ok(list_builder) = self.client.list(&self_path) {
            if let Ok(self_urls) = list_builder.send().await {
                urls.extend(self_urls);
            }
        }

        if let Ok(list_builder) = self.client.list(&other_path) {
            if let Ok(other_urls) = list_builder.send().await {
                urls.extend(other_urls);
            }
        }

        // Process each message
        for url in urls.iter() {
            let response = self.client.get(url).send().await?;
            if response.status().is_success() {
                let response_text = response.text().await?;

                if let Ok(message) = serde_json::from_str::<PrivateMessage>(&response_text) {
                    // Decrypt content
                    if let Ok(content) = message.decrypt_content(&self.keypair, other_pubkey) {
                        // Decrypt sender
                        if let Ok(sender) = message.decrypt_sender(&self.keypair, other_pubkey) {
                            // Verify signature using decrypted content and sender
                            let verified = message.verify_signature(&content, &sender).unwrap_or(false);

                            println!("     ✅ Decrypted message from {}: '{}' (verified: {})",
                                     sender.chars().take(8).collect::<String>(),
                                     content.chars().take(20).collect::<String>(),
                                     verified);

                            all_messages.push((message, content, verified));
                        } else {
                            println!("     ❌ Failed to decrypt sender");
                        }
                    } else {
                        println!("     ❌ Failed to decrypt content");
                    }
                }
            }
        }

        // Sort by timestamp
        all_messages.sort_by(|a, b| a.0.timestamp.cmp(&b.0.timestamp));
        println!("🎯 Returning {} messages total", all_messages.len());
        Ok(all_messages)
    }

    // Add this method to PrivateMessageHandler
    pub(crate) async fn get_all_new_messages_from_contacts(&self, contacts: &[PublicKey]) -> Result<Vec<(String, String, bool)>> {
        let mut all_messages = Vec::new();

        for contact in contacts {
            let conversation_messages = self.get_messages(contact).await?;
            for (msg, content, verified) in conversation_messages {
                // Decrypt the sender field using the contact as the other participant
                match msg.decrypt_sender(&self.keypair, contact) {
                    Ok(sender) => {
                        all_messages.push((sender, content, verified));
                    }
                    Err(e) => {
                        println!("❌ Failed to decrypt sender for message: {}", e);
                        // Skip messages we can't decrypt
                        continue;
                    }
                }
            }
        }

        // Sort by timestamp to get most recent messages first
        // Note: We might want to include timestamp in the return type for proper sorting
        all_messages.sort_by(|a, b| {
            // For now, sorting by sender string (not ideal, but maintains current API)
            a.0.cmp(&b.0)
        });

        Ok(all_messages)
    }

    pub async fn get_homeserver(&self, pubky: String) -> Result<String> {
        let public_key = PublicKey::try_from(pubky.clone())?;
        self.client.get_homeserver(&public_key).await
            .ok_or_else(|| anyhow!("No homeserver found for public key: {}", pubky))
    }

    pub async fn sign_in(&self) -> Result<Session> {
        self.client.signin(&self.keypair).await
            .map_err(|e| anyhow!("Failed to sign in: {}", e))
    }

    pub fn decrypt_recovery_file(&self, recovery_file: &str, passphrase: &str) -> Result<Keypair> {
        if recovery_file.is_empty() || passphrase.is_empty() {
            return Err(anyhow!("Recovery file and passphrase must not be empty"));
        }

        let recovery_file_bytes = base64::decode(recovery_file)
            .map_err(|e| anyhow!("Failed to decode recovery file: {}", e))?;

        let keypair = recovery_file::decrypt_recovery_file(&recovery_file_bytes, passphrase)
            .map_err(|_| anyhow!("Failed to decrypt recovery file"))?;

        Ok(keypair)
    }
}
pub struct AppState {
    pub keypair: Mutex<Option<Keypair>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            keypair: Mutex::new(None),
        }
    }

    // Helper method to create a client
    pub async fn create_client_and_handler(&self) -> std::result::Result<Option<PrivateMessageHandler>, String> {
        let keypair_guard = self.keypair.lock().await;
        if let Some(keypair) = keypair_guard.as_ref() {
            let client = pubky::Client::builder().build()
                .map_err(|e| format!("Failed to create client: {}", e))?;
            Ok(Some(PrivateMessageHandler::new(client, keypair.clone())))
        } else {
            Ok(None)
        }
    }
}

// Data structures for frontend communication
#[derive(Serialize, Deserialize)]
pub struct ChatMessage {
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
    pub verified: bool,
    pub is_own_message: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Contact {
    pub public_key: String,
    pub name: Option<String>,
    pub last_message: Option<String>,
    pub last_message_time: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct UserProfile {
    pub public_key: String,
    pub signed_in: bool,
}