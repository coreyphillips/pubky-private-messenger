// Access Tauri API through window object
const { invoke } = window.__TAURI__.core;

// Application state
let currentUser = null;
let currentContact = null;
let contacts = new Map();
let isEditingContactName = false; // Track when editing contact names
let userSettings = null; // User settings

// Session persistence key
const SESSION_STORAGE_KEY = 'pubky_session';

// Default settings
const DEFAULT_SETTINGS = {
  pollingEnabled: true,
  pollingInterval: 5000, // 5 seconds
};

// DOM elements
const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const settingsPanel = document.getElementById('settings-panel');
const recoveryFileInput = document.getElementById('recovery-file');
const passphraseInput = document.getElementById('passphrase');
const signInBtn = document.getElementById('sign-in-btn');
const signOutBtn = document.getElementById('sign-out-btn');
const settingsBtn = document.getElementById('settings-btn');
const closeSettingsBtn = document.getElementById('close-settings-btn');
const userPubkeySpan = document.getElementById('user-pubkey');
const loginError = document.getElementById('login-error');
const newContactInput = document.getElementById('new-contact');
const addContactBtn = document.getElementById('add-contact-btn');
const contactsList = document.getElementById('contacts-list');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const conversationTitle = document.getElementById('conversation-title');

// Settings elements
const pollingEnabledToggle = document.getElementById('polling-enabled');
const pollingIntervalSelect = document.getElementById('polling-interval');
const saveSettingsBtn = document.getElementById('save-settings-btn');

// Initialize app
async function init() {
  try {
    console.log('Initializing client...');
    await invoke('init_client');
    console.log('Client initialized');

    // Check for existing session first
    const savedSession = getSavedSession();
    if (savedSession) {
      console.log('🔄 Found saved session, attempting auto-login...');
      try {
        const profile = await invoke('restore_session', {
          encryptedKeypair: savedSession
        });
        if (profile) {
          console.log('✅ Auto-login successful');
          showChatScreen(profile);
          return;
        }
      } catch (error) {
        console.log('❌ Auto-login failed, clearing saved session:', error);
        clearSavedSession();
      }
    }

    // Check if user is already signed in (fallback)
    const profile = await invoke('get_user_profile');
    if (profile) {
      showChatScreen(profile);
    }
  } catch (error) {
    console.error('Failed to initialize:', error);
    showError('Failed to initialize application');
  }
}

// Settings management
function getSettingsKey() {
  return currentUser ? `settings_${currentUser.public_key}` : null;
}

function loadSettings() {
  const settingsKey = getSettingsKey();
  if (!settingsKey) {
    userSettings = { ...DEFAULT_SETTINGS };
    return;
  }

  try {
    const saved = localStorage.getItem(settingsKey);
    if (saved) {
      userSettings = { ...DEFAULT_SETTINGS, ...JSON.parse(saved) };
      console.log(`⚙️ Loaded settings for user ${currentUser.public_key.substring(0, 8)}`);
    } else {
      userSettings = { ...DEFAULT_SETTINGS };
      console.log(`⚙️ Using default settings for user ${currentUser.public_key.substring(0, 8)}`);
    }
  } catch (error) {
    console.error('Failed to load settings:', error);
    userSettings = { ...DEFAULT_SETTINGS };
  }
}

function saveSettings() {
  const settingsKey = getSettingsKey();
  if (!settingsKey || !userSettings) return;

  try {
    localStorage.setItem(settingsKey, JSON.stringify(userSettings));
    console.log(`💾 Saved settings for user ${currentUser.public_key.substring(0, 8)}`);
  } catch (error) {
    console.error('Failed to save settings:', error);
  }
}

function showSettings() {
  // Load current settings into UI
  pollingEnabledToggle.checked = userSettings.pollingEnabled;
  pollingIntervalSelect.value = userSettings.pollingInterval.toString();

  // Show settings panel
  settingsPanel.classList.remove('hidden');
}

function closeSettings() {
  settingsPanel.classList.add('hidden');
}

function applySettings() {
  // Get values from UI
  const pollingEnabled = pollingEnabledToggle.checked;
  const pollingInterval = parseInt(pollingIntervalSelect.value);

  // Update settings
  const oldPollingEnabled = userSettings.pollingEnabled;
  const oldPollingInterval = userSettings.pollingInterval;

  userSettings.pollingEnabled = pollingEnabled;
  userSettings.pollingInterval = pollingInterval;

  // Save settings
  saveSettings();

  // Apply polling changes
  if (oldPollingEnabled !== pollingEnabled || oldPollingInterval !== pollingInterval) {
    console.log(`⚙️ Polling settings changed: enabled=${pollingEnabled}, interval=${pollingInterval}ms`);

    // Restart polling with new settings
    stopMessagePolling();
    if (pollingEnabled) {
      startMessagePolling();
    }
  }

  // Close settings panel
  closeSettings();

  // Show feedback
  console.log('✅ Settings saved and applied');
}

// Session persistence functions
function saveSession(encryptedKeypair) {
  try {
    localStorage.setItem(SESSION_STORAGE_KEY, encryptedKeypair);
    console.log('💾 Session saved');
  } catch (error) {
    console.error('Failed to save session:', error);
  }
}

function getSavedSession() {
  try {
    return localStorage.getItem(SESSION_STORAGE_KEY);
  } catch (error) {
    console.error('Failed to get saved session:', error);
    return null;
  }
}

function clearSavedSession() {
  try {
    localStorage.removeItem(SESSION_STORAGE_KEY);
    console.log('🗑️ Session cleared');
  } catch (error) {
    console.error('Failed to clear session:', error);
  }
}

// Convert file to base64
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => {
      const base64 = reader.result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = error => reject(error);
  });
}

// Sign in
async function signIn() {
  try {
    console.log('Starting sign in...');
    const file = recoveryFileInput.files[0];
    const passphrase = passphraseInput.value;

    if (!file || !passphrase) {
      showError('Please select a recovery file and enter your passphrase');
      return;
    }

    console.log('Converting file to base64...');
    const recoveryFileB64 = await fileToBase64(file);

    console.log('Calling sign_in_with_recovery...');
    const result = await invoke('sign_in_with_recovery', {
      recoveryFileB64,
      passphrase
    });

    console.log('Sign in successful:', result.profile);

    // Save the encrypted keypair for future sessions
    if (result.encrypted_keypair) {
      saveSession(result.encrypted_keypair);
    }

    showChatScreen(result.profile);
    clearError();
  } catch (error) {
    console.error('Sign in error:', error);
    showError(error.toString());
  }
}

// Show chat screen
function showChatScreen(profile) {
  currentUser = profile;
  loginScreen.classList.add('hidden');
  chatScreen.classList.remove('hidden');
  userPubkeySpan.textContent = profile.public_key.substring(0, 16) + '...';

  console.log(`🔐 Signed in as: ${profile.public_key.substring(0, 8)}`);

  // Load user settings
  loadSettings();

  // Load contacts specific to this pubky account
  loadContacts();

  // Start polling for new messages (if enabled in settings)
  if (userSettings.pollingEnabled) {
    startMessagePolling();
  }
}

// Sign out
async function signOut() {
  try {
    await invoke('sign_out');

    // Clear saved session
    clearSavedSession();

    // Clear application state
    currentUser = null;
    currentContact = null;
    contacts.clear();
    userSettings = null;

    // Clear caches
    clearMessageCaches();

    // Clear UI
    chatScreen.classList.add('hidden');
    settingsPanel.classList.add('hidden'); // Also hide settings if open
    loginScreen.classList.remove('hidden');
    contactsList.innerHTML = '';
    messagesContainer.innerHTML = '';
    conversationTitle.textContent = 'Select a contact to start chatting';
    messageInput.disabled = true;
    sendBtn.disabled = true;

    stopMessagePolling();
    console.log('🚪 Signed out and cleared all data including saved session');
  } catch (error) {
    console.error('Sign out error:', error);
  }
}

// Add contact
function addContact() {
  const pubkey = newContactInput.value.trim();
  if (!pubkey) return;

  // Check if contact already exists
  if (contacts.has(pubkey)) {
    alert('Contact already exists!');
    return;
  }

  contacts.set(pubkey, {
    public_key: pubkey,
    name: null,
    last_message: null,
    last_message_time: null,
    last_read_time: 0, // Track when messages were last read
    unread_count: 0    // Track unread message count
  });

  saveContacts();
  renderContacts();
  newContactInput.value = '';

  // Check for messages immediately after adding contact
  setTimeout(() => updateContactUnreadCount(pubkey), 1000);

  console.log(`➕ Added contact ${pubkey.substring(0, 8)} to account ${currentUser.public_key.substring(0, 8)}`);
}

// Remove contact
function removeContact(pubkey, event) {
  // Stop event propagation to prevent selecting the contact
  event.stopPropagation();

  contacts.delete(pubkey);
  saveContacts();

  // If we're removing the currently selected contact, clear the chat
  if (currentContact === pubkey) {
    currentContact = null;
    conversationTitle.textContent = 'Select a contact to start chatting';
    messagesContainer.innerHTML = '';
    messageInput.disabled = true;
    sendBtn.disabled = true;
  }

  renderContacts();
  console.log(`🗑️  Removed contact ${pubkey.substring(0, 8)} from account ${currentUser.public_key.substring(0, 8)}`);
}

// Edit contact name
function editContactName(pubkey, nameElement) {
  const contact = contacts.get(pubkey);
  if (!contact) return;

  const originalName = contact.name || '';
  const currentDisplayName = nameElement.textContent;

  // Set editing flag to prevent polling interference
  isEditingContactName = true;

  // Create input element
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'contact-name-input';
  input.value = originalName;
  input.maxLength = 30;
  input.style.cssText = `
    width: 100%;
    border: none;
    background: transparent;
    font-size: inherit;
    font-weight: inherit;
    color: inherit;
    outline: 2px solid #007bff;
    border-radius: 3px;
    padding: 2px 4px;
  `;

  // Save function
  function saveName() {
    const newName = input.value.trim();

    if (newName && newName !== originalName) {
      contact.name = newName;
      console.log(`✏️  Renamed contact ${pubkey.substring(0, 8)} to "${newName}"`);
    } else if (!newName && originalName) {
      // If empty, remove custom name
      contact.name = null;
      console.log(`🔄 Removed custom name for contact ${pubkey.substring(0, 8)}`);
    }

    saveContacts();

    // Clear editing flag before re-rendering
    isEditingContactName = false;
    renderContacts();

    // Update conversation title if this is the current contact
    if (currentContact === pubkey) {
      conversationTitle.textContent = contact.name || pubkey.substring(0, 16) + '...';
    }
  }

  // Cancel function
  function cancelEdit() {
    nameElement.textContent = currentDisplayName;
    nameElement.style.display = '';
    isEditingContactName = false; // Clear editing flag
  }

  // Replace name element with input
  nameElement.style.display = 'none';
  nameElement.parentNode.insertBefore(input, nameElement);

  // Focus and select text
  input.focus();
  input.select();

  // Event handlers
  input.addEventListener('blur', () => {
    saveName();
    input.remove();
    nameElement.style.display = '';
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      input.blur(); // This will trigger save
    } else if (e.key === 'Escape') {
      input.remove();
      cancelEdit();
    }
  });

  // Prevent contact selection when clicking on input
  input.addEventListener('click', (e) => {
    e.stopPropagation();
  });
}

function loadContacts() {
  contacts.clear(); // Clear existing contacts first

  if (currentUser) {
    const storageKey = `contacts_${currentUser.public_key}`;
    const saved = localStorage.getItem(storageKey);

    if (saved) {
      const contactsArray = JSON.parse(saved);
      contactsArray.forEach(([pubkey, contact]) => {
        // Ensure new fields exist for backward compatibility
        if (!contact.hasOwnProperty('last_read_time')) {
          contact.last_read_time = 0;
        }
        if (!contact.hasOwnProperty('unread_count')) {
          contact.unread_count = 0;
        }
        contacts.set(pubkey, contact);
      });
      console.log(`📂 Loaded ${contactsArray.length} contacts for pubkey: ${currentUser.public_key.substring(0, 8)}`);
    } else {
      console.log(`📂 No saved contacts found for pubkey: ${currentUser.public_key.substring(0, 8)}`);
    }
  }

  renderContacts();

  // Update last messages and unread counts for all contacts
  updateAllContactsData();
}

// Update contact unread count
async function updateContactUnreadCount(pubkey, skipRender = false) {
  const contact = contacts.get(pubkey);
  if (!contact) return;

  try {
    const messages = await invoke('get_conversation', { otherPubkey: pubkey });

    if (messages.length > 0) {
      // Update last message info
      const lastMessage = messages[messages.length - 1];
      contact.last_message = lastMessage.content.length > 30
          ? lastMessage.content.substring(0, 30) + '...'
          : lastMessage.content;
      contact.last_message_time = lastMessage.timestamp;

      // Count unread messages
      const unreadMessages = messages.filter(msg =>
          msg.timestamp > contact.last_read_time && !msg.is_own_message
      );

      const previousUnreadCount = contact.unread_count;
      contact.unread_count = unreadMessages.length;

      // Cache messages if:
      // 1. Unread count changed (new messages arrived)
      // 2. OR no cache exists yet (first time checking)
      // 3. OR the last message is different (could be user sent a message)
      const cachedMessages = loadMessagesCache(pubkey);
      const shouldCache =
          contact.unread_count !== previousUnreadCount ||
          !cachedMessages ||
          (cachedMessages.length > 0 &&
              cachedMessages[cachedMessages.length - 1].timestamp !== lastMessage.timestamp);

      if (shouldCache) {
        saveMessagesCache(pubkey, messages);
        console.log(`💾 Cached messages for ${pubkey.substring(0, 8)} (unread: ${previousUnreadCount} → ${contact.unread_count})`);
      }

      // Log if unread count changed
      if (contact.unread_count !== previousUnreadCount) {
        console.log(`📬 Contact ${pubkey.substring(0, 8)} unread count: ${previousUnreadCount} → ${contact.unread_count}`);
      }

    } else {
      contact.unread_count = 0;
    }

    saveContacts();

    // Only re-render if not currently editing a contact name and not skipping render
    if (!isEditingContactName && !skipRender) {
      renderContacts();
    }
  } catch (error) {
    console.log(`Failed to update unread count for ${pubkey.substring(0, 8)}:`, error);
  }
}

// Update last message and unread count for all contacts
async function updateAllContactsData() {
  console.log('🔄 Updating message data for all contacts...');

  const updatePromises = Array.from(contacts.keys()).map(pubkey =>
      updateContactUnreadCount(pubkey, true) // Skip individual renders
  );

  await Promise.all(updatePromises);

  // Re-render once at the end if not editing
  if (!isEditingContactName) {
    renderContacts();
  }

  console.log('✅ Finished updating all contact data');
}

// Mark contact as read (when opening conversation)
function markContactAsRead(pubkey) {
  const contact = contacts.get(pubkey);
  if (!contact) return;

  const now = Math.floor(Date.now() / 1000);
  const hadUnreadMessages = contact.unread_count > 0;

  contact.last_read_time = now;
  contact.unread_count = 0;

  if (hadUnreadMessages) {
    console.log(`👁️  Marked contact ${pubkey.substring(0, 8)} as read`);
    saveContacts();
    renderContacts();
  }
}

// Save messages to localStorage (per conversation)
function saveMessagesCache(otherPubkey, messages) {
  if (currentUser && messages.length > 0) {
    const cacheKey = `messages_${currentUser.public_key}_${otherPubkey}`;
    const cacheData = {
      timestamp: Date.now(),
      messages: messages
    };
    localStorage.setItem(cacheKey, JSON.stringify(cacheData));
    console.log(`💾 Cached ${messages.length} messages for conversation with ${otherPubkey.substring(0, 8)}`);
  }
}

// Load messages from localStorage cache
function loadMessagesCache(otherPubkey) {
  if (currentUser) {
    const cacheKey = `messages_${currentUser.public_key}_${otherPubkey}`;
    const cached = localStorage.getItem(cacheKey);

    if (cached) {
      try {
        const cacheData = JSON.parse(cached);
        const ageMinutes = (Date.now() - cacheData.timestamp) / (1000 * 60);
        console.log(`📂 Found cached messages (${cacheData.messages.length} msgs, ${Math.round(ageMinutes)} min old)`);
        return cacheData.messages;
      } catch (error) {
        console.log('❌ Error loading cached messages:', error);
        return null;
      }
    }
  }
  return null;
}

// Add a message to the cache immediately (for sent messages)
function addMessageToCache(otherPubkey, newMessage) {
  if (currentUser) {
    const cacheKey = `messages_${currentUser.public_key}_${otherPubkey}`;
    const cached = localStorage.getItem(cacheKey);

    if (cached) {
      try {
        const cacheData = JSON.parse(cached);
        cacheData.messages.push(newMessage);
        cacheData.timestamp = Date.now();
        localStorage.setItem(cacheKey, JSON.stringify(cacheData));
        console.log(`➕ Added sent message to cache`);
      } catch (error) {
        console.log('❌ Error updating message cache:', error);
      }
    } else {
      // If no cache exists, create a new one with just this message
      const cacheData = {
        timestamp: Date.now(),
        messages: [newMessage]
      };
      localStorage.setItem(cacheKey, JSON.stringify(cacheData));
      console.log(`➕ Created new cache with sent message`);
    }
  }
}

// Clear message caches for current user
function clearMessageCaches() {
  if (currentUser) {
    const keysToDelete = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key.startsWith(`messages_${currentUser.public_key}_`)) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach(key => localStorage.removeItem(key));
    console.log(`🧹 Cleared ${keysToDelete.length} message caches`);
  }
}

function saveContacts() {
  if (currentUser) {
    const contactsArray = Array.from(contacts.entries());
    const storageKey = `contacts_${currentUser.public_key}`;
    localStorage.setItem(storageKey, JSON.stringify(contactsArray));
    console.log(`💾 Saved ${contactsArray.length} contacts for pubkey: ${currentUser.public_key.substring(0, 8)}`);
  }
}

// Render contacts list
function renderContacts() {
  contactsList.innerHTML = '';

  // Sort contacts: by unread count (desc), then by last message time (desc)
  // No longer move active contact to top to prevent jumping
  const sortedContacts = Array.from(contacts.entries()).sort(([pubkeyA, contactA], [pubkeyB, contactB]) => {
    // Sort by unread count (descending)
    if (contactB.unread_count !== contactA.unread_count) {
      return contactB.unread_count - contactA.unread_count;
    }

    // Then by last message time (descending)
    return (contactB.last_message_time || 0) - (contactA.last_message_time || 0);
  });

  for (const [pubkey, contact] of sortedContacts) {
    const contactEl = document.createElement('div');
    contactEl.className = 'contact-item';
    if (currentContact === pubkey) {
      contactEl.classList.add('active');
    }

    const displayName = contact.name || pubkey.substring(0, 16) + '...';
    const displaySubtext = contact.name
        ? pubkey.substring(0, 16) + '...'
        : (contact.last_message || 'No messages');

    // Create unread badge if there are unread messages
    const unreadBadge = contact.unread_count > 0
        ? `<span class="unread-badge">${contact.unread_count}</span>`
        : '';

    contactEl.innerHTML = `
      <div class="contact-info">
        <div class="contact-name-row">
          <span class="contact-name">${displayName}</span>
          ${unreadBadge}
          <button class="contact-edit-btn" title="Edit name">✏️</button>
        </div>
        <div class="contact-last-message">${displaySubtext}</div>
      </div>
      <button class="contact-delete-btn" title="Remove contact">×</button>
    `;

    // Add click handler for selecting contact (but not on action buttons)
    contactEl.addEventListener('click', (e) => {
      if (!e.target.classList.contains('contact-delete-btn') &&
          !e.target.classList.contains('contact-edit-btn') &&
          !e.target.classList.contains('contact-name-input')) {
        selectContact(pubkey);
      }
    });

    // Add click handler for edit button
    const editBtn = contactEl.querySelector('.contact-edit-btn');
    if (editBtn) {
      editBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const nameEl = contactEl.querySelector('.contact-name');
        editContactName(pubkey, nameEl);
      });
    }

    // Add click handler for delete button
    const deleteBtn = contactEl.querySelector('.contact-delete-btn');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', (e) => {
        removeContact(pubkey, e);
      });
    }

    contactsList.appendChild(contactEl);
  }
}

// Select contact
async function selectContact(pubkey) {
  currentContact = pubkey;

  // Mark contact as read when opening
  markContactAsRead(pubkey);

  renderContacts();

  const contact = contacts.get(pubkey);
  const displayName = contact?.name || pubkey.substring(0, 16) + '...';
  conversationTitle.textContent = displayName;

  messageInput.disabled = false;
  sendBtn.disabled = false;

  // Load conversation history
  await loadConversation(pubkey);
}

// Load conversation
async function loadConversation(pubkey) {
  try {
    console.log(`📖 Loading conversation with ${pubkey.substring(0, 16)}...`);

    // First, try to load cached messages for instant display
    const cachedMessages = loadMessagesCache(pubkey);
    if (cachedMessages && cachedMessages.length > 0) {
      console.log(`⚡ Showing ${cachedMessages.length} cached messages instantly`);
      renderMessages(cachedMessages);

      // Update conversation title to show we have cached data
      const contact = contacts.get(pubkey);
      if (contact) {
        conversationTitle.textContent = `${contact?.name || pubkey.substring(0, 16) + '...'} 📂`;
      }
    }

    // Then fetch fresh messages from the backend
    console.log(`🔄 Fetching fresh messages from backend...`);
    const messages = await invoke('get_conversation', { otherPubkey: pubkey });
    console.log(`📬 Loaded ${messages.length} fresh messages from backend`);

    // Log message details for debugging
    messages.forEach((msg, i) => {
      const sender = msg.is_own_message ? 'You' : 'Them';
      console.log(`  ${i + 1}. ${sender}: "${msg.content}" (${msg.verified ? '✅' : '⚠️'})`);
    });

    // Update the display with fresh messages
    renderMessages(messages);

    // Update conversation title (remove cache indicator)
    const contact = contacts.get(pubkey);
    if (contact) {
      conversationTitle.textContent = contact?.name || pubkey.substring(0, 16) + '...';
    }

    // Cache the fresh messages
    if (messages.length > 0) {
      saveMessagesCache(pubkey, messages);
    }

    // Update contact's last message if there are messages
    if (messages.length > 0) {
      const lastMessage = messages[messages.length - 1];
      if (contact) {
        contact.last_message = lastMessage.content.length > 30
            ? lastMessage.content.substring(0, 30) + '...'
            : lastMessage.content;
        contact.last_message_time = lastMessage.timestamp;

        // Since we're viewing this conversation, mark as read
        markContactAsRead(pubkey);

        saveContacts();
        renderContacts(); // Re-render to show updated last message
      }
    }

  } catch (error) {
    console.error('Failed to load conversation:', error);

    // If backend fails but we have cached messages, keep showing them
    const cachedMessages = loadMessagesCache(pubkey);
    if (cachedMessages && cachedMessages.length > 0) {
      console.log(`📂 Backend failed, keeping ${cachedMessages.length} cached messages`);
      renderMessages(cachedMessages);
    }
  }
}

// Helper function to format message timestamps with better date information
function formatMessageTimestamp(timestamp) {
  const messageDate = new Date(timestamp * 1000);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
  const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);

  const messageDateOnly = new Date(messageDate.getFullYear(), messageDate.getMonth(), messageDate.getDate());
  const timeString = messageDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  // Today: just show time
  if (messageDateOnly.getTime() === today.getTime()) {
    return timeString;
  }

  // Yesterday: show "Yesterday" + time
  if (messageDateOnly.getTime() === yesterday.getTime()) {
    return `Yesterday ${timeString}`;
  }

  // This week: show day name + time
  if (messageDateOnly.getTime() >= weekAgo.getTime()) {
    const dayName = messageDate.toLocaleDateString([], { weekday: 'short' });
    return `${dayName} ${timeString}`;
  }

  // Older: show full date + time
  // If it's from this year, don't show the year
  if (messageDate.getFullYear() === now.getFullYear()) {
    const dateString = messageDate.toLocaleDateString([], { month: 'short', day: 'numeric' });
    return `${dateString} ${timeString}`;
  }

  // Different year: show full date including year
  const dateString = messageDate.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  return `${dateString} ${timeString}`;
}

// Render messages
function renderMessages(messages) {
  messagesContainer.innerHTML = '';

  messages.forEach(message => {
    const messageEl = document.createElement('div');
    messageEl.className = `message ${message.is_own_message ? 'own' : 'other'}`;

    const timestamp = formatMessageTimestamp(message.timestamp);
    const verifiedIcon = message.verified ? '✅' : '⚠️';

    messageEl.innerHTML = `
            <div class="message-content">${message.content}</div>
            <div class="message-meta">
                <span class="message-time">${timestamp}</span>
                <span class="message-verified">${verifiedIcon}</span>
            </div>
        `;

    messagesContainer.appendChild(messageEl);
  });

  // Scroll to bottom
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Send message
async function sendMessage() {
  if (!currentContact || !messageInput.value.trim()) return;

  const messageContent = messageInput.value.trim();
  messageInput.value = ''; // Clear input immediately for better UX

  // Create optimistic message object for immediate display
  const optimisticMessage = {
    sender: currentUser.public_key,
    content: messageContent,
    timestamp: Math.floor(Date.now() / 1000),
    verified: true, // Assume it will be verified
    is_own_message: true
  };

  // Add message to cache and display immediately
  addMessageToCache(currentContact, optimisticMessage);

  // Update the display immediately with the optimistic message
  const cachedMessages = loadMessagesCache(currentContact);
  if (cachedMessages) {
    renderMessages(cachedMessages);
    console.log(`⚡ Added message to display optimistically`);
  }

  // Update contact's last message immediately
  const contact = contacts.get(currentContact);
  if (contact) {
    contact.last_message = messageContent.length > 30
        ? messageContent.substring(0, 30) + '...'
        : messageContent;
    contact.last_message_time = Math.floor(Date.now() / 1000);
    saveContacts();
    renderContacts(); // Re-render to show updated last message
  }

  try {
    console.log(`📤 Sending message: "${messageContent}"`);
    await invoke('send_message', {
      recipientPubkey: currentContact,
      content: messageContent
    });

    console.log('✅ Message sent successfully, refreshing with backend data...');

    // Reload conversation after a short delay to get the actual backend data
    // This will update the cache with the real message and verify it was sent
    setTimeout(async () => {
      const messages = await invoke('get_conversation', { otherPubkey: currentContact });
      if (messages.length > 0) {
        saveMessagesCache(currentContact, messages);
        renderMessages(messages);
        console.log('🔄 Updated with verified backend messages');
      }
    }, 1000);

  } catch (error) {
    console.error('Failed to send message:', error);

    // If sending failed, reload conversation to remove the optimistic message
    // and show the user that their message didn't go through
    setTimeout(async () => {
      await loadConversation(currentContact);
    }, 500);

    // Show error to user
    alert('Failed to send message: ' + error);
  }
}

// Message polling
let messagePollingInterval;

function startMessagePolling() {
  // Don't start if polling is disabled in settings
  if (!userSettings || !userSettings.pollingEnabled) {
    console.log('📭 Message polling disabled in settings');
    return;
  }

  const interval = userSettings.pollingInterval;
  console.log(`🔄 Starting message polling every ${interval / 1000} seconds`);

  messagePollingInterval = setInterval(async () => {
    try {
      console.log('🔄 Polling for new messages...');

      let hasNewMessages = false;
      let currentContactHasNewMessages = false;

      const checkPromises = Array.from(contacts.keys()).map(async (pubkey) => {
        const contact = contacts.get(pubkey);
        const oldUnreadCount = contact.unread_count;

        await updateContactUnreadCount(pubkey, true);

        // Check if this contact got new messages
        if (contact.unread_count > oldUnreadCount) {
          hasNewMessages = true;
          console.log(`📬 New messages from ${pubkey.substring(0, 8)}: +${contact.unread_count - oldUnreadCount}`);

          // Check if it's the current conversation
          if (currentContact === pubkey) {
            currentContactHasNewMessages = true;
          }
        }
      });

      await Promise.all(checkPromises);

      // Re-render contacts if not editing
      if (!isEditingContactName) {
        renderContacts();
      }

      // If viewing a conversation that got new messages, refresh it from cache
      if (currentContact && currentContactHasNewMessages) {
        console.log('🔄 Refreshing current conversation with new messages');

        // Since we already cached the messages during polling,
        // we can just load from cache for instant update
        const cachedMessages = loadMessagesCache(currentContact);
        if (cachedMessages) {
          renderMessages(cachedMessages);

          // Mark as read since user is viewing it
          markContactAsRead(currentContact);
        }
      }

    } catch (error) {
      console.error('Failed to poll messages:', error);
    }
  }, interval);
}

function stopMessagePolling() {
  if (messagePollingInterval) {
    clearInterval(messagePollingInterval);
    messagePollingInterval = null;
    console.log('⏹️ Message polling stopped');
  }
}

// Utility functions
function showError(message) {
  loginError.textContent = message;
  loginError.style.display = 'block';
}

function clearError() {
  loginError.style.display = 'none';
}

// Event listeners
signInBtn.addEventListener('click', (e) => {
  console.log('Sign in button clicked!');
  e.preventDefault();
  signIn();
});

signOutBtn.addEventListener('click', signOut);
settingsBtn.addEventListener('click', showSettings);
closeSettingsBtn.addEventListener('click', closeSettings);
saveSettingsBtn.addEventListener('click', applySettings);
addContactBtn.addEventListener('click', addContact);
sendBtn.addEventListener('click', sendMessage);

messageInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    sendMessage();
  }
});

passphraseInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    signIn();
  }
});

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', init);

// Utility functions for managing account data (accessible from console)
window.debugContacts = {
  // See all stored pubky accounts and their contact counts
  listAccounts: function() {
    const accounts = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key.startsWith('contacts_')) {
        const pubkey = key.replace('contacts_', '');
        const contactsData = JSON.parse(localStorage.getItem(key));
        const contactsWithNames = contactsData.map(([pk, contact]) => ({
          pubkey: pk.substring(0, 16) + '...',
          name: contact.name || '(no name)',
          lastMessage: contact.last_message || '(no messages)',
          unreadCount: contact.unread_count || 0
        }));

        accounts.push({
          accountPubkey: pubkey.substring(0, 16) + '...',
          fullPubkey: pubkey,
          contactCount: contactsData.length,
          contacts: contactsWithNames
        });
      }
    }
    console.table(accounts);
    return accounts;
  },

  // See contacts for current account
  currentContacts: function() {
    if (!currentUser) {
      console.log('❌ No user signed in');
      return [];
    }

    const contactsArray = Array.from(contacts.entries()).map(([pubkey, contact]) => ({
      pubkey: pubkey.substring(0, 16) + '...',
      fullPubkey: pubkey,
      name: contact.name || '(no name)',
      lastMessage: contact.last_message || '(no messages)',
      unreadCount: contact.unread_count || 0,
      lastReadTime: new Date(contact.last_read_time * 1000).toLocaleString()
    }));

    console.table(contactsArray);
    return contactsArray;
  },

  // See message caches for current account
  messageCaches: function() {
    if (!currentUser) {
      console.log('❌ No user signed in');
      return [];
    }

    const caches = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key.startsWith(`messages_${currentUser.public_key}_`)) {
        const otherPubkey = key.replace(`messages_${currentUser.public_key}_`, '');
        const cacheData = JSON.parse(localStorage.getItem(key));
        const ageMinutes = Math.round((Date.now() - cacheData.timestamp) / (1000 * 60));
        const contact = contacts.get(otherPubkey);

        caches.push({
          contact: contact?.name || otherPubkey.substring(0, 16) + '...',
          messageCount: cacheData.messages.length,
          ageMinutes: ageMinutes,
          lastUpdate: new Date(cacheData.timestamp).toLocaleString()
        });
      }
    }

    console.table(caches);
    return caches;
  },

  // Clear message cache for specific contact
  clearMessageCache: function(pubkey) {
    if (!currentUser) {
      console.log('❌ No user signed in');
      return;
    }

    const cacheKey = `messages_${currentUser.public_key}_${pubkey}`;
    if (localStorage.getItem(cacheKey)) {
      localStorage.removeItem(cacheKey);
      console.log(`🧹 Cleared message cache for ${pubkey.substring(0, 8)}`);
    } else {
      console.log(`❌ No message cache found for ${pubkey.substring(0, 8)}`);
    }
  },

  // Clear contacts for a specific pubkey
  clearAccount: function(pubkey) {
    const key = `contacts_${pubkey}`;
    if (localStorage.getItem(key)) {
      localStorage.removeItem(key);
      console.log(`🗑️  Cleared contacts for pubkey: ${pubkey.substring(0, 8)}`);
      if (currentUser && currentUser.public_key === pubkey) {
        loadContacts(); // Reload if it's the current user
      }
    } else {
      console.log(`❌ No contacts found for pubkey: ${pubkey.substring(0, 8)}`);
    }
  },

  // Clear all account data
  clearAll: function() {
    if (confirm('This will delete ALL contact data and message caches for ALL accounts. Are you sure?')) {
      const keysToDelete = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key.startsWith('contacts_') || key.startsWith('messages_')) {
          keysToDelete.push(key);
        }
      }
      keysToDelete.forEach(key => localStorage.removeItem(key));
      contacts.clear();
      renderContacts();
      console.log(`🗑️  Cleared all data (${keysToDelete.length} items: contacts + message caches)`);
    }
  },

  // Clear saved session
  clearSession: function() {
    clearSavedSession();
    console.log('🗑️ Cleared saved session');
  },

  // Force update unread counts
  updateUnreadCounts: function() {
    updateAllContactsData();
    console.log('🔄 Forcing unread count update for all contacts');
  },

  // View current settings
  viewSettings: function() {
    if (!userSettings) {
      console.log('❌ No settings loaded');
      return;
    }
    console.log('⚙️ Current settings:', userSettings);
    return userSettings;
  }
};

console.log('🔧 Debug utilities available:');
console.log('  debugContacts.listAccounts() - See all stored accounts');
console.log('  debugContacts.currentContacts() - See current account contacts');
console.log('  debugContacts.messageCaches() - See message caches');
console.log('  debugContacts.clearMessageCache(pubkey) - Clear specific message cache');
console.log('  debugContacts.clearAccount(pubkey) - Clear specific account');
console.log('  debugContacts.clearAll() - Clear all accounts and caches');
console.log('  debugContacts.clearSession() - Clear saved session');
console.log('  debugContacts.updateUnreadCounts() - Force update unread counts');
console.log('  debugContacts.viewSettings() - View current settings');