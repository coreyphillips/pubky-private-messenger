// Access Tauri API through window object
const { invoke } = window.__TAURI__.core;

// Application state
let currentUser = null;
let currentContact = null;
let contacts = new Map();

// DOM elements
const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const recoveryFileInput = document.getElementById('recovery-file');
const passphraseInput = document.getElementById('passphrase');
const signInBtn = document.getElementById('sign-in-btn');
const signOutBtn = document.getElementById('sign-out-btn');
const userPubkeySpan = document.getElementById('user-pubkey');
const loginError = document.getElementById('login-error');
const newContactInput = document.getElementById('new-contact');
const addContactBtn = document.getElementById('add-contact-btn');
const contactsList = document.getElementById('contacts-list');
const messagesContainer = document.getElementById('messages-container');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const conversationTitle = document.getElementById('conversation-title');

// Initialize app
async function init() {
  try {
    console.log('Initializing client...');
    await invoke('init_client');
    console.log('Client initialized');

    // Check if user is already signed in
    const profile = await invoke('get_user_profile');
    if (profile) {
      showChatScreen(profile);
    }
  } catch (error) {
    console.error('Failed to initialize:', error);
    showError('Failed to initialize application');
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
    const profile = await invoke('sign_in_with_recovery', {
      recoveryFileB64,
      passphrase
    });

    console.log('Sign in successful:', profile);
    showChatScreen(profile);
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

  // Load contacts specific to this pubky account
  loadContacts();

  // Start polling for new messages
  startMessagePolling();
}

// Sign out
async function signOut() {
  try {
    await invoke('sign_out');

    // Clear application state
    currentUser = null;
    currentContact = null;
    contacts.clear(); // Clear contacts from memory

    // Clear caches
    clearMessageCaches(); // Clear message caches for this user

    // Clear UI
    chatScreen.classList.add('hidden');
    loginScreen.classList.remove('hidden');
    contactsList.innerHTML = ''; // Clear contacts display
    messagesContainer.innerHTML = ''; // Clear messages display
    conversationTitle.textContent = 'Select a contact to start chatting';
    messageInput.disabled = true;
    sendBtn.disabled = true;

    stopMessagePolling();
    console.log('🚪 Signed out and cleared all data including message caches');
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
    last_message_time: null
  });

  saveContacts();
  renderContacts();
  newContactInput.value = '';

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
      contacts = new Map(contactsArray);
      console.log(`📂 Loaded ${contactsArray.length} contacts for pubkey: ${currentUser.public_key.substring(0, 8)}`);
    } else {
      console.log(`📂 No saved contacts found for pubkey: ${currentUser.public_key.substring(0, 8)}`);
    }
  }

  renderContacts();

  // Update last messages for all contacts
  updateAllContactsLastMessages();
}

// Update last message for all contacts
async function updateAllContactsLastMessages() {
  console.log('🔄 Updating last messages for all contacts...');

  for (const [pubkey, contact] of contacts) {
    try {
      const messages = await invoke('get_conversation', { otherPubkey: pubkey });
      if (messages.length > 0) {
        const lastMessage = messages[messages.length - 1];
        contact.last_message = lastMessage.content.length > 30
            ? lastMessage.content.substring(0, 30) + '...'
            : lastMessage.content;
        contact.last_message_time = lastMessage.timestamp;
      }
    } catch (error) {
      console.log(`Failed to get messages for ${pubkey.substring(0, 8)}:`, error);
    }
  }

  saveContacts();
  renderContacts();
  console.log('✅ Finished updating contact last messages');
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

  for (const [pubkey, contact] of contacts) {
    const contactEl = document.createElement('div');
    contactEl.className = 'contact-item';
    if (currentContact === pubkey) {
      contactEl.classList.add('active');
    }

    const displayName = contact.name || pubkey.substring(0, 16) + '...';
    const displaySubtext = contact.name
        ? pubkey.substring(0, 16) + '...'
        : (contact.last_message || 'No messages');

    contactEl.innerHTML = `
      <div class="contact-info">
        <div class="contact-name-row">
          <span class="contact-name">${displayName}</span>
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

// Render messages
function renderMessages(messages) {
  messagesContainer.innerHTML = '';

  messages.forEach(message => {
    const messageEl = document.createElement('div');
    messageEl.className = `message ${message.is_own_message ? 'own' : 'other'}`;

    const timestamp = new Date(message.timestamp * 1000).toLocaleTimeString();
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
  messagePollingInterval = setInterval(async () => {
    try {
      const newMessages = await invoke('get_new_messages');
      if (newMessages.length > 0) {
        // Update conversation if viewing sender
        const senders = [...new Set(newMessages.map(m => m.sender))];
        if (currentContact && senders.includes(currentContact)) {
          await loadConversation(currentContact);
        }
      }
    } catch (error) {
      console.error('Failed to poll messages:', error);
    }
  }, 3000);
}

function stopMessagePolling() {
  if (messagePollingInterval) {
    clearInterval(messagePollingInterval);
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
          lastMessage: contact.last_message || '(no messages)'
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
      lastMessage: contact.last_message || '(no messages)'
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
  }
};

console.log('🔧 Debug utilities available:');
console.log('  debugContacts.listAccounts() - See all stored accounts');
console.log('  debugContacts.currentContacts() - See current account contacts');
console.log('  debugContacts.messageCaches() - See message caches');
console.log('  debugContacts.clearMessageCache(pubkey) - Clear specific message cache');
console.log('  debugContacts.clearAccount(pubkey) - Clear specific account');
console.log('  debugContacts.clearAll() - Clear all accounts and caches');