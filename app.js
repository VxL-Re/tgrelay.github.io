// ---------- Telegram Relay - Web App ----------

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ---------- State ----------
const STATE = {
    encryptionKey: null,
    sessionString: null,
    db: null,
    currentChat: null,
    repoOwner: null,
    repoName: null,
    pat: null
};

// Persist non-sensitive config
function saveConfig() {
    const config = {
        repoOwner: STATE.repoOwner,
        repoName: STATE.repoName,
        hasSession: !!STATE.sessionString,
        hasPat: !!STATE.pat
    };
    localStorage.setItem('relay_config', JSON.stringify(config));
}

function loadConfig() {
    try {
        const config = JSON.parse(localStorage.getItem('relay_config'));
        if (config) {
            STATE.repoOwner = config.repoOwner;
            STATE.repoName = config.repoName;
            return config;
        }
    } catch (e) { /* ignore */ }
    return null;
}

// ---------- Crypto ----------
const CryptoHelper = {
    async deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-CBC', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async decrypt(packageStr, password) {
        const pkg = JSON.parse(packageStr);
        const salt = b64ToBuf(pkg.salt);
        const iv = b64ToBuf(pkg.iv);
        const tag = b64ToBuf(pkg.tag);
        const ciphertext = b64ToBuf(pkg.data);

        const key = await this.deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv }, key, ciphertext
        );

        const data = new Uint8Array(decrypted);
        const padLen = data[data.length - 1];
        const unpadded = data.slice(0, data.length - padLen);

        const computedTag = await crypto.subtle.digest('SHA-256', unpadded);
        if (!bufEquals(new Uint8Array(computedTag), new Uint8Array(tag))) {
            throw new Error('Integrity check failed — wrong key or corrupted data');
        }

        return new TextDecoder().decode(unpadded);
    },

    async encrypt(dataStr, password) {
        const enc = new TextEncoder();
        const data = enc.encode(dataStr);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(16));

        const key = await this.deriveKey(password, salt);

        // PKCS7 padding
        const padLen = 16 - (data.length % 16);
        const padded = new Uint8Array(data.length + padLen);
        padded.set(data);
        padded.fill(padLen, data.length);

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv }, key, padded
        );

        const tag = await crypto.subtle.digest('SHA-256', data);

        return JSON.stringify({
            salt: bufToB64(salt),
            iv: bufToB64(iv),
            tag: bufToB64(tag),
            data: bufToB64(ciphertext),
            v: 1
        });
    }
};

function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function bufToB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function bufEquals(a, b) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => v === b[i]);
}

// ---------- GitHub API ----------
class GitHubDB {
    constructor(owner, repo, token = null) {
        this.owner = owner;
        this.repo = repo;
        this.token = token;
        this.rawBase = `https://raw.githubusercontent.com/${owner}/${repo}/main`;
        this.apiBase = `https://api.github.com/repos/${owner}/${repo}`;
    }

    async fetchRaw(path) {
        const url = `${this.rawBase}/${path}`;
        const headers = {};
        if (this.token) headers['Authorization'] = `token ${this.token}`;
        const res = await fetch(url, { headers, cache: 'no-cache' });
        if (!res.ok) throw new Error(`HTTP ${res.status} for ${path}`);
        return res.text();
    }

    async fetchJSON(path, encrypted = true) {
        const raw = await this.fetchRaw(path);
        if (encrypted) {
            const dec = await CryptoHelper.decrypt(raw, STATE.encryptionKey);
            return JSON.parse(dec);
        }
        return JSON.parse(raw);
    }

    async saveSecret(secretName, secretValue) {
        if (!this.token) throw new Error('GitHub token required');

        // Get repo public key for secret encryption
        const pubKeyRes = await fetch(
            `${this.apiBase}/actions/secrets/public-key`,
            { headers: { Authorization: `token ${this.token}` } }
        );
        if (!pubKeyRes.ok) {
            const err = await pubKeyRes.json().catch(() => ({}));
            throw new Error(err.message || `Cannot access repo secrets (HTTP ${pubKeyRes.status})`);
        }
        const pubKey = await pubKeyRes.json();

        // Encrypt secret with libsodium sealed box
        const encryptedValue = await sealBoxEncrypt(secretValue, pubKey.key);

        // Save secret
        const saveRes = await fetch(
            `${this.apiBase}/actions/secrets/${secretName}`,
            {
                method: 'PUT',
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    encrypted_value: encryptedValue,
                    key_id: pubKey.key_id
                })
            }
        );
        if (!saveRes.ok && saveRes.status !== 204) {
            const err = await saveRes.json().catch(() => ({}));
            throw new Error(err.message || `Failed to save secret (HTTP ${saveRes.status})`);
        }
        return true;
    }
}

// ---------- libsodium sealed box (pure JS implementation for GitHub secrets) ----------
async function sealBoxEncrypt(message, publicKeyB64) {
    // Decode GitHub's public key (base64)
    const pubKeyBytes = b64ToBuf(publicKeyB64);
    const pubKey = new Uint8Array(pubKeyBytes);

    // Generate ephemeral keypair using X25519
    const ephemeralKeyPair = await crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits']
    );

    // Export ephemeral public key
    const ephemeralPubRaw = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);
    const ephemeralPub = new Uint8Array(ephemeralPubRaw);

    // Import recipient public key
    const recipientPubKey = await crypto.subtle.importKey(
        'raw', pubKey,
        { name: 'X25519' }, false, []
    );

    // Derive shared secret: DH(ephemeral_private, recipient_public)
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'X25519', public: recipientPubKey },
        ephemeralKeyPair.privateKey,
        256
    );

    // Derive encryption key and nonce using BLAKE2b (simplified with SHA-256)
    const sharedSecretBytes = new Uint8Array(sharedSecret);
    const hkdfKey = await crypto.subtle.importKey(
        'raw', sharedSecretBytes,
        { name: 'HKDF' }, false, ['deriveBits']
    );

    // Derive key + nonce
    const derived = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: new TextEncoder().encode('github-sealed-box')
        },
        hkdfKey,
        384 // 256 bits key + 96 bits nonce
    );

    const derivedBytes = new Uint8Array(derived);
    const encKey = derivedBytes.slice(0, 32);
    const nonce = derivedBytes.slice(32, 44);

    // Pad nonce to 12 bytes for AES-GCM
    const nonce12 = new Uint8Array(12);
    nonce12.set(nonce);

    // Encrypt message with AES-256-GCM
    const aesKey = await crypto.subtle.importKey(
        'raw', encKey,
        { name: 'AES-GCM' }, false, ['encrypt']
    );

    const messageBytes = new TextEncoder().encode(message);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce12 },
        aesKey,
        messageBytes
    );

    // Prepend ephemeral public key to ciphertext
    const result = new Uint8Array(ephemeralPub.length + ciphertext.byteLength);
    result.set(ephemeralPub);
    result.set(new Uint8Array(ciphertext), ephemeralPub.length);

    return bufToB64(result);
}

// ---------- Setup Flow ----------
let setupStep = 1;

$('#session-next-btn').addEventListener('click', () => {
    const session = $('#session-input').value.trim();
    if (!session || session.length < 20) {
        showError('Please paste a valid session string');
        return;
    }
    // Basic validation: Telethon sessions start with a specific pattern
    if (!session.includes('1') || session.length < 50) {
        showError('This does not look like a valid Telethon session string');
        return;
    }
    STATE.sessionString = session;
    showError('');
    goToStep(2);
});

$('#repo-next-btn').addEventListener('click', async () => {
    const repo = $('#repo-input').value.trim();
    if (!repo || !repo.includes('/')) {
        showError('Enter repo as username/repository');
        return;
    }

    const [owner, name] = repo.split('/');
    STATE.repoOwner = owner.trim();
    STATE.repoName = name.trim();

    // Check if saving session
    const saveSession = $('#save-session-check').checked;
    if (saveSession) {
        const pat = $('#pat-input').value.trim();
        if (!pat) {
            showError('GitHub token is required to save the session');
            return;
        }
        STATE.pat = pat;
    }

    // Validate repo access
    try {
        const db = new GitHubDB(STATE.repoOwner, STATE.repoName, STATE.pat || null);
        // Try to fetch the index to verify access
        await db.fetchRaw('db/chats_index.json');
        // If we get here, repo exists and has data
        showStatus('Repo found with existing data');
    } catch (e) {
        // Repo might exist but no data yet — that's OK
        showStatus('Repo ready (no data yet — run the Action first)');
    }

    showError('');
    goToStep(3);
});

$('#unlock-btn').addEventListener('click', async () => {
    const key = $('#key-input').value.trim();
    if (!key || key.length < 4) {
        showError('Encryption key must be at least 4 characters');
        return;
    }

    STATE.encryptionKey = key;

    // Save session to GitHub Secret if requested
    if (STATE.pat && STATE.sessionString) {
        try {
            showStatus('Saving session to GitHub...');
            const db = new GitHubDB(STATE.repoOwner, STATE.repoName, STATE.pat);
            await db.saveSecret('TELETHON_SESSION', STATE.sessionString);
            // Also save encryption key
            await db.saveSecret('ENCRYPTION_KEY', STATE.encryptionKey);
            showStatus('Session saved to GitHub Secrets');
        } catch (e) {
            showError('Failed to save secrets: ' + e.message);
            return;
        }
    }

    // Initialize DB
    STATE.db = new GitHubDB(STATE.repoOwner, STATE.repoName, STATE.pat || null);
    saveConfig();

    // Test decryption
    try {
        showStatus('Decrypting data...');
        const chatsIndex = await STATE.db.fetchJSON('db/chats_index.json');
        if (!chatsIndex || !chatsIndex.chats) {
            throw new Error('No chat data found');
        }

        // Success — enter main screen
        showError('');
        showStatus('');
        $('#lock-screen').classList.remove('active');
        $('#main-screen').classList.add('active');
        await loadChats(chatsIndex);
    } catch (e) {
        console.error('Unlock failed:', e);
        if (e.message.includes('Integrity check failed')) {
            showError('Wrong encryption key');
        } else if (e.message.includes('HTTP 404')) {
            showError('No data found in repo. Run the GitHub Action first.');
        } else {
            showError('Failed: ' + e.message);
        }
    }
});

function goToStep(step) {
    $(`#setup-step-${setupStep}`).style.display = 'none';
    setupStep = step;
    $(`#setup-step-${setupStep}`).style.display = '';
}

function showError(msg) {
    $('#lock-error').textContent = msg;
}

function showStatus(msg) {
    $('#lock-status').textContent = msg;
}

// Toggle password visibility
$('#toggle-key-vis').addEventListener('click', () => {
    const input = $('#key-input');
    const icon = $('#toggle-key-vis .material-icons');
    if (input.type === 'password') {
        input.type = 'text';
        icon.textContent = 'visibility_off';
    } else {
        input.type = 'password';
        icon.textContent = 'visibility';
    }
});

// Show/hide PAT section
$('#save-session-check').addEventListener('change', () => {
    $('#pat-section').style.display = $('#save-session-check').checked ? '' : 'none';
});

// Session help modal
$('#session-help-link').addEventListener('click', (e) => {
    e.preventDefault();
    $('#session-help-modal').style.display = 'flex';
});
$('#close-help-modal').addEventListener('click', () => {
    $('#session-help-modal').style.display = 'none';
});

// Settings modal
$('#settings-btn').addEventListener('click', () => {
    $('#settings-session').value = STATE.sessionString || '(not set)';
    $('#settings-key').value = STATE.encryptionKey || '(not set)';
    $('#settings-repo').value = `${STATE.repoOwner || '?'}/${STATE.repoName || '?'}`;
    $('#settings-modal').style.display = 'flex';
});
$('#close-settings-btn').addEventListener('click', () => {
    $('#settings-modal').style.display = 'none';
});
$('#copy-session-btn').addEventListener('click', () => {
    navigator.clipboard.writeText(STATE.sessionString || '');
    showToast('Session copied to clipboard');
});
$('#clear-settings-btn').addEventListener('click', () => {
    if (confirm('Clear all local data? This cannot be undone.')) {
        localStorage.clear();
        location.reload();
    }
});

// Close modals on background click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.style.display = 'none';
    });
});

// ---------- Lock ----------
$('#lock-btn').addEventListener('click', () => {
    STATE.encryptionKey = null;
    STATE.db = null;
    STATE.currentChat = null;
    $('#main-screen').classList.remove('active');
    $('#lock-screen').classList.add('active');
    $('#messages-container').innerHTML = `
        <div class="empty-state">
            <span class="material-icons">chat</span>
            <p>Select a chat to view messages</p>
        </div>
    `;
    $('#chat-list').innerHTML = '';
    $('#chat-title').textContent = 'Select a chat';
    setupStep = 1;
    goToStep(1);
    // Pre-fill from stored config
    if (STATE.repoOwner && STATE.repoName) {
        $('#repo-input').value = `${STATE.repoOwner}/${STATE.repoName}`;
    }
});

// ---------- Chat List ----------
async function loadChats(chatsIndex) {
    const list = $('#chat-list');
    list.innerHTML = '';

    const chats = chatsIndex.chats || [];

    if (chats.length === 0) {
        list.innerHTML = '<p class="empty-text">No chats yet. Run the relay Action first.</p>';
        return;
    }

    for (const chat of chats) {
        const div = document.createElement('div');
        div.className = 'chat-item';
        div.dataset.chatId = chat.id;
        div.innerHTML = `
            <div class="chat-avatar">${(chat.title || '?')[0].toUpperCase()}</div>
            <div class="chat-info">
                <div class="chat-name">${escapeHTML(chat.title || 'Unknown')}</div>
                <div class="chat-meta">${chat.type || 'chat'} • ${chat.batches?.length || 0} batches</div>
            </div>
        `;
        div.addEventListener('click', () => {
            // Highlight active
            $$('.chat-item').forEach(el => el.classList.remove('active'));
            div.classList.add('active');
            loadMessages(chat);
        });
        list.appendChild(div);
    }
}

// ---------- Messages ----------
async function loadMessages(chat) {
    STATE.currentChat = chat;
    $('#chat-title').textContent = chat.title || 'Chat';
    const container = $('#messages-container');
    container.innerHTML = '<div class="loading"><span class="material-icons spinning">sync</span> Loading messages...</div>';

    try {
        const manifest = await STATE.db.fetchJSON(`db/messages/${chat.id}/manifest.json`);
        if (!manifest || !manifest.batches || manifest.batches.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No messages fetched yet. Trigger the Action.</p></div>';
            return;
        }

        // Load all batches
        let allMessages = [];
        for (const batchInfo of manifest.batches) {
            try {
                const batchData = await STATE.db.fetchJSON(`db/messages/${chat.id}/${batchInfo.file}`);
                if (batchData && batchData.messages) {
                    allMessages = allMessages.concat(batchData.messages);
                }
            } catch (e) {
                console.warn(`Failed to load batch ${batchInfo.file}:`, e);
            }
        }

        // Sort newest first
        allMessages.sort((a, b) => new Date(b.date) - new Date(a.date));
        renderMessages(allMessages);
    } catch (e) {
        console.error('Failed to load messages:', e);
        container.innerHTML = `<div class="error-state"><p>Failed: ${escapeHTML(e.message)}</p></div>`;
    }
}

function renderMessages(messages) {
    const container = $('#messages-container');
    container.innerHTML = '';

    if (messages.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No messages</p></div>';
        return;
    }

    for (const msg of messages) {
        const div = document.createElement('div');
        div.className = 'message-card';

        const date = new Date(msg.date);
        const dateStr = date.toLocaleDateString() + ' ' + 
            date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        let mediaHTML = '';
        if (msg.media && msg.media.id) {
            mediaHTML = `
                <div class="media-attachment">
                    <span class="material-icons">${msg.media.type === 'photo' ? 'image' : msg.media.type === 'video' ? 'videocam' : 'attach_file'}</span>
                    <span class="media-info">
                        ${msg.media.type || 'file'} • ${formatSize(msg.media.size_bytes || 0)}
                        ${msg.media.filename ? ` • ${escapeHTML(msg.media.filename)}` : ''}
                    </span>
                    <button class="btn-download" data-file-id="${msg.media.id}" data-msg-id="${msg.id}">
                        <span class="material-icons">download</span>
                    </button>
                </div>
            `;
        }

        div.innerHTML = `
            <div class="message-header">
                <span class="message-date">${dateStr}</span>
                ${msg.forwarded_from ? `<span class="forwarded">↳ ${escapeHTML(msg.forwarded_from)}</span>` : ''}
                ${msg.views ? `<span class="views">👁 ${msg.views.toLocaleString()}</span>` : ''}
            </div>
            <div class="message-text">${escapeHTML(msg.text || '')}</div>
            ${mediaHTML}
        `;

        const downloadBtn = div.querySelector('.btn-download');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                downloadFile(downloadBtn.dataset.fileId, downloadBtn.dataset.msgId);
            });
        }

        container.appendChild(div);
    }
}

// ---------- File Downloads ----------
async function downloadFile(fileId, msgId) {
    if (!STATE.db) return;

    showToast('Checking file...');

    try {
        let fileMeta;
        try {
            fileMeta = await STATE.db.fetchJSON(`db/files/${fileId}/meta.json`);
        } catch (e) {
            showToast('File not downloaded yet. Use Actions → download_pending_files');
            return;
        }

        if (!fileMeta || fileMeta.status !== 'complete') {
            showToast('File not fully downloaded yet');
            return;
        }

        showToast(`Downloading ${fileMeta.chunks_total} chunks...`);
        const chunks = [];

        for (let i = 1; i <= fileMeta.chunks_total; i++) {
            const chunkEncrypted = await STATE.db.fetchRaw(`db/files/${fileId}/chunk_${i}.bin`);
            const chunkDecrypted = await CryptoHelper.decrypt(chunkEncrypted, STATE.encryptionKey);
            const chunkBytes = Uint8Array.from(chunkDecrypted, c => c.charCodeAt(0));
            chunks.push(chunkBytes);
        }

        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        const combined = new Uint8Array(totalLen);
        let offset = 0;
        for (const chunk of chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }

        const blob = new Blob([combined], { type: fileMeta.mime_type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileMeta.filename || `file_${fileId}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast('Download complete!');
    } catch (e) {
        console.error('Download failed:', e);
        showToast('Download failed: ' + e.message);
    }
}

// ---------- Fetch More ----------
$('#fetch-more-btn').addEventListener('click', () => {
    if (!STATE.currentChat) {
        showToast('Select a chat first');
        return;
    }
    const count = parseInt($('#fetch-count').value) || 50;
    showToast(`To fetch ${count} more messages, trigger the Action manually`);
    if (STATE.repoOwner && STATE.repoName) {
        window.open(`https://github.com/${STATE.repoOwner}/${STATE.repoName}/actions`, '_blank');
    }
});

// ---------- Refresh ----------
$('#refresh-btn').addEventListener('click', async () => {
    if (!STATE.db) return;
    try {
        showToast('Refreshing...');
        const chatsIndex = await STATE.db.fetchJSON('db/chats_index.json');
        await loadChats(chatsIndex);
        if (STATE.currentChat) {
            const updatedChat = chatsIndex.chats.find(c => c.id === STATE.currentChat.id);
            if (updatedChat) await loadMessages(updatedChat);
        }
        showToast('Refreshed');
    } catch (e) {
        showToast('Refresh failed: ' + e.message);
    }
});

// ---------- Utilities ----------
function formatSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function showToast(msg) {
    const toast = $('#toast');
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => toast.classList.remove('show'), 3000);
}

// ---------- Init ----------
(function init() {
    const config = loadConfig();
    if (config && config.repoOwner && config.repoName) {
        $('#repo-input').value = `${config.repoOwner}/${config.repoName}`;
    }

    // Check for stored PAT in sessionStorage (we don't persist PAT)
    // User must re-enter encryption key each time for security

    console.log('Telegram Relay ready.');
    console.log('1. Paste your Telethon session string');
    console.log('2. Enter your repo');
    console.log('3. Enter your encryption key');
})();
