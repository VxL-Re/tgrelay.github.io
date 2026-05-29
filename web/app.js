// ---------- Crypto ----------
const ENCRYPTION_KEY = { current: null };
const REPO_RAW_BASE = ''; // Will be set based on repo

class CryptoHelper {
    static async deriveKey(password, salt) {
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
    }

    static async decrypt(packageStr, password) {
        const pkg = JSON.parse(packageStr);
        const salt = this.base64ToBuffer(pkg.salt);
        const iv = this.base64ToBuffer(pkg.iv);
        const tag = this.base64ToBuffer(pkg.tag);
        const ciphertext = this.base64ToBuffer(pkg.data);

        const key = await this.deriveKey(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv },
            key,
            ciphertext
        );

        // Remove PKCS7 padding
        const data = new Uint8Array(decrypted);
        const padLength = data[data.length - 1];
        const unpadded = data.slice(0, data.length - padLength);

        // Verify SHA-256 tag
        const computedTag = await crypto.subtle.digest('SHA-256', unpadded);
        const computedTagArr = new Uint8Array(computedTag);
        const tagArr = new Uint8Array(tag);

        if (computedTagArr.length !== tagArr.length || 
            !computedTagArr.every((v, i) => v === tagArr[i])) {
            throw new Error('Integrity check failed - wrong password or corrupted data');
        }

        return new TextDecoder().decode(unpadded);
    }

    static base64ToBuffer(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }
}

// ---------- GitHub API ----------
class GitHubDB {
    constructor(repoUrl, token = null) {
        // Parse username/repo from URL
        const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
        if (!match) throw new Error('Invalid GitHub repo URL');
        this.owner = match[1];
        this.repo = match[2];
        this.token = token;
        this.apiBase = `https://api.github.com/repos/${this.owner}/${this.repo}/contents`;
        this.rawBase = `https://raw.githubusercontent.com/${this.owner}/${this.repo}/main`;
    }

    async fetchFile(path) {
        const url = `${this.rawBase}/${path}`;
        const response = await fetch(url, {
            cache: 'no-cache',
            headers: this.token ? { 'Authorization': `token ${this.token}` } : {}
        });
        if (!response.ok) throw new Error(`Failed to fetch ${path}: ${response.status}`);
        return response.text();
    }

    async fetchJSON(path, encrypted = true) {
        const content = await this.fetchFile(path);
        if (encrypted) {
            const decrypted = await CryptoHelper.decrypt(content, ENCRYPTION_KEY.current);
            return JSON.parse(decrypted);
        }
        return JSON.parse(content);
    }

    async listDirectory(path) {
        const url = `${this.apiBase}/${path}`;
        const response = await fetch(url, {
            headers: this.token ? { 'Authorization': `token ${this.token}` } : {}
        });
        if (!response.ok) return [];
        const data = await response.json();
        return data.filter(f => f.type === 'file').map(f => f.name);
    }
}

// ---------- App State ----------
let db = null;
let currentChat = null;

// ---------- DOM ----------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ---------- Lock Screen ----------
$('#unlock-btn').addEventListener('click', unlock);
$('#key-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') unlock();
});

async function unlock() {
    const key = $('#key-input').value.trim();
    const repoUrl = localStorage.getItem('relay_repo_url') || 
                    prompt('GitHub repo URL (username/repo):') || 
                    '';

    if (!key || !repoUrl) {
        $('#lock-error').textContent = 'Please enter both key and repo URL';
        return;
    }

    // Store repo URL
    localStorage.setItem('relay_repo_url', repoUrl);

    // Test decryption by trying to load chats index
    try {
        db = new GitHubDB(repoUrl.includes('github.com') ? repoUrl : `https://github.com/${repoUrl}`);
        ENCRYPTION_KEY.current = key;

        const chatsIndex = await db.fetchJSON('db/chats_index.json');
        if (!chatsIndex || !chatsIndex.chats) {
            throw new Error('Invalid data structure');
        }

        // Success!
        $('#lock-screen').classList.remove('active');
        $('#main-screen').classList.add('active');
        $('#lock-error').textContent = '';

        await loadChats(chatsIndex);
    } catch (e) {
        console.error('Unlock failed:', e);
        $('#lock-error').textContent = 'Wrong key, invalid repo, or no data yet. Check console.';
        ENCRYPTION_KEY.current = null;
    }
}

$('#lock-btn').addEventListener('click', () => {
    ENCRYPTION_KEY.current = null;
    currentChat = null;
    $('#main-screen').classList.remove('active');
    $('#lock-screen').classList.add('active');
    $('#messages-container').innerHTML = `
        <div class="empty-state">
            <span class="material-icons">chat</span>
            <p>Select a chat to view messages</p>
        </div>
    `;
    $('#chat-list').innerHTML = '';
});

// ---------- Chat List ----------
async function loadChats(chatsIndex) {
    const list = $('#chat-list');
    list.innerHTML = '';

    const chats = chatsIndex.chats || [];
    
    if (chats.length === 0) {
        list.innerHTML = '<p class="empty-text">No chats yet. Run the relay first.</p>';
        return;
    }

    for (const chat of chats) {
        const div = document.createElement('div');
        div.className = 'chat-item';
        div.dataset.chatId = chat.id;
        div.innerHTML = `
            <div class="chat-avatar">${(chat.title || '?')[0].toUpperCase()}</div>
            <div class="chat-info">
                <div class="chat-name">${chat.title || 'Unknown'}</div>
                <div class="chat-meta">${chat.type} • ${chat.batches?.length || 0} batches</div>
            </div>
        `;
        div.addEventListener('click', () => loadMessages(chat));
        list.appendChild(div);
    }
}

// ---------- Messages ----------
async function loadMessages(chat) {
    currentChat = chat;
    $('#chat-title').textContent = chat.title || 'Chat';
    const container = $('#messages-container');
    container.innerHTML = '<div class="loading"><span class="material-icons spinning">sync</span> Loading...</div>';

    try {
        // Load manifest
        const manifest = await db.fetchJSON(`db/messages/${chat.id}/manifest.json`);
        if (!manifest || !manifest.batches || manifest.batches.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No messages fetched yet</p></div>';
            return;
        }

        // Load all batches
        let allMessages = [];
        for (const batchInfo of manifest.batches) {
            const batchData = await db.fetchJSON(`db/messages/${chat.id}/${batchInfo.file}`);
            if (batchData && batchData.messages) {
                allMessages = allMessages.concat(batchData.messages);
            }
        }

        // Sort by date descending
        allMessages.sort((a, b) => new Date(b.date) - new Date(a.date));

        renderMessages(allMessages, chat);
    } catch (e) {
        console.error('Failed to load messages:', e);
        container.innerHTML = `<div class="error-state"><p>Failed to load: ${e.message}</p></div>`;
    }
}

function renderMessages(messages, chat) {
    const container = $('#messages-container');
    container.innerHTML = '';

    if (messages.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No messages</p></div>';
        return;
    }

    for (const msg of messages) {
        const div = document.createElement('div');
        div.className = 'message-card';
        div.dataset.msgId = msg.id;

        const date = new Date(msg.date);
        const dateStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        let mediaHTML = '';
        if (msg.media) {
            const media = msg.media;
            const fileMetaExists = media.id ? true : false; // Could check downloads panel
            
            mediaHTML = `
                <div class="media-attachment">
                    <span class="material-icons">${media.type === 'photo' ? 'image' : media.type === 'video' ? 'videocam' : 'attach_file'}</span>
                    <span class="media-info">
                        ${media.type} • ${formatSize(media.size_bytes || 0)}
                        ${media.filename ? ` • ${media.filename}` : ''}
                    </span>
                    <button class="btn-download" data-file-id="${media.id}" data-msg-id="${msg.id}">
                        <span class="material-icons">download</span>
                    </button>
                </div>
            `;
        }

        div.innerHTML = `
            <div class="message-header">
                <span class="message-date">${dateStr}</span>
                ${msg.forwarded_from ? `<span class="forwarded">↳ ${msg.forwarded_from}</span>` : ''}
                ${msg.views ? `<span class="views">👁 ${msg.views}</span>` : ''}
            </div>
            <div class="message-text">${escapeHTML(msg.text || '')}</div>
            ${mediaHTML}
        `;

        // Add download button handler
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
    if (!currentChat) return;
    
    showToast('Checking file...');
    
    try {
        // Check if file meta exists
        let fileMeta;
        try {
            fileMeta = await db.fetchJSON(`db/files/${fileId}/meta.json`);
        } catch (e) {
            showToast('File not downloaded yet. Trigger "download_pending_files" from Actions.');
            return;
        }

        if (!fileMeta || fileMeta.status !== 'complete') {
            showToast('File not fully downloaded yet.');
            return;
        }

        // Fetch and reassemble chunks
        showToast(`Downloading ${fileMeta.chunks_total} chunks...`);
        const chunks = [];
        
        for (let i = 1; i <= fileMeta.chunks_total; i++) {
            const chunkEncrypted = await db.fetchFile(`db/files/${fileId}/chunk_${i}.bin`);
            const chunkDecrypted = await CryptoHelper.decrypt(chunkEncrypted, ENCRYPTION_KEY.current);
            const chunkBytes = new Uint8Array(chunkDecrypted.split('').map(c => c.charCodeAt(0)));
            chunks.push(chunkBytes);
        }

        // Combine chunks
        const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
        const combined = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }

        // Trigger download
        const blob = new Blob([combined], { type: fileMeta.mime_type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileMeta.filename || `file_${fileId}`;
        a.click();
        URL.revokeObjectURL(url);
        
        showToast('Download complete!');
    } catch (e) {
        console.error('Download failed:', e);
        showToast('Download failed: ' + e.message);
    }
}

// ---------- Fetch More ----------
$('#fetch-more-btn').addEventListener('click', () => {
    if (!currentChat) {
        showToast('Select a chat first');
        return;
    }
    const count = parseInt($('#fetch-count').value) || 50;
    showToast(`To fetch ${count} more messages, trigger the GitHub Action manually with chat_id=${currentChat.id}&message_limit=${count}`);
    // Could also open Actions page
    window.open(`https://github.com/${db.owner}/${db.repo}/actions`, '_blank');
});

// ---------- Refresh ----------
$('#refresh-btn').addEventListener('click', async () => {
    if (!ENCRYPTION_KEY.current) return;
    try {
        const chatsIndex = await db.fetchJSON('db/chats_index.json');
        await loadChats(chatsIndex);
        if (currentChat) {
            // Reload current chat
            const updatedChat = chatsIndex.chats.find(c => c.id === currentChat.id);
            if (updatedChat) await loadMessages(updatedChat);
        }
        showToast('Refreshed');
    } catch (e) {
        showToast('Refresh failed: ' + e.message);
    }
});

// ---------- Utilities ----------
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function showToast(msg) {
    const toast = $('#toast');
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

// ---------- Init ----------
console.log('Telegram Relay ready. Enter your encryption key.');
