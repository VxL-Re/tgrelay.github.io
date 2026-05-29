#!/usr/bin/env python3
"""
Telegram Relay - Fetches messages and media, encrypts, stores in db/
"""
import os
import json
import base64
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from telethon import TelegramClient
from telethon.sessions import StringSession
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.exceptions import InvalidTag

# ---------- Config ----------
API_ID = int(os.environ['API_ID'])
API_HASH = os.environ['API_HASH']
SESSION = os.environ['TELETHON_SESSION']
ENCRYPTION_KEY = os.environ['ENCRYPTION_KEY']  # Password/passphrase
FETCH_MODE = os.environ.get('FETCH_MODE', 'fetch_new')
CHAT_IDS = os.environ.get('CHAT_IDS', '')
MESSAGE_LIMIT = int(os.environ.get('MESSAGE_LIMIT', 50))
BATCH_SIZE = 50
CHUNK_SIZE = 512 * 1024  # 512KB chunks for files
MAX_FILE_SIZE = 50 * 1024 * 1024  # Skip files > 50MB

DB_DIR = Path('db')
MESSAGES_DIR = DB_DIR / 'messages'
FILES_DIR = DB_DIR / 'files'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)


# ---------- Encryption ----------
def derive_key(password: str, salt: bytes = None) -> tuple:
    """Derive AES-256 key from password. Returns (key, salt)."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def encrypt_data(data: bytes, password: str) -> str:
    """Encrypt bytes with password. Returns base64 JSON string with iv, salt, tag, ciphertext."""
    key, salt = derive_key(password)
    iv = os.urandom(16)

    # Pad data
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Create a simple integrity tag
    tag = hashlib.sha256(data).digest()

    package = {
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(tag).decode(),
        'data': base64.b64encode(ciphertext).decode(),
        'v': 1  # version
    }
    return json.dumps(package)


def encrypt_json(obj: dict, password: str) -> str:
    """Encrypt a JSON-serializable object."""
    return encrypt_data(json.dumps(obj, ensure_ascii=False, default=str).encode('utf-8'), password)


def decrypt_data(package_str: str, password: str) -> bytes:
    """Decrypt data encrypted with encrypt_data."""
    package = json.loads(package_str)
    salt = base64.b64decode(package['salt'])
    iv = base64.b64decode(package['iv'])
    tag = base64.b64decode(package['tag'])
    ciphertext = base64.b64decode(package['data'])

    key, _ = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Verify integrity
    computed_tag = hashlib.sha256(data).digest()
    if computed_tag != tag:
        raise InvalidTag("Data integrity check failed - wrong password or corrupted data")

    return data


# ---------- Helpers ----------
def save_json(path: Path, data: dict, encrypt: bool = True):
    """Save JSON to file, optionally encrypted."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if encrypt:
        content = encrypt_json(data, ENCRYPTION_KEY)
    else:
        content = json.dumps(data, ensure_ascii=False, default=str, indent=2)
    path.write_text(content, encoding='utf-8')
    log.info(f"Saved: {path}")


def load_json(path: Path, encrypted: bool = True) -> dict:
    """Load JSON from file, optionally decrypting."""
    if not path.exists():
        return None
    content = path.read_text(encoding='utf-8')
    if encrypted:
        decrypted = decrypt_data(content, ENCRYPTION_KEY)
        return json.loads(decrypted)
    return json.loads(content)


def load_chats_index() -> dict:
    """Load chats index (stored encrypted)."""
    return load_json(DB_DIR / 'chats_index.json') or {'chats': [], 'last_updated': None}


def save_chats_index(index: dict):
    """Save chats index (encrypted)."""
    index['last_updated'] = datetime.now(timezone.utc).isoformat()
    save_json(DB_DIR / 'chats_index.json', index)


# ---------- Fetch Logic ----------
async def fetch_chats(client: TelegramClient):
    """Fetch all dialogs and update index."""
    log.info("Fetching chat list...")
    index = {'chats': [], 'last_updated': datetime.now(timezone.utc).isoformat()}

    async for dialog in client.iter_dialogs(limit=200):
        entity = dialog.entity
        chat = {
            'id': dialog.id,
            'title': dialog.name,
            'username': getattr(entity, 'username', None) or '',
            'type': 'channel' if dialog.is_channel else 'group' if dialog.is_group else 'user',
            'last_message_id': dialog.message.id if dialog.message else 0,
            'fetched_until_id': 0,
            'batches': []
        }

        # Load existing manifest to preserve fetched_until_id and batches
        manifest = load_chat_manifest(dialog.id)
        if manifest:
            chat['fetched_until_id'] = manifest.get('fetched_until_id', 0)
            chat['batches'] = manifest.get('batches', [])

        index['chats'].append(chat)

    save_chats_index(index)
    log.info(f"Saved {len(index['chats'])} chats to index")


def load_chat_manifest(chat_id: int) -> dict:
    """Load manifest for a chat."""
    return load_json(MESSAGES_DIR / str(chat_id) / 'manifest.json')


def save_chat_manifest(chat_id: int, manifest: dict):
    """Save manifest for a chat."""
    manifest['last_updated'] = datetime.now(timezone.utc).isoformat()
    save_json(MESSAGES_DIR / str(chat_id) / 'manifest.json', manifest)


async def fetch_messages(client: TelegramClient, chat_id: int, limit: int = 50):
    """Fetch messages for a specific chat."""
    log.info(f"Fetching up to {limit} messages from chat {chat_id}")

    manifest = load_chat_manifest(chat_id) or {
        'chat_id': chat_id,
        'batches': [],
        'fetched_until_id': 0,
        'total_fetched': 0
    }

    fetched_until = manifest.get('fetched_until_id', 0)
    messages_data = []
    media_messages = []
    batch_num = len(manifest['batches']) + 1

    async for message in client.iter_messages(chat_id, limit=limit, offset_id=0 if fetched_until == 0 else fetched_until):
        if message.id <= fetched_until and fetched_until > 0:
            continue

        msg_dict = {
            'id': message.id,
            'date': message.date.isoformat(),
            'sender_id': message.sender_id,
            'text': message.text or message.message or '',
            'reply_to': message.reply_to.reply_to_msg_id if message.reply_to else None,
            'forwarded_from': message.forward.chat.title if message.forward and message.forward.chat else None,
            'views': getattr(message, 'views', 0) or 0
        }

        # Handle media
        if message.media:
            media_info = await extract_media_info(client, message)
            msg_dict['media'] = media_info
            if media_info and media_info.get('size_bytes', 0) < MAX_FILE_SIZE:
                media_messages.append({'msg_id': message.id, 'media': media_info})
        else:
            msg_dict['media'] = None

        messages_data.append(msg_dict)

    if not messages_data:
        log.info(f"No new messages for chat {chat_id}")
        return

    # Save batch
    batch_file = f'batch_{batch_num}.json'
    batch = {
        'batch_id': batch_num,
        'chat_id': chat_id,
        'message_count': len(messages_data),
        'first_id': messages_data[-1]['id'],
        'last_id': messages_data[0]['id'],
        'has_media': [m['id'] for m in messages_data if m.get('media')]
    }

    batch_dir = MESSAGES_DIR / str(chat_id)
    save_json(batch_dir / batch_file, {'batch': batch, 'messages': messages_data})

    # Update manifest
    manifest['batches'].append(batch)
    manifest['fetched_until_id'] = messages_data[0]['id']
    manifest['total_fetched'] = manifest.get('total_fetched', 0) + len(messages_data)
    save_chat_manifest(chat_id, manifest)

    log.info(f"Saved {len(messages_data)} messages to batch {batch_num}")


async def extract_media_info(client: TelegramClient, message) -> dict:
    """Extract media metadata from a message."""
    try:
        if hasattr(message.media, 'photo'):
            # Photo - get the largest size
            photo = message.media.photo
            if hasattr(photo, 'sizes') and photo.sizes:
                largest = photo.sizes[-1]
                if hasattr(largest, 'sizes'):
                    largest = largest.sizes[-1]
                return {
                    'type': 'photo',
                    'size_bytes': getattr(largest, 'size', 0) or photo.sizes[-1].sizes[-1].size if hasattr(photo.sizes[-1], 'sizes') else 0,
                    'mime_type': 'image/jpeg',
                    'id': photo.id,
                    'dc_id': photo.dc_id
                }
        elif hasattr(message.media, 'document'):
            doc = message.media.document
            return {
                'type': 'document',
                'size_bytes': doc.size,
                'mime_type': doc.mime_type,
                'id': doc.id,
                'dc_id': doc.dc_id,
                'filename': next((attr.file_name for attr in doc.attributes if hasattr(attr, 'file_name')), None)
            }
        elif hasattr(message.media, 'video'):
            return {
                'type': 'video',
                'size_bytes': message.media.video.size,
                'id': message.media.video.id,
                'dc_id': message.media.video.dc_id
            }
    except Exception as e:
        log.warning(f"Could not extract media info: {e}")
    return None


async def download_pending_files(client: TelegramClient):
    """Download files that have been marked for download but not yet fetched."""
    log.info("Checking for pending file downloads...")

    # Walk through all message batches looking for pending files
    for chat_dir in MESSAGES_DIR.iterdir():
        if not chat_dir.is_dir():
            continue
        manifest = load_chat_manifest(int(chat_dir.name))
        if not manifest:
            continue

        for batch in manifest.get('batches', []):
            batch_file = chat_dir / batch['file']
            batch_data = load_json(batch_file)
            if not batch_data:
                continue

            for msg in batch_data.get('messages', []):
                media = msg.get('media')
                if not media or not media.get('id'):
                    continue

                file_id = media['id']
                file_dir = FILES_DIR / str(file_id)
                file_meta_path = file_dir / 'meta.json'

                # Check if already downloaded
                if file_meta_path.exists():
                    file_meta = load_json(file_meta_path)
                    if file_meta and file_meta.get('status') == 'complete':
                        continue

                # Download the file
                log.info(f"Downloading file {file_id} from message {msg['id']}")
                try:
                    message = await client.get_messages(int(chat_dir.name), ids=msg['id'])
                    if not message or not message.media:
                        continue

                    file_path = file_dir / 'original.bin'
                    file_dir.mkdir(parents=True, exist_ok=True)

                    await client.download_media(message, file=str(file_path))

                    # Split into chunks
                    if file_path.exists():
                        file_size = file_path.stat().st_size
                        chunks_total = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

                        with open(file_path, 'rb') as f:
                            for i in range(chunks_total):
                                chunk_data = f.read(CHUNK_SIZE)
                                chunk_path = file_dir / f'chunk_{i+1}.bin'
                                # Encrypt chunk
                                encrypted_chunk = encrypt_data(chunk_data, ENCRYPTION_KEY)
                                chunk_path.write_text(encrypted_chunk, encoding='utf-8')

                        # Save meta
                        file_meta = {
                            'file_id': file_id,
                            'chat_id': int(chat_dir.name),
                            'message_id': msg['id'],
                            'filename': media.get('filename') or f'file_{file_id}',
                            'size_bytes': file_size,
                            'mime_type': media.get('mime_type', 'unknown'),
                            'chunks_total': chunks_total,
                            'chunks_downloaded': list(range(1, chunks_total + 1)),
                            'chunk_size': CHUNK_SIZE,
                            'status': 'complete',
                            'downloaded_at': datetime.now(timezone.utc).isoformat()
                        }
                        save_json(file_meta_path, file_meta, encrypt=True)

                        # Remove original
                        file_path.unlink()
                        log.info(f"Downloaded and chunked file {file_id}: {chunks_total} chunks")

                except Exception as e:
                    log.error(f"Failed to download file {file_id}: {e}")


# ---------- Main ----------
async def main():
    client = TelegramClient(StringSession(SESSION), API_ID, API_HASH)

    async with client:
        me = await client.get_me()
        log.info(f"Connected as {me.first_name} (@{me.username})")

        if FETCH_MODE == 'fetch_chats_only':
            await fetch_chats(client)

        elif FETCH_MODE == 'download_pending_files':
            await download_pending_files(client)

        elif FETCH_MODE == 'fetch_new':
            # Always update chats first
            await fetch_chats(client)

            # Fetch messages for specified or all chats
            index = load_chats_index()
            target_chats = []

            if CHAT_IDS:
                chat_ids = [int(c.strip()) for c in CHAT_IDS.split(',') if c.strip()]
                target_chats = [c for c in index['chats'] if c['id'] in chat_ids]
            else:
                # Fetch from all chats that have messages
                target_chats = [c for c in index['chats'] if c.get('last_message_id', 0) > 0]

            for chat in target_chats[:20]:  # Limit to 20 chats per run
                await fetch_messages(client, chat['id'], MESSAGE_LIMIT)

        else:
            log.error(f"Unknown fetch mode: {FETCH_MODE}")


if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
