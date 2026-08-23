import base64
import hashlib
import os
import time
from dataclasses import dataclass, asdict

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MLKEM_ALGORITHM = 'ML-KEM-768'


@dataclass
class TraceStep:
    name: str
    algorithm: str
    status: str
    time_ms: float
    detail: str
    summary: str = ''
    input_label: str = ''
    output_label: str = ''
    why: str = ''

    def to_dict(self):
        return asdict(self)


def _ms(start_ns, end_ns):
    return round((end_ns - start_ns) / 1_000_000, 4)


def fingerprint(data: bytes, n=16) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def _decode_master_key(master_key_b64: str) -> bytes:
    if not master_key_b64 or master_key_b64 == 'replace_me':
        raise RuntimeError('SERVER_MASTER_KEY_B64 is missing. Run: python setup_env.py')
    try:
        key = base64.urlsafe_b64decode(master_key_b64.encode())
    except Exception as exc:
        raise RuntimeError('SERVER_MASTER_KEY_B64 is not valid base64.') from exc
    if len(key) != 32:
        raise RuntimeError('SERVER_MASTER_KEY_B64 must decode to exactly 32 bytes.')
    return key


def generate_user_mlkem_keypair():
    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    t1 = time.perf_counter_ns()
    return public_key, secret_key, _ms(t0, t1)


def wrap_user_secret_key(secret_key: bytes, email: str, master_key_b64: str):
    master_key = _decode_master_key(master_key_b64)
    nonce = os.urandom(12)
    aad = f'PQVault|user-key|v1|{email.strip().lower()}'.encode()
    wrapped = ChaCha20Poly1305(master_key).encrypt(nonce, secret_key, aad)
    return wrapped, nonce


def unwrap_user_secret_key(wrapped: bytes, nonce: bytes, email: str, master_key_b64: str):
    master_key = _decode_master_key(master_key_b64)
    aad = f'PQVault|user-key|v1|{email.strip().lower()}'.encode()
    return ChaCha20Poly1305(master_key).decrypt(nonce, wrapped, aad)


def derive_file_key(shared_secret: bytes, salt: bytes, file_uuid: str) -> bytes:
    info = f'PQVault|file-key|v1|{file_uuid}'.encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def build_aad(file_uuid: str, owner_id: int) -> bytes:
    return f'PQVault|file|v1|{file_uuid}|owner={owner_id}'.encode()


def encrypt_for_user(plaintext: bytes, public_key: bytes, owner_id: int, file_uuid: str):
    trace = []

    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as sender:
        kem_ciphertext, shared_secret = sender.encap_secret(public_key)
    t1 = time.perf_counter_ns()
    trace.append(TraceStep(
        'Create a shared secret', MLKEM_ALGORITHM, 'complete', _ms(t0, t1),
        f'Public-key fingerprint {fingerprint(public_key)}… → KEM ciphertext {len(kem_ciphertext)} bytes; shared secret hidden (fingerprint {fingerprint(shared_secret)}…).',
        'ML-KEM uses the user public key to create a fresh shared secret and a KEM ciphertext. The shared secret itself is never shown to the user.',
        'User ML-KEM public key + fresh randomness',
        f'Hidden shared secret + {len(kem_ciphertext)}-byte KEM ciphertext',
        'This establishes post-quantum key material without using RSA or elliptic-curve key exchange.'
    ))

    salt = os.urandom(16)
    t2 = time.perf_counter_ns()
    file_key = derive_file_key(shared_secret, salt, file_uuid)
    t3 = time.perf_counter_ns()
    trace.append(TraceStep(
        'Make a file-specific 256-bit key', 'HKDF-SHA256', 'complete', _ms(t2, t3),
        f'16-byte random salt {salt.hex()[:16]}… + shared secret → 32-byte key; key value hidden (fingerprint {fingerprint(file_key)}…).',
        'HKDF takes the shared secret, a random salt and this file context, then derives exactly one 32-byte key for file encryption.',
        'Hidden shared secret + 16-byte salt + file ID context',
        '32-byte (256-bit) file-encryption key',
        'The raw ML-KEM shared secret is not used directly as the ChaCha20-Poly1305 key.'
    ))

    nonce = os.urandom(12)
    aad = build_aad(file_uuid, owner_id)
    t4 = time.perf_counter_ns()
    encrypted = ChaCha20Poly1305(file_key).encrypt(nonce, plaintext, aad)
    t5 = time.perf_counter_ns()
    trace.append(TraceStep(
        'Encrypt the file and add a tamper seal', 'ChaCha20-Poly1305', 'complete', _ms(t4, t5),
        f'12-byte nonce {nonce.hex()} + 256-bit key → {len(encrypted)} encrypted bytes including authentication tag.',
        'ChaCha20 hides the file contents while Poly1305 creates an authentication tag that detects modification.',
        'Plain file bytes + 256-bit file key + 12-byte nonce',
        f'{len(encrypted)} encrypted bytes including authentication tag',
        'This provides both confidentiality and integrity. Modified ciphertext will fail authentication during download.'
    ))

    return {
        'encrypted': encrypted,
        'kem_ciphertext': kem_ciphertext,
        'salt': salt,
        'nonce': nonce,
        'trace': [step.to_dict() for step in trace],
        'timings': {
            'kem_encap_ms': trace[0].time_ms,
            'hkdf_ms': trace[1].time_ms,
            'encrypt_ms': trace[2].time_ms,
        },
    }


def decrypt_for_user(encrypted: bytes, kem_ciphertext: bytes, salt: bytes, nonce: bytes,
                     wrapped_secret_key: bytes, secret_key_nonce: bytes, email: str,
                     master_key_b64: str, owner_id: int, file_uuid: str):
    trace = []

    secret_key = unwrap_user_secret_key(
        wrapped_secret_key, secret_key_nonce, email, master_key_b64
    )

    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM, secret_key) as receiver:
        shared_secret = receiver.decap_secret(kem_ciphertext)
    t1 = time.perf_counter_ns()
    trace.append(TraceStep(
        'Recover the same shared secret', MLKEM_ALGORITHM, 'complete', _ms(t0, t1),
        f'KEM ciphertext + protected user secret key → same shared secret; value hidden (fingerprint {fingerprint(shared_secret)}…).',
        'ML-KEM decapsulation combines the stored KEM ciphertext with the user secret key to reproduce the same shared secret created during upload.',
        'Stored KEM ciphertext + protected user ML-KEM secret key',
        'Same hidden shared secret',
        'Only the correct secret key can recover the matching shared secret from this KEM ciphertext.'
    ))

    t2 = time.perf_counter_ns()
    file_key = derive_file_key(shared_secret, salt, file_uuid)
    t3 = time.perf_counter_ns()
    trace.append(TraceStep(
        'Re-create the same 256-bit file key', 'HKDF-SHA256', 'complete', _ms(t2, t3),
        f'Stored salt + recovered shared secret + file context → same 32-byte key (fingerprint {fingerprint(file_key)}…).',
        'Using the recovered shared secret and the same stored salt/context makes HKDF derive the exact same 32-byte key again.',
        'Recovered shared secret + stored salt + same file context',
        'Same 32-byte file-encryption key',
        'The application can recreate the key when authorized instead of storing the plaintext file key.'
    ))

    aad = build_aad(file_uuid, owner_id)
    t4 = time.perf_counter_ns()
    plaintext = ChaCha20Poly1305(file_key).decrypt(nonce, encrypted, aad)
    t5 = time.perf_counter_ns()
    trace.append(TraceStep(
        'Verify the tamper seal and decrypt', 'ChaCha20-Poly1305', 'complete', _ms(t4, t5),
        f'Authentication passed; {len(encrypted)} encrypted bytes → {len(plaintext)} plaintext bytes in memory only.',
        'Poly1305 authentication is checked and, only if it is valid, ChaCha20 recovers the original file bytes.',
        'Encrypted bytes + authentication tag + same key + stored nonce',
        f'{len(plaintext)} original file bytes in memory',
        'If the encrypted file or protected metadata was changed, authentication fails and the download is rejected.'
    ))

    return {
        'plaintext': plaintext,
        'trace': [step.to_dict() for step in trace],
        'timings': {
            'kem_decap_ms': trace[0].time_ms,
            'hkdf_ms': trace[1].time_ms,
            'decrypt_ms': trace[2].time_ms,
        },
    }


def derive_share_wrap_key(shared_secret: bytes, salt: bytes, file_uuid: str, recipient_id: int) -> bytes:
    info = f'PQVault|share-wrap|v1|{file_uuid}|recipient={recipient_id}'.encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def build_share_aad(file_uuid: str, owner_id: int, recipient_id: int) -> bytes:
    return f'PQVault|share-key|v1|{file_uuid}|owner={owner_id}|recipient={recipient_id}'.encode()


def recover_owner_file_key(kem_ciphertext: bytes, salt: bytes,
                           wrapped_secret_key: bytes, secret_key_nonce: bytes,
                           email: str, master_key_b64: str,
                           owner_id: int, file_uuid: str):
    """Re-create an owner's original 32-byte file key without storing it permanently."""
    trace = []
    secret_key = unwrap_user_secret_key(
        wrapped_secret_key, secret_key_nonce, email, master_key_b64
    )

    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM, secret_key) as receiver:
        shared_secret = receiver.decap_secret(kem_ciphertext)
    t1 = time.perf_counter_ns()
    decap_ms = _ms(t0, t1)
    trace.append(TraceStep(
        'Recover the owner shared secret', MLKEM_ALGORITHM, 'complete', decap_ms,
        f'Original file KEM ciphertext + owner secret key → hidden shared secret (fingerprint {fingerprint(shared_secret)}…).',
        'To share safely, the app first re-creates the same hidden shared secret that was used when the owner uploaded the file.',
        'Original KEM ciphertext + protected owner secret key',
        'Same hidden owner shared secret',
        'This lets the app re-create the file key without storing the plaintext key in the database.'
    ))

    t2 = time.perf_counter_ns()
    file_key = derive_file_key(shared_secret, salt, file_uuid)
    t3 = time.perf_counter_ns()
    hkdf_ms = _ms(t2, t3)
    trace.append(TraceStep(
        'Re-create the original file key', 'HKDF-SHA256', 'complete', hkdf_ms,
        f'Original salt + owner shared secret + file context → 32-byte file key (fingerprint {fingerprint(file_key)}…).',
        'HKDF deterministically re-creates the exact same 256-bit key that protects this file.',
        'Owner shared secret + original salt + file context',
        'Original 256-bit file key (hidden)',
        'The file key can now be wrapped for another authorized user instead of re-encrypting the whole file.'
    ))

    return {
        'file_key': file_key,
        'trace': [step.to_dict() for step in trace],
        'timings': {'kem_decap_ms': decap_ms, 'hkdf_ms': hkdf_ms},
    }


def create_share_envelope(file_key: bytes, recipient_public_key: bytes,
                          file_uuid: str, owner_id: int, recipient_id: int):
    """Wrap an existing file key for a recipient using ML-KEM + HKDF + ChaCha20-Poly1305."""
    trace = []

    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as sender:
        kem_ciphertext, shared_secret = sender.encap_secret(recipient_public_key)
    t1 = time.perf_counter_ns()
    encap_ms = _ms(t0, t1)
    trace.append(TraceStep(
        'Create a recipient-only shared secret', MLKEM_ALGORITHM, 'complete', encap_ms,
        f'Recipient public-key fingerprint {fingerprint(recipient_public_key)}… → share KEM ciphertext {len(kem_ciphertext)} bytes; shared secret hidden.',
        'ML-KEM uses the recipient public key to create fresh post-quantum key material specifically for this share.',
        'Recipient ML-KEM public key + fresh randomness',
        'Hidden share secret + share KEM ciphertext',
        'Only the recipient secret key can recover this share secret later.'
    ))

    salt = os.urandom(16)
    t2 = time.perf_counter_ns()
    wrap_key = derive_share_wrap_key(shared_secret, salt, file_uuid, recipient_id)
    t3 = time.perf_counter_ns()
    hkdf_ms = _ms(t2, t3)
    trace.append(TraceStep(
        'Derive a key-wrapping key', 'HKDF-SHA256', 'complete', hkdf_ms,
        f'16-byte share salt + hidden share secret + recipient context → 32-byte wrapping key (fingerprint {fingerprint(wrap_key)}…).',
        'HKDF turns the ML-KEM share secret into a dedicated 256-bit key used only to protect the file key.',
        'Share secret + random salt + file/recipient context',
        '256-bit key-wrapping key (hidden)',
        'A separate wrapping key keeps file encryption and sharing key protection as different jobs.'
    ))

    nonce = os.urandom(12)
    aad = build_share_aad(file_uuid, owner_id, recipient_id)
    t4 = time.perf_counter_ns()
    wrapped_file_key = ChaCha20Poly1305(wrap_key).encrypt(nonce, file_key, aad)
    t5 = time.perf_counter_ns()
    wrap_ms = _ms(t4, t5)
    trace.append(TraceStep(
        'Lock the file key for the recipient', 'ChaCha20-Poly1305', 'complete', wrap_ms,
        f'Original 32-byte file key → {len(wrapped_file_key)} protected bytes including authentication tag; key value never shown.',
        'ChaCha20-Poly1305 encrypts and authenticates the original file key with the recipient-specific wrapping key.',
        'Original hidden file key + wrapping key + 12-byte nonce',
        'Recipient-protected file-key envelope',
        'The encrypted file itself does not need to be duplicated or encrypted again for every recipient.'
    ))

    return {
        'kem_ciphertext': kem_ciphertext,
        'salt': salt,
        'nonce': nonce,
        'wrapped_file_key': wrapped_file_key,
        'trace': [step.to_dict() for step in trace],
        'timings': {'kem_encap_ms': encap_ms, 'hkdf_ms': hkdf_ms, 'wrap_ms': wrap_ms},
    }


def decrypt_shared_file(encrypted: bytes, file_nonce: bytes, file_uuid: str,
                        owner_id: int, share_kem_ciphertext: bytes,
                        share_salt: bytes, share_nonce: bytes,
                        wrapped_file_key: bytes,
                        recipient_wrapped_secret_key: bytes,
                        recipient_secret_key_nonce: bytes,
                        recipient_email: str, master_key_b64: str,
                        recipient_id: int):
    """Recover a recipient-wrapped file key and decrypt the owner's original ciphertext."""
    trace = []
    secret_key = unwrap_user_secret_key(
        recipient_wrapped_secret_key,
        recipient_secret_key_nonce,
        recipient_email,
        master_key_b64,
    )

    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM, secret_key) as receiver:
        shared_secret = receiver.decap_secret(share_kem_ciphertext)
    t1 = time.perf_counter_ns()
    decap_ms = _ms(t0, t1)
    trace.append(TraceStep(
        'Recover your share secret', MLKEM_ALGORITHM, 'complete', decap_ms,
        f'Share KEM ciphertext + recipient secret key → same hidden share secret (fingerprint {fingerprint(shared_secret)}…).',
        'The recipient uses their ML-KEM secret key to recover the same share secret created by the owner during sharing.',
        'Share KEM ciphertext + recipient protected secret key',
        'Same hidden share secret',
        'A different user secret key will not recover the matching share key material.'
    ))

    t2 = time.perf_counter_ns()
    wrap_key = derive_share_wrap_key(shared_secret, share_salt, file_uuid, recipient_id)
    t3 = time.perf_counter_ns()
    hkdf_ms = _ms(t2, t3)
    trace.append(TraceStep(
        'Re-create the key-wrapping key', 'HKDF-SHA256', 'complete', hkdf_ms,
        f'Stored share salt + recovered share secret + recipient context → same 32-byte wrapping key (fingerprint {fingerprint(wrap_key)}…).',
        'HKDF deterministically re-creates the recipient-specific key that protects the file key envelope.',
        'Recovered share secret + stored share salt + same context',
        'Same 256-bit wrapping key',
        'This avoids storing the wrapping key itself.'
    ))

    share_aad = build_share_aad(file_uuid, owner_id, recipient_id)
    t4 = time.perf_counter_ns()
    file_key = ChaCha20Poly1305(wrap_key).decrypt(
        share_nonce, wrapped_file_key, share_aad
    )
    t5 = time.perf_counter_ns()
    unwrap_ms = _ms(t4, t5)
    trace.append(TraceStep(
        'Unlock the file key', 'ChaCha20-Poly1305', 'complete', unwrap_ms,
        f'Recipient-protected key envelope → original hidden 32-byte file key (fingerprint {fingerprint(file_key)}…).',
        'The share envelope is authenticated and decrypted. If it was changed, this step fails before the file is opened.',
        'Wrapped file key + same wrapping key + stored nonce',
        'Original hidden 256-bit file key',
        'The recipient gets authorization to use the file key without the server storing that key as plaintext metadata.'
    ))

    file_aad = build_aad(file_uuid, owner_id)
    t6 = time.perf_counter_ns()
    plaintext = ChaCha20Poly1305(file_key).decrypt(file_nonce, encrypted, file_aad)
    t7 = time.perf_counter_ns()
    decrypt_ms = _ms(t6, t7)
    trace.append(TraceStep(
        'Verify and decrypt the shared file', 'ChaCha20-Poly1305', 'complete', decrypt_ms,
        f'Authentication passed; {len(encrypted)} encrypted bytes → {len(plaintext)} plaintext bytes in memory only.',
        'The same original file key authenticates the encrypted file and recovers the original bytes.',
        'Original ciphertext + original nonce + recovered file key',
        f'{len(plaintext)} original file bytes in memory',
        'The same encrypted file can serve the owner and authorized recipients without keeping extra plaintext copies.'
    ))

    return {
        'plaintext': plaintext,
        'trace': [step.to_dict() for step in trace],
        'timings': {
            'kem_decap_ms': decap_ms,
            'hkdf_ms': hkdf_ms,
            'unwrap_ms': unwrap_ms,
            'decrypt_ms': decrypt_ms,
        },
    }
