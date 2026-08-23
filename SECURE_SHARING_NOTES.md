# Secure Sharing Design

## What changed

QuantumVault now supports registered-user sharing without duplicating the encrypted file.

### Owner flow

1. Verify the logged-in user owns the file.
2. Re-create the original file key using the owner's ML-KEM ciphertext + secret key, then HKDF.
3. Use the recipient's ML-KEM public key to create a fresh share secret and share KEM ciphertext.
4. Derive a recipient-specific 256-bit wrapping key with HKDF-SHA256.
5. Wrap the original 32-byte file key with ChaCha20-Poly1305.
6. Store only the share permission and protected file-key envelope.

### Recipient flow

1. Verify an active share record exists for the logged-in recipient.
2. Use the recipient ML-KEM secret key to decapsulate the share KEM ciphertext.
3. Re-create the wrapping key with HKDF-SHA256.
4. Authenticate and decrypt the protected file-key envelope.
5. Use the recovered original file key to authenticate and decrypt the same encrypted file stored for the owner.

### Revocation

The owner can delete the share record. That blocks future vault downloads for that recipient. It cannot erase a plaintext copy that the recipient already downloaded earlier.

## Database

New table: `file_shares`

Existing databases should run `upgrade_secure_sharing.sql` once. New databases can run `schema.sql`.
