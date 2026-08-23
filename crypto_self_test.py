import os
import uuid
import oqs
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from crypto.engine import MLKEM_ALGORITHM, derive_file_key, build_aad

message = b'PQ Vault crypto self-test'
file_uuid = str(uuid.uuid4())
salt = os.urandom(16)
nonce = os.urandom(12)
aad = build_aad(file_uuid, 1)

with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as receiver:
    public_key = receiver.generate_keypair()
    secret_key = receiver.export_secret_key()

with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as sender:
    ciphertext, shared_sender = sender.encap_secret(public_key)

with oqs.KeyEncapsulation(MLKEM_ALGORITHM, secret_key) as receiver2:
    shared_receiver = receiver2.decap_secret(ciphertext)

assert shared_sender == shared_receiver
key1 = derive_file_key(shared_sender, salt, file_uuid)
key2 = derive_file_key(shared_receiver, salt, file_uuid)
assert key1 == key2
enc = ChaCha20Poly1305(key1).encrypt(nonce, message, aad)
dec = ChaCha20Poly1305(key2).decrypt(nonce, enc, aad)
assert dec == message
print('PASS: ML-KEM-768 -> HKDF-SHA256 -> ChaCha20-Poly1305 pipeline is working.')
