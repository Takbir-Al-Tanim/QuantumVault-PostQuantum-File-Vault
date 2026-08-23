import os
import time
import tracemalloc
import uuid

import oqs
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .engine import MLKEM_ALGORITHM, build_aad, derive_file_key


def _elapsed_ms(start_ns, end_ns):
    return (end_ns - start_ns) / 1_000_000


def run_single_benchmark(data: bytes):
    file_uuid = str(uuid.uuid4())
    owner_id = 0
    aad = build_aad(file_uuid, owner_id)
    salt = os.urandom(16)
    nonce = os.urandom(12)

    tracemalloc.start()
    total_start = time.perf_counter_ns()

    t0 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as receiver:
        public_key = receiver.generate_keypair()
        secret_key = receiver.export_secret_key()
    t1 = time.perf_counter_ns()

    t2 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM) as sender:
        kem_ciphertext, shared_secret_sender = sender.encap_secret(public_key)
    t3 = time.perf_counter_ns()

    t4 = time.perf_counter_ns()
    file_key_sender = derive_file_key(shared_secret_sender, salt, file_uuid)
    t5 = time.perf_counter_ns()

    t6 = time.perf_counter_ns()
    encrypted = ChaCha20Poly1305(file_key_sender).encrypt(nonce, data, aad)
    t7 = time.perf_counter_ns()

    t8 = time.perf_counter_ns()
    with oqs.KeyEncapsulation(MLKEM_ALGORITHM, secret_key) as receiver2:
        shared_secret_receiver = receiver2.decap_secret(kem_ciphertext)
    t9 = time.perf_counter_ns()

    t10 = time.perf_counter_ns()
    file_key_receiver = derive_file_key(shared_secret_receiver, salt, file_uuid)
    t11 = time.perf_counter_ns()

    t12 = time.perf_counter_ns()
    decrypted = ChaCha20Poly1305(file_key_receiver).decrypt(nonce, encrypted, aad)
    t13 = time.perf_counter_ns()

    total_end = time.perf_counter_ns()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if decrypted != data or shared_secret_sender != shared_secret_receiver:
        raise RuntimeError('Benchmark self-check failed: recovered data/secret did not match.')

    total_ms = _elapsed_ms(total_start, total_end)
    crypto_data_ms = _elapsed_ms(t6, t7) + _elapsed_ms(t12, t13)
    size_mb = len(data) / (1024 * 1024)
    throughput = (2 * size_mb) / (crypto_data_ms / 1000) if crypto_data_ms > 0 else None

    return {
        'file_size_bytes': len(data),
        'ciphertext_size_bytes': len(encrypted),
        'mlkem_keygen_ms': round(_elapsed_ms(t0, t1), 4),
        'mlkem_encap_ms': round(_elapsed_ms(t2, t3), 4),
        'mlkem_decap_ms': round(_elapsed_ms(t8, t9), 4),
        'hkdf_ms': round(_elapsed_ms(t4, t5) + _elapsed_ms(t10, t11), 4),
        'encrypt_ms': round(_elapsed_ms(t6, t7), 4),
        'decrypt_ms': round(_elapsed_ms(t12, t13), 4),
        'total_ms': round(total_ms, 4),
        'throughput_mbps': round(throughput, 4) if throughput is not None else None,
        'peak_memory_kb': round(peak / 1024, 2),
    }
