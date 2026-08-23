const benchmarkForm = document.getElementById('benchmarkForm');
if (benchmarkForm) {
  benchmarkForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const csrf = document.querySelector('meta[name="csrf-token"]').content;
    const btn = document.getElementById('benchmarkBtn');
    const box = document.getElementById('benchmarkResult');
    btn.disabled = true;
    btn.textContent = 'Benchmark running...';
    box.classList.remove('hidden');
    box.textContent = 'Running real ML-KEM/HKDF/ChaCha operations. Large files × many repetitions can take time...';
    try {
      const res = await fetch('/api/benchmark', {
        method: 'POST', body: new FormData(benchmarkForm), headers: {'X-CSRFToken': csrf}
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || 'Benchmark failed');
      const a = data.average;
      box.innerHTML = `<strong>${data.runs} run(s) complete.</strong><br>
        Avg total: ${a.total_ms} ms · keygen: ${a.mlkem_keygen_ms} ms · encap: ${a.mlkem_encap_ms} ms · decap: ${a.mlkem_decap_ms} ms<br>
        HKDF: ${a.hkdf_ms} ms · encrypt: ${a.encrypt_ms} ms · decrypt: ${a.decrypt_ms} ms · throughput: ${a.throughput_mbps} MB/s · peak: ${a.peak_memory_kb} KB`;
      setTimeout(() => window.location.reload(), 1600);
    } catch (err) {
      box.textContent = err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Run Benchmark';
    }
  });
}
