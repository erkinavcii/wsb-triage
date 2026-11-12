(function () {
  const input = document.getElementById('authTokenInput');
  const btn = document.getElementById('btnAuthSubmit');
  const errBox = document.getElementById('authErr');

  async function submitToken() {
    const token = (input.value || '').trim();
    if (!token) {
      errBox.textContent = 'Lütfen belirteci girin.';
      errBox.classList.remove('hidden');
      return;
    }
    errBox.classList.add('hidden');
    try {
      const r = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      if (!r.ok) {
        let d = null;
        try { d = await r.json(); } catch (_) {}
        throw new Error((d && d.detail) || ('HTTP ' + r.status));
      }
      window.location.replace('/');
    } catch (e) {
      errBox.textContent = e.message || 'Doğrulama başarısız.';
      errBox.classList.remove('hidden');
    }
  }

  btn.addEventListener('click', submitToken);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitToken();
  });
})();
