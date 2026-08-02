/**
 * login-init.js — Login gate controller.
 *
 * Runs synchronously in <body> before radar.js to decide whether the
 * login overlay should remain visible or be dismissed (valid token in
 * localStorage).  Exposes window._doLogin() for the login button.
 */
(function () {
  // Check for existing valid token
  var token = localStorage.getItem('radar_access_token');
  if (token) {
    // Validate token by calling a protected endpoint
    fetch('/api/data_status', { headers: { 'Authorization': 'Bearer ' + token } })
      .then(function (r) {
        if (r.ok) {
          document.getElementById('login-gate').style.display = 'none';
          // Invalidate Leaflet map size after login-gate overlay is removed
          // (map tiles/layers rendered while hidden get wrong dimensions)
          setTimeout(function () {
            if (window._radarMap) window._radarMap.invalidateSize();
            if (window._resetRenderSig) window._resetRenderSig();
            if (window.forceDataSync) window.forceDataSync();
          }, 300);
        }
      })
      .catch(function (err) {
        // SF8 (audit fix): a network error here used to be silent,
        // leaving the analyst staring at the login gate with no
        // explanation. Surface a hint so the user can distinguish
        // "actually logged out" from "network down".
        console.warn('[login-init] token validation failed:', err);
        var errEl = document.getElementById('login-error');
        if (errEl) {
          errEl.textContent = '保存済みセッションを検証できませんでした — 接続を確認するか、再度サインインしてください。';
          errEl.style.display = '';
        }
      });
  }

  window._doLogin = async function () {
    var user = document.getElementById('login-user').value.trim();
    var pass = document.getElementById('login-pass').value;
    var errEl = document.getElementById('login-error');
    errEl.style.display = 'none';
    if (!user || !pass) {
      errEl.textContent = _t('login.error.required');
      errEl.style.display = '';
      return;
    }
    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass }),
      });
      var data = await res.json();
      if (!res.ok) {
        errEl.textContent = data.error || _t('login.error.failed');
        errEl.style.display = '';
        return;
      }
      // Phase 7.5g (audit Security H3): the refresh token is now
      // delivered as an httpOnly cookie by the backend (/api/auth/login
      // → set_refresh_cookies). The JSON body no longer carries
      // `data.refresh_token` — we only persist the short-lived access
      // token in localStorage. The browser stores and replays the
      // refresh cookie automatically; we cannot read it from JS.
      localStorage.setItem('radar_access_token', data.access_token);
      localStorage.setItem('radar_username', data.username);
      localStorage.setItem('radar_role', data.role);
      if (data.access_expires_sec)
        localStorage.setItem('radar_token_lifetime', data.access_expires_sec);
      // Reload page — initApp will run with valid token in localStorage
      location.reload();
    } catch (e) {
      errEl.textContent = _t('login.error.connection');
      errEl.style.display = '';
    }
  };

  // Bind login button (replaces inline onclick)
  document.getElementById('login-btn').addEventListener('click', function () {
    window._doLogin();
  });

  // Allow Enter key to submit
  document.addEventListener('keydown', function (e) {
    if (
      e.key === 'Enter' &&
      document.getElementById('login-gate').style.display !== 'none'
    ) {
      window._doLogin();
    }
  });
})();
