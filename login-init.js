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
      .catch(function () {});
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
      localStorage.setItem('radar_access_token', data.access_token);
      localStorage.setItem('radar_refresh_token', data.refresh_token);
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
