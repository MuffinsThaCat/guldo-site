
(function () {
  var root = document.documentElement;
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
  var saved = store('theme');
  if (saved === 'dark' || saved === 'light') root.setAttribute('data-theme', saved);
  var tbtn = document.getElementById('theme-toggle');
  function isDark() { var t = root.getAttribute('data-theme'); return t ? t === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches; }
  function label() { if (tbtn) { tbtn.textContent = isDark() ? 'Light mode' : 'Dark mode'; tbtn.setAttribute('aria-pressed', String(isDark())); } }
  if (tbtn) { tbtn.addEventListener('click', function () { var next = isDark() ? 'light' : 'dark'; root.setAttribute('data-theme', next); store('theme', next); label(); }); label(); }

  var tip = document.getElementById('tip');
  function show(e) {
    var t = e.target && e.target.getAttribute && e.target.getAttribute('data-tip');
    if (!tip) return;
    if (!t) { tip.style.opacity = 0; return; }
    tip.textContent = t; tip.style.opacity = 1;
    var r = e.target.getBoundingClientRect();
    var x = (e.clientX || r.left) + 14, y = (e.clientY || r.top) + 14;
    tip.style.left = Math.min(x, window.innerWidth - tip.offsetWidth - 8) + 'px';
    tip.style.top = Math.min(y, window.innerHeight - tip.offsetHeight - 8) + 'px';
  }
  document.addEventListener('mousemove', show);
  document.addEventListener('focusin', show);
  document.addEventListener('focusout', function () { if (tip) tip.style.opacity = 0; });

  document.querySelectorAll('button.copy').forEach(function (b) {
    b.addEventListener('click', function () {
      var text = b.getAttribute('data-copy') || '';
      var done = function () { var old = b.textContent; b.textContent = 'Copied'; setTimeout(function () { b.textContent = old; }, 1400); };
      var fallback = function () {
        var code = b.parentElement.querySelector('code'); if (code) { var s = window.getSelection(), r = document.createRange(); r.selectNodeContents(code); s.removeAllRanges(); s.addRange(r); }
        b.textContent = 'Press Ctrl+C'; setTimeout(function () { b.textContent = 'Copy'; }, 2000);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
    });
  });

  async function sha256hex(text) {
    var bytes = new TextEncoder().encode(text.trim());
    var digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.prototype.map.call(new Uint8Array(digest), function (x) { return x.toString(16).padStart(2, '0'); }).join('');
  }
  var form = document.getElementById('verify');
  if (form) {
    var manifestEl = document.getElementById('runs-manifest');
    var runs = []; try { runs = JSON.parse(manifestEl.textContent); } catch (e) { runs = []; }
    var sel = document.getElementById('v-run'), seed = document.getElementById('v-seed'), res = document.getElementById('v-result');
    runs.forEach(function (r, i) { var o = document.createElement('option'); o.value = String(i); o.textContent = r.label; sel.appendChild(o); });
    function current() { return runs[Number(sel.value)]; }
    document.getElementById('v-fill').addEventListener('click', function () {
      var r = current(); if (!r) return;
      if (r.seed) { seed.value = r.seed; res.textContent = 'Revealed seed filled in. Press Check.'; res.className = 'vres'; }
      else { res.textContent = 'This run has no revealed seed on this site yet.'; res.className = 'vres bad'; }
    });
    document.getElementById('v-check').addEventListener('click', async function () {
      var r = current();
      if (!r) { res.textContent = 'Choose a run first.'; res.className = 'vres bad'; return; }
      if (!seed.value.trim()) { res.textContent = 'Paste a seed first.'; res.className = 'vres bad'; return; }
      if (!(window.crypto && crypto.subtle)) { res.textContent = 'This browser cannot compute SHA-256 here (it needs a secure context).'; res.className = 'vres bad'; return; }
      var h = await sha256hex(seed.value);
      if (h === r.commit) { res.textContent = 'Match. This seed hashes to the commitment published before the run: ' + h.slice(0, 16) + '...'; res.className = 'vres good'; }
      else { res.textContent = 'No match. This seed hashes to ' + h.slice(0, 16) + '..., not ' + r.commit.slice(0, 16) + '...'; res.className = 'vres bad'; }
    });
  }
})();
