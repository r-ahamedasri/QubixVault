import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut as fbSignOut, onAuthStateChanged }
  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
import { getFirestore, doc, getDoc, setDoc }
  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';

// ─── PASTE YOUR FIREBASE CONFIG HERE ───────────────────────
const firebaseConfig = {
  apiKey:            "PASTE_YOUR_API_KEY",
  authDomain:        "PASTE_YOUR_AUTH_DOMAIN",
  projectId:         "PASTE_YOUR_PROJECT_ID",
  storageBucket:     "PASTE_YOUR_STORAGE_BUCKET",
  messagingSenderId: "PASTE_YOUR_MESSAGING_SENDER_ID",
  appId:             "PASTE_YOUR_APP_ID"
};
// ───────────────────────────────────────────────────────────

const app  = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

let _key = null, _entries = [], _uid = null, _lastGen = '', _viewId = null;

// ══════════════════════════════════════
// CRYPTO
// ══════════════════════════════════════
async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function encryptEntries(key, entries) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(entries)));
  const buf = new Uint8Array(iv.byteLength + ct.byteLength);
  buf.set(iv); buf.set(new Uint8Array(ct), iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}
async function decryptEntries(key, b64) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  return JSON.parse(new TextDecoder().decode(plain));
}
function randomB64(n = 32) {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))));
}

// ══════════════════════════════════════
// FIRESTORE
// ══════════════════════════════════════
async function loadVaultDoc(uid) {
  const snap = await getDoc(doc(db, 'vaults', uid));
  return snap.exists() ? snap.data() : null;
}
async function saveVaultDoc(uid, salt, vault) {
  await setDoc(doc(db, 'vaults', uid), { salt, vault });
}

// ══════════════════════════════════════
// AUTH
// ══════════════════════════════════════
window.signInWithGoogle = async () => {
  try { await signInWithPopup(auth, new GoogleAuthProvider()); }
  catch(e) { showToast('Sign-in failed: ' + e.message); }
};
window.signOut = async () => {
  _key = null; _entries = []; _uid = null;
  await fbSignOut(auth);
  showScreen('login'); setNavVisible(false);
};
window.lockVault = () => {
  _key = null; _entries = [];
  showScreen('master');
  document.getElementById('master-input').value = '';
  showToast('Vault locked');
};

onAuthStateChanged(auth, async user => {
  if (!user) { showScreen('login'); setNavVisible(false); return; }
  _uid = user.uid;
  const vaultDoc = await loadVaultDoc(user.uid).catch(() => null);
  const isNew = !vaultDoc;

  document.getElementById('master-avatar').src = user.photoURL || '';
  document.getElementById('master-greeting').textContent =
    isNew ? `Hi, ${user.displayName?.split(' ')[0] || 'there'}` : `Welcome back`;
  document.getElementById('master-sub').textContent =
    isNew ? 'Create a master password to encrypt your vault.'
          : 'Enter your master password to unlock your vault.';
  document.getElementById('new-vault-hint').style.display = isNew ? 'block' : 'none';
  setNavVisible(false);
  showScreen('master');
  setTimeout(() => document.getElementById('master-input').focus(), 100);
});

// ══════════════════════════════════════
// MASTER PASSWORD
// ══════════════════════════════════════
window.submitMaster = async () => {
  const pw = document.getElementById('master-input').value;
  const errEl = document.getElementById('master-error');
  errEl.textContent = '';
  if (pw.length < 6) { showToast('Master password must be at least 6 characters'); return; }
  try {
    showToast('Unlocking…');
    const vaultDoc = await loadVaultDoc(_uid);
    if (!vaultDoc) {
      const saltB64 = randomB64(32);
      const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
      const key = await deriveKey(pw, salt);
      await saveVaultDoc(_uid, saltB64, await encryptEntries(key, []));
      _key = key; _entries = [];
    } else {
      const salt = Uint8Array.from(atob(vaultDoc.salt), c => c.charCodeAt(0));
      const key = await deriveKey(pw, salt);
      _entries = await decryptEntries(key, vaultDoc.vault);
      _key = key;
    }
    const user = auth.currentUser;
    setNavUser(user); setNavVisible(true);
    showScreen('vault'); renderEntries(); setSyncStatus('synced');
    showToast('Vault unlocked');
  } catch(e) {
    errEl.textContent = e.name === 'OperationError' ? 'Wrong master password.' : 'Error: ' + e.message;
  }
};

// ══════════════════════════════════════
// VAULT CRUD
// ══════════════════════════════════════
async function persistVault() {
  setSyncStatus('saving');
  try {
    const snap = await getDoc(doc(db, 'vaults', _uid));
    await saveVaultDoc(_uid, snap.data().salt, await encryptEntries(_key, _entries));
    setSyncStatus('synced');
  } catch(e) { setSyncStatus('error'); showToast('Sync failed: ' + e.message); }
}

window.saveEntry = async () => {
  const site  = document.getElementById('f-site').value.trim();
  const user  = document.getElementById('f-user').value.trim();
  const pass  = document.getElementById('f-pass').value;
  const url   = document.getElementById('f-url').value.trim();
  const notes = document.getElementById('f-notes').value.trim();
  const editId = document.getElementById('f-id').value;
  if (!site) { showToast('Enter a site name'); return; }
  if (!user) { showToast('Enter a username or email'); return; }
  if (!pass) { showToast('Enter a password'); return; }
  if (editId) {
    const idx = _entries.findIndex(e => e.id === editId);
    if (idx >= 0) _entries[idx] = { ..._entries[idx], site, user, pass, url, notes, updated: Date.now() };
  } else {
    _entries.unshift({ id: crypto.randomUUID(), site, user, pass, url, notes, created: Date.now(), updated: Date.now() });
  }
  closeModal('modal-add'); renderEntries();
  await persistVault();
  showToast(editId ? 'Entry updated' : 'Password saved');
};

window.deleteCurrent = async () => {
  if (!confirm('Delete this entry?')) return;
  _entries = _entries.filter(e => e.id !== _viewId);
  closeModal('modal-view'); renderEntries();
  await persistVault(); showToast('Deleted');
};
window.editCurrent = () => { closeModal('modal-view'); openAddModal(_viewId); };

// ══════════════════════════════════════
// UI
// ══════════════════════════════════════
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + id)?.classList.add('active');
}
function setNavVisible(v) {
  document.getElementById('main-nav').style.display = v ? 'grid' : 'none';
}
function setNavUser(user) {
  if (!user) return;
  document.getElementById('nav-avatar').src = user.photoURL || '';
  document.getElementById('menu-avatar').src = user.photoURL || '';
  document.getElementById('menu-name').textContent = user.displayName || '';
  document.getElementById('menu-email').textContent = user.email || '';
  document.getElementById('sb-avatar').src = user.photoURL || '';
  document.getElementById('sb-name').textContent = user.displayName?.split(' ')[0] || '';
}
function setSyncStatus(state) {
  const dot = document.getElementById('sync-dot');
  const lbl = document.getElementById('sync-label');
  dot.className = 'sync-dot' + (state === 'saving' ? ' saving' : state === 'error' ? ' error' : '');
  lbl.textContent = state === 'saving' ? 'saving…' : state === 'error' ? 'error' : 'synced';
}

let _toastTimer;
window.showToast = (msg, dur = 2500) => {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), dur);
};
window.closeModal = id => document.getElementById(id).classList.remove('open');
window.toggleVis = id => {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
};
window.checkStrength = (input, barId, labelId) => {
  const v = input.value; let s = 0;
  if (v.length >= 8) s++; if (v.length >= 14) s++;
  if (/[A-Z]/.test(v)) s++; if (/[0-9]/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  const colors = ['#ef4444','#f97316','#eab308','#22c55e','#34d399'];
  const labels = ['very weak','weak','fair','strong','excellent'];
  const bar = document.getElementById(barId);
  bar.style.width = s > 0 ? (s * 20) + '%' : '0';
  bar.style.background = s > 0 ? colors[s-1] : '';
  const lbl = document.getElementById(labelId);
  if (lbl) lbl.textContent = s > 0 ? labels[s-1] : '';
};

window.renderEntries = () => {
  const q = (document.getElementById('search-input')?.value || document.getElementById('search-input-mobile')?.value || '').toLowerCase();
  const countEl = document.getElementById('entry-count');
  const sbCount = document.getElementById('sb-count');
  const list = document.getElementById('entries-list');
  if (sbCount) sbCount.textContent = _entries.length;
  if (countEl) countEl.textContent = _entries.length + ' item' + (_entries.length !== 1 ? 's' : '');
  const filtered = q ? _entries.filter(e => e.site.toLowerCase().includes(q) || e.user.toLowerCase().includes(q)) : _entries;
  if (!filtered.length) {
    list.innerHTML = `<div class="empty-state">
      <div class="empty-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
      <p class="empty-title">${q ? 'No results' : 'Your vault is empty'}</p>
      <p class="empty-sub">${q ? 'Try a different search term.' : 'Add your first password to get started.'}</p>
    </div>`;
    return;
  }
  list.innerHTML = filtered.map(e => `
    <div class="entry-card" onclick="viewEntry('${e.id}')">
      <div class="entry-avatar">${e.site[0].toUpperCase()}</div>
      <div class="entry-info">
        <div class="entry-site">${esc(e.site)}</div>
        <div class="entry-user">${esc(e.user)}</div>
      </div>
      <div class="entry-actions" onclick="event.stopPropagation()">
        <button class="entry-btn" onclick="copyPass('${e.id}')">copy</button>
        <button class="entry-btn" onclick="viewEntry('${e.id}')">view</button>
      </div>
    </div>`).join('');
};

window.syncSearch = (input) => {
  const other = input.id === 'search-input' ? 'search-input-mobile' : 'search-input';
  const otherEl = document.getElementById(other);
  if (otherEl) otherEl.value = input.value;
  renderEntries();
};

window.viewEntry = id => {
  const e = _entries.find(x => x.id === id); if (!e) return;
  _viewId = id;
  document.getElementById('view-title').textContent = e.site;
  document.getElementById('view-avatar-icon').textContent = e.site[0].toUpperCase();
  document.getElementById('view-user').textContent = e.user;
  document.getElementById('view-pass-disp').textContent = '••••••••••••';
  document.getElementById('view-pass-disp').style.letterSpacing = '';
  document.getElementById('view-pass-real').value = e.pass;
  const urlRow = document.getElementById('view-url-row');
  const notesRow = document.getElementById('view-notes-row');
  if (e.url) { urlRow.style.display = 'flex'; document.getElementById('view-url').textContent = e.url; document.getElementById('view-url-link').href = e.url; }
  else urlRow.style.display = 'none';
  if (e.notes) { notesRow.style.display = 'flex'; document.getElementById('view-notes').textContent = e.notes; }
  else notesRow.style.display = 'none';
  document.getElementById('modal-view').classList.add('open');
};
window.toggleViewPass = () => {
  const disp = document.getElementById('view-pass-disp');
  const real = document.getElementById('view-pass-real').value;
  if (disp.textContent === '••••••••••••') { disp.textContent = real; disp.style.letterSpacing = '0.04em'; }
  else { disp.textContent = '••••••••••••'; disp.style.letterSpacing = ''; }
};
window.copyHidden = () => navigator.clipboard.writeText(document.getElementById('view-pass-real').value).then(() => showToast('Password copied'));
window.copyEl = id => navigator.clipboard.writeText(document.getElementById(id).textContent).then(() => showToast('Copied'));
window.copyPass = id => { const e = _entries.find(x => x.id === id); if(e) navigator.clipboard.writeText(e.pass).then(() => showToast('Password copied')); };

window.openAddModal = (editId) => {
  const e = editId ? _entries.find(x => x.id === editId) : null;
  document.getElementById('modal-add-title').textContent = e ? 'Edit entry' : 'Add password';
  document.getElementById('f-site').value  = e?.site  || '';
  document.getElementById('f-user').value  = e?.user  || '';
  document.getElementById('f-pass').value  = e?.pass  || '';
  document.getElementById('f-url').value   = e?.url   || '';
  document.getElementById('f-notes').value = e?.notes || '';
  document.getElementById('f-id').value    = editId   || '';
  document.getElementById('f-bar').style.width = '0';
  document.getElementById('f-slabel').textContent = '';
  document.getElementById('modal-add').classList.add('open');
};
window.filterAll = btn => {
  document.querySelectorAll('.sidebar-item').forEach(b => b.classList.remove('active'));
  btn.classList.add('active'); renderEntries();
};

// Generator
window.openGenModal = () => { genPw(); document.getElementById('modal-gen').classList.add('open'); };
window.genPw = () => {
  const len = parseInt(document.getElementById('gen-len').value);
  let chars = '';
  if (document.getElementById('gen-upper').checked) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (document.getElementById('gen-lower').checked) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (document.getElementById('gen-num').checked)   chars += '0123456789';
  if (document.getElementById('gen-sym').checked)   chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!chars) { document.getElementById('gen-output').textContent = 'Select at least one option'; return; }
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  _lastGen = Array.from(arr).map(n => chars[n % chars.length]).join('');
  document.getElementById('gen-output').textContent = _lastGen;
};
window.copyGenPw = () => _lastGen && navigator.clipboard.writeText(_lastGen).then(() => showToast('Copied'));
window.useGenPw = () => {
  if (!_lastGen) return;
  closeModal('modal-gen'); openAddModal();
  setTimeout(() => { document.getElementById('f-pass').value = _lastGen; checkStrength(document.getElementById('f-pass'),'f-bar','f-slabel'); }, 50);
};
window.fillGenerated = () => {
  if (_lastGen) { document.getElementById('f-pass').value = _lastGen; checkStrength(document.getElementById('f-pass'),'f-bar','f-slabel'); }
  else openGenModal();
};

// User menu
window.toggleUserMenu = () => document.getElementById('user-menu').classList.toggle('open');
document.addEventListener('click', e => {
  if (!document.getElementById('nav-menu-wrap')?.contains(e.target)) {
    document.getElementById('user-menu')?.classList.remove('open');
  }
});

// Sidebar (mobile)
window.toggleSidebar = () => {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('open');
};

// Keyboard
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    document.getElementById('sidebar')?.classList.remove('open');
    document.getElementById('sidebar-overlay')?.classList.remove('open');
    document.getElementById('user-menu')?.classList.remove('open');
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'k' && _key) {
    e.preventDefault();
    const s = document.getElementById('search-input') || document.getElementById('search-input-mobile');
    s?.focus();
  }
});

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }