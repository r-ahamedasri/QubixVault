/**
 * firebase.js — QuantumVault
 *
 * Flow:
 *  1. User clicks "Sign in with Google" → Firebase Auth popup
 *  2. On auth success → show master password screen
 *  3. User enters master password → PBKDF2 derives AES-256 key
 *  4. Key decrypts vault fetched from Firestore (or creates new vault)
 *  5. All CRUD operations re-encrypt vault → save back to Firestore
 *
 * What Firebase stores per user (document: /vaults/{uid}):
 *   { salt: string, vault: string }
 *   - salt  : base64 random bytes used in PBKDF2
 *   - vault : base64 AES-256-GCM ciphertext of the entries array
 *
 * Master password and CryptoKey NEVER leave the browser.
 */

import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut as fbSignOut, onAuthStateChanged }
  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
import { getFirestore, doc, getDoc, setDoc }
  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';

// ─────────────────────────────────────────────────────────────
// 🔧 PASTE YOUR FIREBASE CONFIG HERE
// Get it from: Firebase Console → Project Settings → Your apps → SDK setup
// ─────────────────────────────────────────────────────────────
const firebaseConfig = {
  apiKey:            "AIzaSyChj-PGpTHZ3hcewBkKydmjM6MgspcLupI",
  authDomain:        "qubixvault-91ea2.firebaseapp.com",
  projectId:         "qubixvault-91ea2",
  storageBucket:     "qubixvault-91ea2.firebasestorage.app",
  messagingSenderId: "16547854406",
  appId:             "1:16547854406:web:ca62a9e544057f7162f247"
};
// ─────────────────────────────────────────────────────────────

const app  = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

// ── In-memory state (cleared on lock/sign-out) ──
let _key     = null;   // CryptoKey (AES-256-GCM)
let _entries = [];     // decrypted vault entries
let _uid     = null;   // Firebase user UID
let _lastGen = '';     // last generated password
let _viewId  = null;   // currently viewed entry id

// ════════════════════════════════════════════════
// CRYPTO
// ════════════════════════════════════════════════

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptEntries(key, entries) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(entries)));
  const buf = new Uint8Array(iv.byteLength + ct.byteLength);
  buf.set(iv); buf.set(new Uint8Array(ct), iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}

async function decryptEntries(key, b64) {
  const buf   = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  return JSON.parse(new TextDecoder().decode(plain));
}

function randomB64(bytes = 32) {
  const u = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...u));
}

// ════════════════════════════════════════════════
// FIRESTORE HELPERS
// ════════════════════════════════════════════════

async function loadVaultDoc(uid) {
  const snap = await getDoc(doc(db, 'vaults', uid));
  return snap.exists() ? snap.data() : null;
}

async function saveVaultDoc(uid, salt, encryptedVault) {
  await setDoc(doc(db, 'vaults', uid), { salt, vault: encryptedVault });
}

// ════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════

window.signInWithGoogle = async function () {
  try {
    const provider = new GoogleAuthProvider();
    await signInWithPopup(auth, provider);
    // onAuthStateChanged handles the rest
  } catch (e) {
    showToast('Sign-in failed: ' + e.message);
  }
};

window.signOut = async function () {
  _key = null; _entries = []; _uid = null;
  setNavUser(null);
  await fbSignOut(auth);
  showScreen('login');
};

window.lockVault = function () {
  _key = null; _entries = [];
  showScreen('master');
  document.getElementById('master-input').value = '';
  showToast('Vault locked');
};

onAuthStateChanged(auth, async (user) => {
  if (!user) {
    showScreen('login');
    setNavUser(null);
    return;
  }
  _uid = user.uid;
  setNavUser(user);

  // Check if vault exists
  const vaultDoc = await loadVaultDoc(user.uid).catch(() => null);
  const isNew = !vaultDoc;

  document.getElementById('master-avatar').src = user.photoURL || '';
  document.getElementById('master-greeting').textContent = isNew
    ? `Welcome, ${user.displayName?.split(' ')[0] || 'there'}!`
    : `Welcome back, ${user.displayName?.split(' ')[0] || 'there'}!`;
  document.getElementById('master-sub').textContent = isNew
    ? 'Create a master password to encrypt your vault.'
    : 'Enter your master password to decrypt your vault.';
  document.getElementById('new-vault-hint').style.display = isNew ? 'block' : 'none';

  showScreen('master');
  document.getElementById('master-input').focus();
});

// ════════════════════════════════════════════════
// MASTER PASSWORD SUBMIT
// ════════════════════════════════════════════════

window.submitMaster = async function () {
  const pw    = document.getElementById('master-input').value;
  const errEl = document.getElementById('master-error');
  errEl.textContent = '';

  if (pw.length < 6) { showToast('Master password must be at least 6 characters'); return; }

  try {
    showToast('Deriving key…');
    const vaultDoc = await loadVaultDoc(_uid);

    if (!vaultDoc) {
      // New vault — create salt, encrypt empty array, save
      const saltB64 = randomB64(32);
      const salt    = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
      const key     = await deriveKey(pw, salt);
      const enc     = await encryptEntries(key, []);
      await saveVaultDoc(_uid, saltB64, enc);
      _key = key; _entries = [];
    } else {
      // Existing vault — derive key from stored salt, decrypt
      const salt = Uint8Array.from(atob(vaultDoc.salt), c => c.charCodeAt(0));
      const key  = await deriveKey(pw, salt);
      // This will throw if password is wrong (GCM auth tag mismatch)
      const entries = await decryptEntries(key, vaultDoc.vault);
      _key = key; _entries = entries;
    }

    setNavUser(auth.currentUser);
    showScreen('vault');
    renderEntries();
    setSyncStatus('synced');
    showToast('Vault unlocked!');
  } catch (e) {
    if (e.name === 'OperationError') {
      errEl.textContent = 'Wrong master password.';
    } else {
      errEl.textContent = 'Error: ' + e.message;
    }
  }
};

// ════════════════════════════════════════════════
// VAULT CRUD
// ════════════════════════════════════════════════

async function persistVault() {
  setSyncStatus('saving');
  try {
    const snap   = await getDoc(doc(db, 'vaults', _uid));
    const saltB64 = snap.data().salt;
    const enc    = await encryptEntries(_key, _entries);
    await saveVaultDoc(_uid, saltB64, enc);
    setSyncStatus('synced');
  } catch (e) {
    setSyncStatus('error');
    showToast('Sync failed: ' + e.message);
  }
}

window.saveEntry = async function () {
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

  closeModal('modal-add');
  renderEntries();
  await persistVault();
  showToast(editId ? 'Entry updated!' : 'Password saved!');
};

window.deleteCurrent = async function () {
  if (!confirm('Delete this entry? This cannot be undone.')) return;
  _entries = _entries.filter(e => e.id !== _viewId);
  closeModal('modal-view');
  renderEntries();
  await persistVault();
  showToast('Deleted');
};

window.editCurrent = function () {
  closeModal('modal-view');
  openAddModal(_viewId);
};

// ════════════════════════════════════════════════
// UI HELPERS
// ════════════════════════════════════════════════

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const el = document.getElementById('screen-' + id);
  if (el) el.classList.add('active');
}

function setNavUser(user) {
  const nav = document.getElementById('nav-user');
  if (!user) { nav.style.display = 'none'; return; }
  nav.style.display = 'flex';
  document.getElementById('nav-avatar').src = user.photoURL || '';
  document.getElementById('nav-name').textContent = user.displayName || user.email;
}

function setSyncStatus(state) {
  const dot   = document.getElementById('sync-dot');
  const label = document.getElementById('sync-label');
  dot.className = 'sync-dot' + (state === 'saving' ? ' yellow' : state === 'error' ? ' red' : '');
  label.textContent = state === 'saving' ? 'saving…' : state === 'error' ? 'sync error' : 'synced';
}

let _toastTimer;
window.showToast = function (msg, dur = 2800) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), dur);
};

window.closeModal = function (id) {
  document.getElementById(id).classList.remove('open');
};

window.toggleVis = function (id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
};

window.checkStrength = function (input, barId, labelId) {
  const v = input.value;
  let s = 0;
  if (v.length >= 8) s++;
  if (v.length >= 14) s++;
  if (/[A-Z]/.test(v)) s++;
  if (/[0-9]/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  const colors = ['#ef4444','#f97316','#eab308','#22c55e','#4ade80'];
  const labels = ['very weak','weak','fair','strong','very strong'];
  const bar = document.getElementById(barId);
  bar.style.width   = s > 0 ? (s * 20) + '%' : '0';
  bar.style.background = s > 0 ? colors[s - 1] : '';
  const lbl = document.getElementById(labelId);
  if (lbl) lbl.textContent = s > 0 ? labels[s - 1] : '—';
};

window.renderEntries = function () {
  const q       = (document.getElementById('search-input')?.value || '').toLowerCase();
  const list    = document.getElementById('entries-list');
  const statEl  = document.getElementById('stat-total');
  if (statEl) statEl.textContent = _entries.length;

  const filtered = q
    ? _entries.filter(e => e.site.toLowerCase().includes(q) || e.user.toLowerCase().includes(q))
    : _entries;

  if (!filtered.length) {
    list.innerHTML = `<div class="empty-state"><div class="empty-icon">⬡</div>
      <p>${q ? 'No results for "' + esc(q) + '"' : 'Your vault is empty.'}</p>
      <p class="empty-sub">${q ? 'Try a different search.' : 'Click "+ add" to save your first password.'}</p></div>`;
    return;
  }

  list.innerHTML = filtered.map(e => `
    <div class="entry-card" onclick="viewEntry('${e.id}')">
      <div class="entry-avatar">${(e.site[0] || '?').toUpperCase()}</div>
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

window.viewEntry = function (id) {
  const e = _entries.find(x => x.id === id);
  if (!e) return;
  _viewId = id;
  document.getElementById('view-title').textContent = e.site;
  document.getElementById('view-user').textContent  = e.user;
  document.getElementById('view-pass-disp').textContent = '••••••••';
  document.getElementById('view-pass-disp').style.letterSpacing = '';
  document.getElementById('view-pass-real').value   = e.pass;
  const urlRow   = document.getElementById('view-url-row');
  const notesRow = document.getElementById('view-notes-row');
  if (e.url)   { urlRow.style.display = 'flex';   document.getElementById('view-url').textContent   = e.url; }
  else           urlRow.style.display = 'none';
  if (e.notes) { notesRow.style.display = 'flex'; document.getElementById('view-notes').textContent = e.notes; }
  else           notesRow.style.display = 'none';
  document.getElementById('modal-view').classList.add('open');
};

window.toggleViewPass = function () {
  const disp = document.getElementById('view-pass-disp');
  const real = document.getElementById('view-pass-real').value;
  if (disp.textContent === '••••••••') { disp.textContent = real; disp.style.letterSpacing = '0.05em'; }
  else { disp.textContent = '••••••••'; disp.style.letterSpacing = ''; }
};

window.copyHidden = function () {
  navigator.clipboard.writeText(document.getElementById('view-pass-real').value)
    .then(() => showToast('Password copied!'));
};

window.copyEl = function (id) {
  navigator.clipboard.writeText(document.getElementById(id).textContent)
    .then(() => showToast('Copied!'));
};

window.copyPass = function (id) {
  const e = _entries.find(x => x.id === id);
  if (e) navigator.clipboard.writeText(e.pass).then(() => showToast('Password copied!'));
};

window.openAddModal = function (editId) {
  const e = editId ? _entries.find(x => x.id === editId) : null;
  document.getElementById('modal-add-title').textContent = e ? 'Edit entry' : 'Add password';
  document.getElementById('f-site').value  = e?.site  || '';
  document.getElementById('f-user').value  = e?.user  || '';
  document.getElementById('f-pass').value  = e?.pass  || '';
  document.getElementById('f-url').value   = e?.url   || '';
  document.getElementById('f-notes').value = e?.notes || '';
  document.getElementById('f-id').value    = editId   || '';
  document.getElementById('f-bar').style.width = '0';
  document.getElementById('f-slabel').textContent = '—';
  document.getElementById('modal-add').classList.add('open');
};

window.filterAll = function (btn) {
  document.querySelectorAll('.sidebar-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderEntries();
};

// ── Generator ──
window.openGenModal = function () { genPw(); document.getElementById('modal-gen').classList.add('open'); };

window.genPw = function () {
  const len  = parseInt(document.getElementById('gen-len').value);
  let chars  = '';
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

window.copyGenPw   = function () { if (_lastGen) navigator.clipboard.writeText(_lastGen).then(() => showToast('Copied!')); };
window.useGenPw    = function () { if (!_lastGen) return; closeModal('modal-gen'); openAddModal(); setTimeout(() => { document.getElementById('f-pass').value = _lastGen; checkStrength(document.getElementById('f-pass'),'f-bar','f-slabel'); }, 50); };
window.fillGenerated = function () { if (_lastGen) { document.getElementById('f-pass').value = _lastGen; checkStrength(document.getElementById('f-pass'),'f-bar','f-slabel'); } else openGenModal(); };

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Keyboard shortcuts ──
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    const s = document.getElementById('search-input');
    if (s && _key) { e.preventDefault(); s.focus(); }
  }
});
