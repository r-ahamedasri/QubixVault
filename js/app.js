import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut as fbSignOut, onAuthStateChanged }
  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
import { getFirestore, doc, getDoc, setDoc }
  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';

/* ─── PASTE YOUR FIREBASE CONFIG HERE ─────────────────────
   Get it from Firebase Console → Project Settings → Your apps
──────────────────────────────────────────────────────────── */
const firebaseConfig = {
  apiKey:            "AIzaSyChj-PGpTHZ3hcewBkKydmjM6MgspcLupI",
  authDomain:        "qubixvault-91ea2.firebaseapp.com",
  projectId:         "qubixvault-91ea2",
  storageBucket:     "qubixvault-91ea2.firebasestorage.app",
  messagingSenderId: "16547854406",
  appId:             "1:16547854406:web:ca62a9e544057f7162f247"
};
/* ────────────────────────────────────────────────────────── */

const app  = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

/* ─── STATE ──────────────────────────────── */
let _key     = null;
let _entries = [];
let _uid     = null;
let _viewId  = null;
let _lastGen = '';

/* ═══════════════════════════════════════════
   HELPERS: show/hide pages
═══════════════════════════════════════════ */
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
}

/* ═══════════════════════════════════════════
   CRYPTO
═══════════════════════════════════════════ */
async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function encryptData(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data))
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...out));
}
async function decryptData(key, b64) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const pt  = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}
function rndB64(n = 32) {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))));
}

/* ═══════════════════════════════════════════
   FIRESTORE
═══════════════════════════════════════════ */
async function dbLoad(uid) {
  const snap = await getDoc(doc(db, 'vaults', uid));
  return snap.exists() ? snap.data() : null;
}
async function dbSave(uid, salt, vault) {
  await setDoc(doc(db, 'vaults', uid), { salt, vault });
}

/* ═══════════════════════════════════════════
   AUTH
═══════════════════════════════════════════ */
window.signInWithGoogle = async () => {
  try {
    await signInWithPopup(auth, new GoogleAuthProvider());
  } catch (e) {
    toast('Sign-in failed: ' + e.message);
  }
};

window.signOut = async () => {
  _key = null; _entries = []; _uid = null;
  await fbSignOut(auth);
  showPage('login');
};

window.lockVault = () => {
  _key = null; _entries = [];
  document.getElementById('master-input').value = '';
  document.getElementById('master-error').textContent = '';
  showPage('master');
  toast('Vault locked');
};

onAuthStateChanged(auth, async user => {
  if (!user) { showPage('login'); return; }

  _uid = user.uid;

  // Fill master page user info
  document.getElementById('master-avatar').src  = user.photoURL || '';
  document.getElementById('master-name').textContent  = user.displayName || '';
  document.getElementById('master-email').textContent = user.email || '';

  const vaultDoc = await dbLoad(user.uid).catch(() => null);
  const isNew = !vaultDoc;

  document.getElementById('master-title').textContent = isNew ? 'Create your vault' : 'Unlock your vault';
  document.getElementById('master-sub').textContent   = isNew
    ? 'Choose a master password to encrypt your vault.'
    : 'Enter your master password to access your passwords.';
  document.getElementById('new-hint').style.display = isNew ? 'flex' : 'none';

  showPage('master');
  setTimeout(() => document.getElementById('master-input').focus(), 120);
});

/* ═══════════════════════════════════════════
   MASTER PASSWORD
═══════════════════════════════════════════ */
window.submitMaster = async () => {
  const pw  = document.getElementById('master-input').value;
  const err = document.getElementById('master-error');
  err.textContent = '';

  if (pw.length < 6) { toast('Password must be at least 6 characters'); return; }

  try {
    toast('Unlocking…');
    const vaultDoc = await dbLoad(_uid);

    if (!vaultDoc) {
      // New vault
      const saltB64 = rndB64(32);
      const salt    = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
      const key     = await deriveKey(pw, salt);
      await dbSave(_uid, saltB64, await encryptData(key, []));
      _key = key; _entries = [];
    } else {
      // Existing vault
      const salt = Uint8Array.from(atob(vaultDoc.salt), c => c.charCodeAt(0));
      const key  = await deriveKey(pw, salt);
      _entries   = await decryptData(key, vaultDoc.vault); // throws if wrong pw
      _key = key;
    }

    // Populate nav user info (now that page-vault exists and is visible)
    const user = auth.currentUser;
    document.getElementById('nav-avatar').src   = user.photoURL || '';
    document.getElementById('drop-avatar').src  = user.photoURL || '';
    document.getElementById('drop-name').textContent  = user.displayName || '';
    document.getElementById('drop-email').textContent = user.email || '';
    document.getElementById('sb-avatar').src    = user.photoURL || '';
    document.getElementById('sb-name').textContent    = user.displayName?.split(' ')[0] || '';

    showPage('vault');
    renderEntries();
    syncStatus('synced');
    toast('Vault unlocked');
  } catch (e) {
    if (e.name === 'OperationError') {
      err.textContent = 'Incorrect master password.';
    } else {
      err.textContent = 'Error: ' + e.message;
    }
  }
};

/* ═══════════════════════════════════════════
   PERSIST
═══════════════════════════════════════════ */
async function persist() {
  syncStatus('saving');
  try {
    const snap = await getDoc(doc(db, 'vaults', _uid));
    await dbSave(_uid, snap.data().salt, await encryptData(_key, _entries));
    syncStatus('synced');
  } catch (e) {
    syncStatus('error');
    toast('Sync failed: ' + e.message);
  }
}

/* ═══════════════════════════════════════════
   CRUD
═══════════════════════════════════════════ */
window.saveEntry = async () => {
  const site  = document.getElementById('f-site').value.trim();
  const user  = document.getElementById('f-user').value.trim();
  const pass  = document.getElementById('f-pass').value;
  const url   = document.getElementById('f-url').value.trim();
  const notes = document.getElementById('f-notes').value.trim();
  const editId = document.getElementById('f-id').value;

  if (!site)  { toast('Enter a site name'); return; }
  if (!user)  { toast('Enter a username or email'); return; }
  if (!pass)  { toast('Enter a password'); return; }

  if (editId) {
    const i = _entries.findIndex(e => e.id === editId);
    if (i >= 0) _entries[i] = { ..._entries[i], site, user, pass, url, notes, updated: Date.now() };
  } else {
    _entries.unshift({ id: crypto.randomUUID(), site, user, pass, url, notes, created: Date.now(), updated: Date.now() });
  }

  closeModal('modal-add');
  renderEntries();
  await persist();
  toast(editId ? 'Entry updated' : 'Password saved');
};

window.deleteCurrent = async () => {
  if (!confirm('Delete this entry? This cannot be undone.')) return;
  _entries = _entries.filter(e => e.id !== _viewId);
  closeModal('modal-view');
  renderEntries();
  await persist();
  toast('Entry deleted');
};

window.editCurrent = () => {
  closeModal('modal-view');
  openAdd(_viewId);
};

/* ═══════════════════════════════════════════
   RENDER
═══════════════════════════════════════════ */
window.renderEntries = () => {
  const q      = (document.getElementById('search-desk')?.value || document.getElementById('search-mob')?.value || '').toLowerCase();
  const list   = document.getElementById('entry-list');
  const sbCnt  = document.getElementById('sb-count');
  const tbCnt  = document.getElementById('toolbar-count');

  if (sbCnt) sbCnt.textContent = _entries.length;
  if (tbCnt) tbCnt.textContent = _entries.length + ' item' + (_entries.length !== 1 ? 's' : '');

  const filtered = q
    ? _entries.filter(e => e.site.toLowerCase().includes(q) || e.user.toLowerCase().includes(q))
    : _entries;

  if (!filtered.length) {
    list.innerHTML = `
      <div class="empty-wrap">
        <div class="empty-ico">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h3>${q ? 'No results found' : 'Your vault is empty'}</h3>
        <p>${q ? 'Try a different search term.' : 'Add your first password to get started.'}</p>
      </div>`;
    return;
  }

  list.innerHTML = filtered.map(e => `
    <div class="entry-card" onclick="viewEntry('${e.id}')">
      <div class="entry-av">${e.site[0].toUpperCase()}</div>
      <div class="entry-info">
        <div class="entry-site">${esc(e.site)}</div>
        <div class="entry-user">${esc(e.user)}</div>
      </div>
      <div class="entry-btns" onclick="event.stopPropagation()">
        <button class="e-btn" onclick="quickCopy('${e.id}')">Copy</button>
        <button class="e-btn" onclick="viewEntry('${e.id}')">View</button>
      </div>
    </div>`).join('');
};

/* ═══════════════════════════════════════════
   UI ACTIONS
═══════════════════════════════════════════ */
window.onSearch = val => {
  document.getElementById('search-desk').value = val;
  document.getElementById('search-mob').value  = val;
  renderEntries();
};

window.viewEntry = id => {
  const e = _entries.find(x => x.id === id); if (!e) return;
  _viewId = id;
  document.getElementById('view-site-name').textContent = e.site;
  document.getElementById('view-av').textContent        = e.site[0].toUpperCase();
  document.getElementById('v-user').textContent         = e.user;
  document.getElementById('v-pass-show').textContent    = '••••••••••';
  document.getElementById('v-pass-show').style.letterSpacing = '';
  document.getElementById('v-pass-real').value          = e.pass;

  const urlRow   = document.getElementById('v-url-row');
  const notesRow = document.getElementById('v-notes-row');
  if (e.url)   { urlRow.style.display = 'block';   document.getElementById('v-url').textContent = e.url; document.getElementById('v-url-link').href = e.url; }
  else           urlRow.style.display = 'none';
  if (e.notes) { notesRow.style.display = 'block'; document.getElementById('v-notes').textContent = e.notes; }
  else           notesRow.style.display = 'none';

  openModal('modal-view');
};

window.toggleShowPass = () => {
  const el   = document.getElementById('v-pass-show');
  const real = document.getElementById('v-pass-real').value;
  if (el.textContent === '••••••••••') { el.textContent = real; el.style.letterSpacing = '0.04em'; }
  else { el.textContent = '••••••••••'; el.style.letterSpacing = ''; }
};

window.copyPass   = () => copy(document.getElementById('v-pass-real').value, 'Password copied');
window.copyById   = id => copy(document.getElementById(id).textContent, 'Copied');
window.quickCopy  = id => { const e = _entries.find(x => x.id === id); if (e) copy(e.pass, 'Password copied'); };

window.openAdd = (editId) => {
  const e = editId ? _entries.find(x => x.id === editId) : null;
  document.getElementById('add-title').textContent = e ? 'Edit entry' : 'Add password';
  document.getElementById('f-site').value  = e?.site  || '';
  document.getElementById('f-user').value  = e?.user  || '';
  document.getElementById('f-pass').value  = e?.pass  || '';
  document.getElementById('f-url').value   = e?.url   || '';
  document.getElementById('f-notes').value = e?.notes || '';
  document.getElementById('f-id').value    = editId   || '';
  document.getElementById('s-bar').style.width = '0';
  document.getElementById('s-lbl').textContent = '';
  openModal('modal-add');
};

window.filterAll = btn => {
  document.querySelectorAll('.sidebar-link').forEach(b => b.classList.remove('active'));
  btn.classList.add('active'); renderEntries();
};

// Generator
window.openGen = () => { genPw(); openModal('modal-gen'); };
window.genPw = () => {
  const len = parseInt(document.getElementById('gen-len').value);
  let c = '';
  if (document.getElementById('g-up').checked) c += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (document.getElementById('g-lo').checked) c += 'abcdefghijklmnopqrstuvwxyz';
  if (document.getElementById('g-nu').checked) c += '0123456789';
  if (document.getElementById('g-sy').checked) c += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!c) { document.getElementById('gen-out').textContent = 'Select at least one option'; return; }
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  _lastGen = Array.from(arr).map(n => c[n % c.length]).join('');
  document.getElementById('gen-out').textContent = _lastGen;
};
window.copyGen = () => _lastGen && copy(_lastGen, 'Password copied');
window.useGen  = () => {
  if (!_lastGen) return;
  closeModal('modal-gen');
  openAdd();
  setTimeout(() => {
    document.getElementById('f-pass').value = _lastGen;
    strengthCheck(document.getElementById('f-pass'), 's-bar', 's-lbl');
  }, 60);
};
window.injectGen = () => {
  if (_lastGen) {
    document.getElementById('f-pass').value = _lastGen;
    strengthCheck(document.getElementById('f-pass'), 's-bar', 's-lbl');
  } else { openGen(); }
};

// Sidebar
window.toggleSidebar = () => {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sb-overlay').classList.toggle('open');
};
window.closeSidebar = () => {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sb-overlay').classList.remove('open');
};

// User dropdown
window.toggleMenu = () => document.getElementById('dropdown-menu').classList.toggle('open');
window.closeMenu  = () => document.getElementById('dropdown-menu').classList.remove('open');
document.addEventListener('click', e => {
  const wrap = document.querySelector('.user-dropdown');
  if (wrap && !wrap.contains(e.target)) closeMenu();
});

/* ═══════════════════════════════════════════
   UTILITY
═══════════════════════════════════════════ */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
window.closeModal = id  => document.getElementById(id).classList.remove('open');

window.toggleVis = id => {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
};

window.strengthCheck = (input, barId, lblId) => {
  const v = input.value; let s = 0;
  if (v.length >= 8) s++; if (v.length >= 14) s++;
  if (/[A-Z]/.test(v)) s++; if (/[0-9]/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  const colors = ['#ef4444','#f97316','#eab308','#22c55e','#34d399'];
  const labels = ['very weak','weak','fair','strong','excellent'];
  const bar = document.getElementById(barId);
  bar.style.width      = s ? (s * 20) + '%' : '0';
  bar.style.background = s ? colors[s - 1] : '';
  const lbl = document.getElementById(lblId);
  if (lbl) lbl.textContent = s ? labels[s - 1] : '';
};

// Alias used in HTML oninput
window.strengthCheck;

function syncStatus(state) {
  const dot = document.getElementById('sync-dot');
  const txt = document.getElementById('sync-text');
  if (!dot) return;
  dot.className = 'sync-dot' + (state === 'saving' ? ' saving' : state === 'error' ? ' error' : '');
  if (txt) txt.textContent = state === 'saving' ? 'saving…' : state === 'error' ? 'error' : 'synced';
}

let _tt;
function toast(msg, dur = 2600) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(_tt); _tt = setTimeout(() => el.classList.remove('show'), dur);
}
window.showToast = toast;

function copy(text, msg = 'Copied') {
  navigator.clipboard.writeText(text).then(() => toast(msg));
}

function esc(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-bg.open').forEach(m => m.classList.remove('open'));
    closeSidebar(); closeMenu();
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'k' && _key) {
    e.preventDefault();
    const s = document.getElementById('search-desk') || document.getElementById('search-mob');
    s?.focus();
  }
});
