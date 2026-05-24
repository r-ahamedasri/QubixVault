# ⬡ QuantumVault

**Post-quantum password manager — Google Sign-In + Firebase + AES-256-GCM**

Users sign in with their Google account. Their encrypted vault is stored in Firebase Firestore. All encryption/decryption happens in the browser — Firebase only ever stores ciphertext.

---

## 🔐 How it works

```
User clicks "Sign in with Google"
        ↓
Firebase Auth (Google OAuth)
        ↓
User enters Master Password
        ↓
PBKDF2 derives AES-256-GCM key (310,000 iterations)
        ↓
Key decrypts vault from Firestore
        ↓
All CRUD re-encrypts → saves back to Firestore
```

**Firebase stores per user:**
```json
{ "salt": "base64...", "vault": "base64-AES-256-GCM-ciphertext..." }
```
Nobody — not you, not Firebase, not Google — can read the passwords.

---

## 🚀 Setup (15 minutes)

### Step 1 — Create a Firebase project

1. Go to [console.firebase.google.com](https://console.firebase.google.com)
2. Click **Add project** → give it a name → Continue
3. Disable Google Analytics (optional) → **Create project**

### Step 2 — Enable Google Sign-In

1. In Firebase Console → **Authentication** → **Get started**
2. Click **Google** → Enable → enter your support email → **Save**

### Step 3 — Create Firestore database

1. Firebase Console → **Firestore Database** → **Create database**
2. Choose **Start in production mode** → pick a region → **Enable**
3. Go to **Rules** tab → replace with:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /vaults/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```
4. Click **Publish**

### Step 4 — Register your web app

1. Firebase Console → **Project settings** (gear icon) → **Your apps** → click `</>`
2. Give it a nickname (e.g. "QuantumVault") → **Register app**
3. Copy the `firebaseConfig` object shown

### Step 5 — Paste config into the code

Open `js/firebase.js` and replace the placeholder:

```js
const firebaseConfig = {
  apiKey:            "AIza...",
  authDomain:        "your-project.firebaseapp.com",
  projectId:         "your-project",
  storageBucket:     "your-project.appspot.com",
  messagingSenderId: "123456789",
  appId:             "1:123456...:web:abc123"
};
```

### Step 6 — Add your GitHub Pages domain to Firebase Auth

1. Firebase Console → **Authentication** → **Settings** → **Authorized domains**
2. Click **Add domain**
3. Add: `YOUR_USERNAME.github.io`

### Step 7 — Deploy to GitHub Pages

```bash
git init
git add .
git commit -m "init: QuantumVault"
git remote add origin https://github.com/YOUR_USERNAME/quantumvault
git push -u origin main
```

Then: **GitHub repo → Settings → Pages → Deploy from branch → main / (root)**

Your app: `https://YOUR_USERNAME.github.io/quantumvault`

---

## 📁 Project structure

```
quantumvault/
├── index.html        ← full app (login, master pw, vault screens)
├── css/style.css     ← dark UI
├── js/firebase.js    ← everything: auth, crypto, Firestore, UI
└── README.md
```

---

## ⚡ Features

- Google Sign-In (one click, no registration form)
- Master password screen after login (zero-knowledge layer)
- AES-256-GCM authenticated encryption
- PBKDF2 key derivation (310,000 iterations, random salt per user)
- Real-time sync to Firestore
- Password generator (cryptographically random)
- Search, add, edit, delete, copy-to-clipboard
- Lock vault (wipes key from memory without signing out)
- Keyboard: `Ctrl+K` search, `Esc` close modals

---

## 🛡 Security notes

- Master password is **never stored** anywhere
- Firebase only stores the encrypted blob and a random salt
- Each user gets their own unique PBKDF2 salt
- AES-GCM provides both confidentiality and integrity (tamper detection)
- Wrong master password = GCM auth tag failure = clear error, no data exposed

---

*MIT License — cybersecurity portfolio project*
