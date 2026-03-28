/**
 * ZeroVault — Zero-Trust Password Manager
 * ========================================
 * ZERO-TRUST GUARANTEE:
 *   • Master password never leaves this device.
 *   • AES-256-GCM encryption key is derived locally and is never transmitted.
 *   • The server stores only opaque encrypted blobs — it cannot read your data.
 *
 * CRYPTO SCHEME (Web Crypto API):
 *   1. Client generates a random 32-byte salt on registration.
 *   2. masterKey  = PBKDF2(masterPassword, salt, 600 000 iter, SHA-256) → 512 raw bits
 *   3. encKey     = first 256 bits  → imported as AES-256-GCM key (never leaves browser)
 *   4. authKey    = last  256 bits  → sent to server for authentication
 *   5. server stores SHA-256(authKey) — so neither the enc key nor master password
 *      is ever stored server-side.
 *   6. Each vault entry is encrypted with a unique 96-bit IV.
 *   7. Ciphertext format: { iv: <hex>, ct: <base64(AES-GCM ciphertext+tag)> }
 */

"use strict";

/* ─────────────────────────────────────────────────────────────────────────────
   CONSTANTS
───────────────────────────────────────────────────────────────────────────── */
const API      = "";          // same origin – Flask serves both static & API
const PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES        = 32;
const IV_BYTES          = 12;  // 96 bits – recommended for AES-GCM

/* ─────────────────────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────────────────────── */
let state = {
  token:      null,  // session token
  encKey:     null,  // CryptoKey – AES-256-GCM – never serialised
  entries:    [],    // decrypted vault entries [{id, site, username, password, notes, created_at, updated_at}]
  filtered:   [],    // currently displayed subset
};

/* ─────────────────────────────────────────────────────────────────────────────
   CRYPTO UTILITIES
───────────────────────────────────────────────────────────────────────────── */

/** Convert ArrayBuffer / Uint8Array → hex string */
function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert hex string → Uint8Array */
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** Convert ArrayBuffer → base64 string */
function toBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/** Convert base64 string → Uint8Array */
function fromBase64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/**
 * Derive encKey + authKey from masterPassword + saltHex.
 *
 * Returns { encKey: CryptoKey, authKeyHex: string }
 */
async function deriveKeys(masterPassword, saltHex) {
  const enc    = new TextEncoder();
  const rawPw  = enc.encode(masterPassword);
  const salt   = fromHex(saltHex);

  // Import password as PBKDF2 key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw", rawPw, "PBKDF2", false, ["deriveBits"]
  );

  // Derive 512 bits (64 bytes)
  const bits512 = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    512
  );

  const buf = new Uint8Array(bits512);

  // First 256 bits → AES-256-GCM encryption key
  const encKeyBytes = buf.slice(0, 32);
  const encKey = await crypto.subtle.importKey(
    "raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );

  // Last 256 bits → auth key (hex) sent to server
  const authKeyHex = toHex(buf.slice(32, 64));

  // Zero out the buffer as best-effort cleanup
  buf.fill(0);
  encKeyBytes.fill(0);

  return { encKey, authKeyHex };
}

/**
 * Encrypt a plaintext JS object with AES-256-GCM.
 * Returns JSON string: {"iv":"<hex>","ct":"<base64>"}
 */
async function encryptEntry(obj, encKey) {
  const iv        = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(obj));

  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encKey,
    plaintext
  );

  return JSON.stringify({ iv: toHex(iv), ct: toBase64(cipherBuf) });
}

/**
 * Decrypt an encrypted_data JSON string produced by encryptEntry.
 * Returns the original JS object, or null on failure.
 */
async function decryptEntry(encDataStr, encKey) {
  try {
    const { iv, ct } = JSON.parse(encDataStr);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromHex(iv) },
      encKey,
      fromBase64(ct)
    );
    return JSON.parse(new TextDecoder().decode(plainBuf));
  } catch {
    return null;
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
   API HELPERS
───────────────────────────────────────────────────────────────────────────── */

async function apiCall(method, path, body = null) {
  const opts = {
    method,
    headers: { "Content-Type": "application/json" },
  };
  if (state.token)
    opts.headers["Authorization"] = `Bearer ${state.token}`;
  if (body)
    opts.body = JSON.stringify(body);

  const res = await fetch(API + path, opts);
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data: json };
}

/* ─────────────────────────────────────────────────────────────────────────────
   PASSWORD STRENGTH
───────────────────────────────────────────────────────────────────────────── */

function passwordStrength(pw) {
  if (!pw) return { score: 0, label: "" };
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const labels = ["", "Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"];
  const colors = ["", "#ff4757", "#ff6b35", "#ffa502", "#ffdd57", "#2ed573", "#1e90ff", "#6c63ff"];
  const pct    = Math.round((score / 7) * 100);

  return {
    score,
    label: labels[Math.min(score, 7)] || "",
    color: colors[Math.min(score, 7)] || "",
    pct,
  };
}

/**
 * Generate a cryptographically random password.
 * Default: 20 chars, letters + digits + symbols.
 */
function generatePassword(length = 20) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => charset[b % charset.length]).join("");
}

/* ─────────────────────────────────────────────────────────────────────────────
   TOAST
───────────────────────────────────────────────────────────────────────────── */

let _toastTimer = null;
function showToast(msg, duration = 2500) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add("hidden"), duration);
}

/* ─────────────────────────────────────────────────────────────────────────────
   SCREEN TRANSITIONS
───────────────────────────────────────────────────────────────────────────── */

function showScreen(id) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
}

/* ─────────────────────────────────────────────────────────────────────────────
   MODAL HELPERS
───────────────────────────────────────────────────────────────────────────── */

function openModal(id) {
  document.getElementById(id).classList.remove("hidden");
}
function closeModal(id) {
  document.getElementById(id).classList.add("hidden");
}

/* ─────────────────────────────────────────────────────────────────────────────
   BUTTON LOADING STATE
───────────────────────────────────────────────────────────────────────────── */

function setLoading(btn, loading) {
  const text    = btn.querySelector(".btn-text");
  const spinner = btn.querySelector(".btn-spinner");
  btn.disabled = loading;
  if (text)    text.classList.toggle("hidden", loading);
  if (spinner) spinner.classList.toggle("hidden", !loading);
}

/* ─────────────────────────────────────────────────────────────────────────────
   VAULT RENDERING
───────────────────────────────────────────────────────────────────────────── */

function getFaviconLetter(site) {
  const clean = site.replace(/^https?:\/\//i, "").replace(/^www\./i, "");
  return clean.charAt(0).toUpperCase() || "?";
}

function renderEntries(entries) {
  const list        = document.getElementById("entry-list");
  const emptyVault  = document.getElementById("empty-state");
  const emptySearch = document.getElementById("search-empty");
  const countEl     = document.getElementById("entry-count");
  const query       = document.getElementById("search-input").value.trim();

  list.innerHTML = "";
  emptyVault.classList.add("hidden");
  emptySearch.classList.add("hidden");

  const total = state.entries.length;
  countEl.textContent = `${total} password${total !== 1 ? "s" : ""}`;

  if (total === 0) {
    emptyVault.classList.remove("hidden");
    return;
  }

  if (entries.length === 0 && query) {
    emptySearch.classList.remove("hidden");
    return;
  }

  entries.forEach(entry => {
    const card = document.createElement("div");
    card.className = "entry-card";
    card.dataset.id = entry.id;

    const maskedPw = "•".repeat(Math.min(entry.password.length, 14));

    card.innerHTML = `
      <div class="entry-favicon">${getFaviconLetter(entry.site)}</div>
      <div class="entry-info">
        <div class="entry-site">${escHtml(entry.site)}</div>
        <div class="entry-user">${escHtml(entry.username)}</div>
      </div>
      <div class="entry-pw-wrap">
        <span class="entry-pw" data-id="${entry.id}">${escHtml(maskedPw)}</span>
        <button class="icon-btn toggle-pw-btn" data-id="${entry.id}" title="Show/hide password">
          <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div class="entry-actions">
        <button class="icon-btn copy-btn" data-id="${entry.id}" title="Copy password">
          <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
        </button>
        <button class="icon-btn edit-btn" data-id="${entry.id}" title="Edit">
          <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="icon-btn danger delete-btn" data-id="${entry.id}" title="Delete">
          <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>
        </button>
      </div>
    `;
    list.appendChild(card);
  });
}

/** HTML-escape user content */
function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ─────────────────────────────────────────────────────────────────────────────
   VAULT OPERATIONS
───────────────────────────────────────────────────────────────────────────── */

async function loadVault() {
  const { ok, data } = await apiCall("GET", "/api/vault");
  if (!ok) { showToast("Failed to load vault"); return; }

  state.entries = [];
  for (const row of data.entries) {
    const plain = await decryptEntry(row.encrypted_data, state.encKey);
    if (plain) {
      state.entries.push({ ...plain, id: row.id, created_at: row.created_at, updated_at: row.updated_at });
    }
  }

  applySearch();
}

function applySearch() {
  const q = document.getElementById("search-input").value.trim().toLowerCase();
  document.getElementById("search-clear").classList.toggle("hidden", !q);

  if (!q) {
    state.filtered = [...state.entries];
  } else {
    state.filtered = state.entries.filter(e =>
      e.site.toLowerCase().includes(q) ||
      e.username.toLowerCase().includes(q) ||
      (e.notes || "").toLowerCase().includes(q)
    );
  }
  renderEntries(state.filtered);
}

/* ─────────────────────────────────────────────────────────────────────────────
   AUTH FLOWS
───────────────────────────────────────────────────────────────────────────── */

async function doRegister(username, password) {
  // 1. Generate random salt
  const saltBuf = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const saltHex = toHex(saltBuf);

  // 2. Derive keys
  const { encKey, authKeyHex } = await deriveKeys(password, saltHex);

  // 3. Register — send salt + SHA-256 of authKey as verifier
  const { ok, data } = await apiCall("POST", "/api/register", {
    username,
    salt: saltHex,
    auth_verifier: authKeyHex,
  });

  if (!ok) throw new Error(data.error || "Registration failed");

  // 4. Auto-login after registration
  const loginRes = await apiCall("POST", "/api/login", {
    username,
    auth_key: authKeyHex,
  });
  if (!loginRes.ok) throw new Error(loginRes.data.error || "Login failed");

  state.token  = loginRes.data.token;
  state.encKey = encKey;
}

async function doLogin(username, password) {
  // 1. Fetch user's salt
  const saltRes = await apiCall("POST", "/api/login/salt", { username });
  if (!saltRes.ok) throw new Error("Could not fetch salt");
  const saltHex = saltRes.data.salt;

  // 2. Derive keys using the retrieved salt
  const { encKey, authKeyHex } = await deriveKeys(password, saltHex);

  // 3. Authenticate
  const { ok, data } = await apiCall("POST", "/api/login", {
    username,
    auth_key: authKeyHex,
  });
  if (!ok) throw new Error(data.error || "Invalid credentials");

  state.token  = data.token;
  state.encKey = encKey;
}

async function doLogout() {
  await apiCall("POST", "/api/logout").catch(() => {});
  state.token  = null;
  state.encKey = null;
  state.entries = [];
  state.filtered = [];
  document.getElementById("entry-list").innerHTML = "";
  document.getElementById("search-input").value = "";
  showScreen("auth-screen");
}

/* ─────────────────────────────────────────────────────────────────────────────
   ENTRY CRUD
───────────────────────────────────────────────────────────────────────────── */

function openAddModal() {
  document.getElementById("modal-title").textContent = "Add Password";
  document.getElementById("edit-entry-id").value = "";
  document.getElementById("entry-site").value     = "";
  document.getElementById("entry-username").value  = "";
  document.getElementById("entry-password").value  = "";
  document.getElementById("entry-notes").value     = "";
  document.getElementById("entry-error").classList.add("hidden");
  // Reset password field to masked
  document.getElementById("entry-password").type = "password";
  openModal("entry-modal");
  document.getElementById("entry-site").focus();
}

function openEditModal(id) {
  const entry = state.entries.find(e => e.id === id);
  if (!entry) return;

  document.getElementById("modal-title").textContent    = "Edit Password";
  document.getElementById("edit-entry-id").value        = id;
  document.getElementById("entry-site").value           = entry.site;
  document.getElementById("entry-username").value        = entry.username;
  document.getElementById("entry-password").value        = entry.password;
  document.getElementById("entry-notes").value          = entry.notes || "";
  document.getElementById("entry-error").classList.add("hidden");
  document.getElementById("entry-password").type = "password";
  openModal("entry-modal");
}

async function saveEntry(e) {
  e.preventDefault();
  const site     = document.getElementById("entry-site").value.trim();
  const username = document.getElementById("entry-username").value.trim();
  const password = document.getElementById("entry-password").value;
  const notes    = document.getElementById("entry-notes").value.trim();
  const editId   = document.getElementById("edit-entry-id").value;
  const errEl    = document.getElementById("entry-error");
  const saveBtn  = document.getElementById("save-btn");

  errEl.classList.add("hidden");

  if (!site || !username || !password) {
    errEl.textContent = "Site, username, and password are required.";
    errEl.classList.remove("hidden");
    return;
  }

  setLoading(saveBtn, true);

  try {
    const payload = { site, username, password, notes };
    const encrypted_data = await encryptEntry(payload, state.encKey);

    if (editId) {
      const { ok, data } = await apiCall("PUT", `/api/vault/${editId}`, { encrypted_data });
      if (!ok) throw new Error(data.error || "Failed to update");

      // Update local state
      const idx = state.entries.findIndex(e => e.id === editId);
      if (idx !== -1) state.entries[idx] = { ...payload, id: editId, created_at: state.entries[idx].created_at, updated_at: new Date().toISOString() };
    } else {
      const { ok, data } = await apiCall("POST", "/api/vault", { encrypted_data });
      if (!ok) throw new Error(data.error || "Failed to save");

      state.entries.unshift({ ...payload, id: data.id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    }

    closeModal("entry-modal");
    applySearch();
    showToast(editId ? "Entry updated" : "Password saved");
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  } finally {
    setLoading(saveBtn, false);
  }
}

let _pendingDeleteId = null;
function openDeleteModal(id) {
  _pendingDeleteId = id;
  const entry = state.entries.find(e => e.id === id);
  document.getElementById("delete-entry-name").textContent = entry ? entry.site : "this entry";
  openModal("delete-modal");
}

async function confirmDelete() {
  if (!_pendingDeleteId) return;
  const id = _pendingDeleteId;
  _pendingDeleteId = null;
  closeModal("delete-modal");

  const { ok, data } = await apiCall("DELETE", `/api/vault/${id}`);
  if (!ok) { showToast(data.error || "Delete failed"); return; }

  state.entries = state.entries.filter(e => e.id !== id);
  applySearch();
  showToast("Entry deleted");
}

/* ─────────────────────────────────────────────────────────────────────────────
   CSV IMPORT  —  all parsing is client-side (zero trust preserved)
───────────────────────────────────────────────────────────────────────────── */

/**
 * RFC 4180-compliant CSV parser.
 * Handles: quoted fields, embedded commas, escaped quotes (""), CRLF/LF.
 * Returns an array of string arrays (rows × columns).
 */
function parseCSV(text) {
  const rows = [];
  const s = text.replace(/\r\n?/g, "\n");
  let i = 0;

  while (i < s.length) {
    const row = [];
    // Parse every field on this line
    while (i < s.length && s[i] !== "\n") {
      if (s[i] === '"') {
        // Quoted field — consume until closing unescaped quote
        i++;
        let val = "";
        while (i < s.length) {
          if (s[i] === '"' && s[i + 1] === '"') { val += '"'; i += 2; }
          else if (s[i] === '"')                 { i++; break; }
          else                                   { val += s[i++]; }
        }
        row.push(val);
        if (i < s.length && s[i] === ",") i++;
      } else {
        // Unquoted field — read until comma or newline
        let val = "";
        while (i < s.length && s[i] !== "," && s[i] !== "\n") val += s[i++];
        row.push(val);
        if (i < s.length && s[i] === ",") i++;
      }
    }
    if (i < s.length && s[i] === "\n") i++;
    // Drop blank rows (e.g. trailing newline)
    if (!(row.length === 1 && row[0] === "")) rows.push(row);
  }
  return rows;
}

/** Lowercase-and-trim a header cell, stripping any surrounding quotes. */
const normHeader = s => s.trim().toLowerCase().replace(/^"|"$/g, "");

/**
 * Given the header row, find the column index for each logical field.
 * Returns { format, siteIdx, urlIdx, userIdx, pwIdx }.
 */
function detectColumns(headerRow) {
  const h = headerRow.map(normHeader);

  const find = (...names) => { for (const n of names) { const i = h.indexOf(n); if (i !== -1) return i; } return -1; };

  const siteIdx = find("name", "title", "service", "label", "account");
  const urlIdx  = find("url", "website", "origin_url", "login_uri", "uri", "hostname", "web site");
  const userIdx = find("username", "user name", "user", "email", "login", "login_username", "account");
  const pwIdx   = find("password", "pass", "secret", "login_password");

  // Detect browser format from characteristic column patterns
  let format = "generic";
  if (h[0] === "name" && h.includes("url") && h.includes("username") && h.includes("password"))
    format = "chrome";   // Chrome / Edge / Brave
  else if (h[0] === "url" && h.includes("username") && h.includes("password") && h.includes("httprealm"))
    format = "firefox";
  else if (h[0] === "url" && h.includes("username") && h.includes("password"))
    format = "safari";

  return { format, siteIdx, urlIdx, userIdx, pwIdx };
}

/** Extract a clean domain from a URL string, or return the raw value on failure. */
function extractDomain(url) {
  try {
    const u = new URL(url.includes("://") ? url : "https://" + url);
    return u.hostname.replace(/^www\./, "");
  } catch {
    return url.split("/")[0] || url;
  }
}

/**
 * Convert parsed CSV rows to an array of vault-entry-shaped objects.
 * Throws a descriptive Error if required columns are missing.
 */
function csvRowsToEntries(rows) {
  if (rows.length < 2) throw new Error("The file appears to be empty or has no data rows.");

  const { format, siteIdx, urlIdx, userIdx, pwIdx } = detectColumns(rows[0]);

  if (userIdx === -1 || pwIdx === -1) {
    throw new Error(
      "Could not find username/password columns. " +
      "Make sure the file was exported directly from your browser."
    );
  }

  const entries = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const pw  = pwIdx !== -1 ? (row[pwIdx] || "").trim() : "";
    if (!pw) continue;  // skip blank-password rows (e.g. Chrome passkey stubs)

    const rawUrl  = urlIdx  !== -1 ? (row[urlIdx]  || "") : "";
    const rawUser = userIdx !== -1 ? (row[userIdx] || "").trim() : "";

    let site = siteIdx !== -1 ? (row[siteIdx] || "").trim() : "";
    if (!site && rawUrl) site = extractDomain(rawUrl);
    if (!site)           site = "Unknown";

    entries.push({ site, username: rawUser, password: pw, notes: "" });
  }

  if (!entries.length) throw new Error("No usable password entries found in the file.");
  return { entries, format };
}

/* ── Import UI state ── */
let _importEntries = [];

/** Returns true if an entry with the same site, username, and password already exists in the vault. */
function isDuplicate(entry) {
  return state.entries.some(e =>
    e.site.toLowerCase()     === entry.site.toLowerCase() &&
    e.username.toLowerCase() === entry.username.toLowerCase() &&
    e.password               === entry.password
  );
}

function resetImportModal() {
  _importEntries = [];
  const fileInput = document.getElementById("import-file-input");
  if (fileInput) fileInput.value = "";

  document.getElementById("import-step-select").classList.remove("hidden");
  document.getElementById("import-step-preview").classList.add("hidden");
  document.getElementById("import-back-btn").classList.add("hidden");
  document.getElementById("import-confirm-btn").classList.add("hidden");
  document.getElementById("import-parse-error").classList.add("hidden");
  document.getElementById("import-progress").classList.add("hidden");
  document.getElementById("import-error").classList.add("hidden");

  const dz = document.getElementById("file-drop-zone");
  dz.classList.remove("drag-over", "file-selected");
  document.getElementById("drop-zone-label").textContent = "Click to choose a CSV file";
}

function openImportModal() {
  resetImportModal();
  openModal("import-modal");
}

function showImportPreview(entries, format) {
  const dupCount = entries.filter(isDuplicate).length;
  const newCount = entries.length - dupCount;
  _importEntries = entries;

  document.getElementById("import-step-select").classList.add("hidden");
  document.getElementById("import-step-preview").classList.remove("hidden");
  document.getElementById("import-back-btn").classList.remove("hidden");

  // Format badge
  const badge = document.getElementById("import-format-badge");
  const labels = { chrome: "Chrome / Edge / Brave", firefox: "Firefox", safari: "Safari", generic: "Generic CSV" };
  badge.textContent = labels[format] || "CSV";
  badge.className   = `bbadge ${format || "generic"}`;

  // Count — show duplicate breakdown when relevant
  let countText = `Found ${entries.length} password${entries.length !== 1 ? "s" : ""}`;
  if (dupCount > 0) {
    countText += ` — ${newCount} new, ${dupCount} duplicate${dupCount !== 1 ? "s" : ""}`;
  }
  document.getElementById("import-count-text").textContent = countText;

  // Preview table (all rows, scroll container limits height)
  const tbody = document.getElementById("import-preview-tbody");
  tbody.innerHTML = "";
  entries.forEach(e => {
    const dup = isDuplicate(e);
    const tr = document.createElement("tr");
    if (dup) tr.classList.add("import-dup");
    tr.innerHTML = `
      <td title="${escHtml(e.site)}">${escHtml(e.site)}${dup ? ' <span class="dup-badge">duplicate</span>' : ""}</td>
      <td title="${escHtml(e.username)}">${escHtml(e.username)}</td>
      <td><span class="preview-pw">••••••••</span></td>`;
    tbody.appendChild(tr);
  });

  // Confirm button text — reflect only new entries to be imported
  const btn = document.getElementById("import-confirm-btn");
  btn.querySelector(".btn-text").textContent =
    newCount > 0
      ? `Import ${newCount} new password${newCount !== 1 ? "s" : ""}`
      : "Nothing new to import";
  btn.classList.remove("hidden");
}

function handleImportFile(file) {
  if (!file) return;
  const errEl = document.getElementById("import-parse-error");
  errEl.classList.add("hidden");

  if (!file.name.toLowerCase().endsWith(".csv") && file.type !== "text/csv") {
    errEl.textContent = "Please select a .csv file.";
    errEl.classList.remove("hidden");
    return;
  }

  // Show filename in drop zone
  const dz = document.getElementById("file-drop-zone");
  dz.classList.add("file-selected");
  document.getElementById("drop-zone-label").textContent = file.name;

  const reader = new FileReader();
  reader.onload = ev => {
    try {
      const rows = parseCSV(ev.target.result);
      const { entries, format } = csvRowsToEntries(rows);
      showImportPreview(entries, format);
    } catch (err) {
      dz.classList.remove("file-selected");
      document.getElementById("drop-zone-label").textContent = "Click to choose a CSV file";
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    }
  };
  reader.onerror = () => {
    errEl.textContent = "Could not read the file.";
    errEl.classList.remove("hidden");
  };
  reader.readAsText(file, "utf-8");
}

async function runImport() {
  const entries  = _importEntries;
  if (!entries.length) return;

  const toImport = entries.filter(e => !isDuplicate(e));

  if (!toImport.length) {
    closeModal("import-modal");
    showToast("All entries already exist in your vault", 3000);
    return;
  }

  const confirmBtn   = document.getElementById("import-confirm-btn");
  const backBtn      = document.getElementById("import-back-btn");
  const progressEl   = document.getElementById("import-progress");
  const progressFill = document.getElementById("import-progress-fill");
  const progressText = document.getElementById("import-progress-text");
  const errorEl      = document.getElementById("import-error");

  setLoading(confirmBtn, true);
  backBtn.disabled = true;
  progressEl.classList.remove("hidden");
  errorEl.classList.add("hidden");

  let done = 0, failed = 0;
  const total = toImport.length;

  for (const entry of toImport) {
    try {
      const encrypted_data = await encryptEntry(entry, state.encKey);
      const { ok, data }   = await apiCall("POST", "/api/vault", { encrypted_data });
      if (ok) {
        state.entries.unshift({
          ...entry,
          id: data.id,
          created_at:  new Date().toISOString(),
          updated_at:  new Date().toISOString(),
        });
        done++;
      } else {
        failed++;
      }
    } catch {
      failed++;
    }

    const pct = Math.round(((done + failed) / total) * 100);
    progressFill.style.width = `${pct}%`;
    progressText.textContent = `Encrypting & saving ${done + failed} / ${total}…`;
  }

  applySearch();
  closeModal("import-modal");

  const msg = failed === 0
    ? `Imported ${done} password${done !== 1 ? "s" : ""} successfully`
    : `Imported ${done} passwords — ${failed} failed`;
  showToast(msg, failed ? 4000 : 2500);
}

/* ─────────────────────────────────────────────────────────────────────────────
   EVENT WIRING
───────────────────────────────────────────────────────────────────────────── */

function showError(elId, msg) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.classList.remove("hidden");
}
function clearError(elId) {
  document.getElementById(elId).classList.add("hidden");
}

document.addEventListener("DOMContentLoaded", () => {

  /* ── Auth tabs ── */
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".auth-form").forEach(f => f.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`${btn.dataset.tab}-form`).classList.add("active");
      clearError("login-error");
      clearError("reg-error");
    });
  });

  /* ── Eye (reveal) buttons ── */
  document.querySelectorAll(".eye-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.target);
      input.type = input.type === "password" ? "text" : "password";
    });
  });

  /* ── Password strength meter ── */
  document.getElementById("reg-password").addEventListener("input", e => {
    const { pct, label, color } = passwordStrength(e.target.value);
    const fill  = document.getElementById("strength-fill");
    const lbl   = document.getElementById("strength-label");
    fill.style.width      = `${pct}%`;
    fill.style.background = color;
    lbl.textContent       = label;
    lbl.style.color       = color;
  });

  /* ── Login form ── */
  document.getElementById("login-form").addEventListener("submit", async e => {
    e.preventDefault();
    clearError("login-error");
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const btn      = document.getElementById("login-btn");

    if (!username || !password) {
      showError("login-error", "Please enter username and password."); return;
    }

    setLoading(btn, true);
    try {
      await doLogin(username, password);
      showScreen("vault-screen");
      await loadVault();
    } catch (err) {
      showError("login-error", err.message);
    } finally {
      setLoading(btn, false);
    }
  });

  /* ── Register form ── */
  document.getElementById("register-form").addEventListener("submit", async e => {
    e.preventDefault();
    clearError("reg-error");
    const username = document.getElementById("reg-username").value.trim();
    const password = document.getElementById("reg-password").value;
    const confirm  = document.getElementById("reg-confirm").value;
    const btn      = document.getElementById("register-btn");

    if (!username || !password) {
      showError("reg-error", "Username and password are required."); return;
    }
    if (username.length < 3) {
      showError("reg-error", "Username must be at least 3 characters."); return;
    }
    if (password.length < 8) {
      showError("reg-error", "Master password must be at least 8 characters."); return;
    }
    if (password !== confirm) {
      showError("reg-error", "Passwords do not match."); return;
    }

    setLoading(btn, true);
    try {
      await doRegister(username, password);
      showScreen("vault-screen");
      await loadVault();
    } catch (err) {
      showError("reg-error", err.message);
    } finally {
      setLoading(btn, false);
    }
  });

  /* ── Logout ── */
  document.getElementById("logout-btn").addEventListener("click", doLogout);

  /* ── Search ── */
  document.getElementById("search-input").addEventListener("input", applySearch);
  document.getElementById("search-clear").addEventListener("click", () => {
    document.getElementById("search-input").value = "";
    applySearch();
  });

  /* ── Add button ── */
  document.getElementById("add-btn").addEventListener("click", openAddModal);

  /* ── Entry modal close ── */
  document.getElementById("modal-close").addEventListener("click", () => closeModal("entry-modal"));
  document.getElementById("modal-cancel").addEventListener("click", () => closeModal("entry-modal"));

  /* ── Generate password ── */
  document.getElementById("gen-password-btn").addEventListener("click", () => {
    const pw = generatePassword(20);
    const input = document.getElementById("entry-password");
    input.value = pw;
    input.type  = "text";
    showToast("Strong password generated");
  });

  /* ── Save entry form ── */
  document.getElementById("entry-form").addEventListener("submit", saveEntry);

  /* ── Delete modal ── */
  document.getElementById("delete-modal-close").addEventListener("click", () => closeModal("delete-modal"));
  document.getElementById("delete-cancel").addEventListener("click", () => closeModal("delete-modal"));
  document.getElementById("delete-confirm").addEventListener("click", confirmDelete);

  /* ── Close modals on overlay click ── */
  ["entry-modal", "delete-modal", "import-modal"].forEach(id => {
    document.getElementById(id).addEventListener("click", e => {
      if (e.target === e.currentTarget) closeModal(id);
    });
  });

  /* ── Import modal ── */
  document.getElementById("import-btn").addEventListener("click", openImportModal);

  document.getElementById("import-modal-close").addEventListener("click", () => closeModal("import-modal"));
  document.getElementById("import-cancel").addEventListener("click", () => closeModal("import-modal"));

  document.getElementById("import-back-btn").addEventListener("click", () => {
    resetImportModal();  // go back to file-pick step
  });

  document.getElementById("import-confirm-btn").addEventListener("click", runImport);

  /* File input change */
  document.getElementById("import-file-input").addEventListener("change", e => {
    handleImportFile(e.target.files[0]);
  });

  /* Drag-and-drop on the drop zone */
  const dropZone = document.getElementById("file-drop-zone");
  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    const file = e.dataTransfer?.files?.[0];
    if (file) handleImportFile(file);
  });

  /* ── Entry list event delegation ── */
  document.getElementById("entry-list").addEventListener("click", async e => {
    const copyBtn   = e.target.closest(".copy-btn");
    const editBtn   = e.target.closest(".edit-btn");
    const deleteBtn = e.target.closest(".delete-btn");
    const toggleBtn = e.target.closest(".toggle-pw-btn");

    if (copyBtn) {
      const id    = copyBtn.dataset.id;
      const entry = state.entries.find(e => e.id === id);
      if (!entry) return;
      try {
        await navigator.clipboard.writeText(entry.password);
        copyBtn.classList.add("copy-success");
        showToast("Password copied to clipboard");
        setTimeout(() => copyBtn.classList.remove("copy-success"), 1500);
      } catch {
        showToast("Copy not available — use HTTPS");
      }
      return;
    }

    if (editBtn) {
      openEditModal(editBtn.dataset.id);
      return;
    }

    if (deleteBtn) {
      openDeleteModal(deleteBtn.dataset.id);
      return;
    }

    if (toggleBtn) {
      const id    = toggleBtn.dataset.id;
      const entry = state.entries.find(e => e.id === id);
      if (!entry) return;
      const pwSpan = document.querySelector(`.entry-pw[data-id="${id}"]`);
      if (!pwSpan) return;
      const showing = pwSpan.dataset.showing === "true";
      if (showing) {
        pwSpan.textContent  = "•".repeat(Math.min(entry.password.length, 14));
        pwSpan.dataset.showing = "false";
      } else {
        pwSpan.textContent  = entry.password;
        pwSpan.dataset.showing = "true";
      }
      return;
    }
  });

  /* ── Keyboard shortcuts ── */
  document.addEventListener("keydown", e => {
    // Esc closes open modals
    if (e.key === "Escape") {
      if (!document.getElementById("entry-modal").classList.contains("hidden"))  closeModal("entry-modal");
      if (!document.getElementById("delete-modal").classList.contains("hidden")) closeModal("delete-modal");
      if (!document.getElementById("import-modal").classList.contains("hidden")) closeModal("import-modal");
    }
    // Ctrl+F / Cmd+F focuses search when on vault screen
    if ((e.ctrlKey || e.metaKey) && e.key === "f") {
      const searchInput = document.getElementById("search-input");
      if (document.getElementById("vault-screen").classList.contains("active")) {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
    }
  });
});
