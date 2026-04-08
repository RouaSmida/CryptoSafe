/**
 * app.js – CryptoSafe frontend logic.
 *
 * Handles:
 *   - Tab switching
 *   - Dark/light mode toggle (persisted in localStorage)
 *   - Drag-and-drop + click file selection for all three panels
 *   - Password strength indicator
 *   - API calls to the Flask backend (encrypt / decrypt / hash)
 *   - Progress animation, success/error alerts, and hash copy button
 */

"use strict";

/* ==========================================================================
   Constants
   ========================================================================== */
const API = {
  encrypt: "/api/encrypt",
  decrypt: "/api/decrypt",
  hash:    "/api/hash",
};

const MAX_BYTES = 50 * 1024 * 1024; // 50 MB

/* ==========================================================================
   Theme toggle
   ========================================================================== */
const themeToggle = document.getElementById("themeToggle");
const themeIcon   = document.getElementById("themeIcon");

/** Apply the saved theme on page load, defaulting to dark. */
(function initTheme() {
  const saved = localStorage.getItem("csTheme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  updateThemeIcon(saved);
}());

themeToggle.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme");
  const next    = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("csTheme", next);
  updateThemeIcon(next);
});

function updateThemeIcon(theme) {
  themeIcon.className = theme === "dark"
    ? "fa-solid fa-sun"
    : "fa-solid fa-moon";
}

/* ==========================================================================
   Tab navigation
   ========================================================================== */
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    // Deactivate all
    document.querySelectorAll(".tab-btn").forEach(b => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));

    // Activate selected
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");
    const panelId = `panel-${btn.dataset.tab}`;
    document.getElementById(panelId).classList.add("active");
  });
});

/* ==========================================================================
   Drop-zone / file-picker factory
   ========================================================================== */

/**
 * Set up drag-and-drop and click-to-browse for a panel.
 *
 * @param {Object} cfg
 *   dropZone   - the drop-zone element
 *   fileInput  - the hidden <input type="file">
 *   fileInfo   - the file-info bar element
 *   fileNameEl - element to display the file name
 *   fileSizeEl - element to display the formatted size
 *   clearBtn   - ✕ button inside the file-info bar
 *   actionBtn  - the Encrypt / Decrypt / Hash button
 *   onFileSet  - optional callback invoked when a file is chosen
 *   onFileClear- optional callback invoked when the file is cleared
 */
function setupDropZone(cfg) {
  const { dropZone, fileInput, fileInfo, fileNameEl, fileSizeEl,
          clearBtn, actionBtn, onFileSet, onFileClear } = cfg;

  // Click on the drop zone opens the picker (unless a link/label is clicked)
  dropZone.addEventListener("click", e => {
    if (e.target.tagName !== "LABEL") fileInput.click();
  });

  // File selected via picker
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) setFile(fileInput.files[0]);
  });

  // Drag-and-drop events
  dropZone.addEventListener("dragover", e => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });

  // Clear button
  clearBtn.addEventListener("click", () => {
    fileInput.value = "";
    fileInfo.classList.add("hidden");
    dropZone.classList.remove("hidden");
    actionBtn.disabled = true;
    if (onFileClear) onFileClear();
  });

  function setFile(file) {
    if (file.size > MAX_BYTES) {
      showAlert(cfg.alertEl, "error",
        `File is too large (${formatSize(file.size)}). Maximum allowed size is 50 MB.`);
      return;
    }
    fileNameEl.textContent = file.name;
    fileSizeEl.textContent = formatSize(file.size);
    fileInfo.classList.remove("hidden");
    actionBtn.disabled = false;
    if (onFileSet) onFileSet(file);
  }
}

/* ==========================================================================
   Password visibility toggle
   ========================================================================== */
document.querySelectorAll(".toggle-pw").forEach(btn => {
  btn.addEventListener("click", () => {
    const target = document.getElementById(btn.dataset.target);
    const isText = target.type === "text";
    target.type = isText ? "password" : "text";
    btn.querySelector("i").className = isText
      ? "fa-solid fa-eye"
      : "fa-solid fa-eye-slash";
  });
});

/* ==========================================================================
   Password strength meter (encrypt panel only)
   ========================================================================== */
const encPassword     = document.getElementById("encPassword");
const encStrengthBar  = document.getElementById("encStrengthBar");
const encStrengthLabel = document.getElementById("encStrengthLabel");

encPassword.addEventListener("input", () => {
  const score = passwordStrength(encPassword.value);
  const configs = [
    { pct: "0%",   bg: "transparent", label: "" },
    { pct: "25%",  bg: "#e63946",     label: "Weak" },
    { pct: "50%",  bg: "#f4a261",     label: "Fair" },
    { pct: "75%",  bg: "#ffb703",     label: "Good" },
    { pct: "100%", bg: "#2dc653",     label: "Strong" },
  ];
  const cfg = configs[score];
  encStrengthBar.style.width      = cfg.pct;
  encStrengthBar.style.background = cfg.bg;
  encStrengthLabel.textContent    = cfg.label;
});

/**
 * Very simple password strength scorer (0-4).
 *  1 = non-empty, 2 = ≥8 chars, 3 = mixed case + digit, 4 = + special char
 */
function passwordStrength(pw) {
  if (!pw) return 0;
  let score = 1;
  if (pw.length >= 8)           score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw)) score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;
  return score;
}

/* ==========================================================================
   ENCRYPT panel
   ========================================================================== */
const encDropZone  = document.getElementById("encDropZone");
const encFile      = document.getElementById("encFile");
const encFileInfo  = document.getElementById("encFileInfo");
const encFileName  = document.getElementById("encFileName");
const encFileSize  = document.getElementById("encFileSize");
const encClearBtn  = document.getElementById("encClearBtn");
const encBtn       = document.getElementById("encBtn");
const encProgress  = document.getElementById("encProgress");
const encAlert     = document.getElementById("encAlert");

setupDropZone({
  dropZone:   encDropZone,
  fileInput:  encFile,
  fileInfo:   encFileInfo,
  fileNameEl: encFileName,
  fileSizeEl: encFileSize,
  clearBtn:   encClearBtn,
  actionBtn:  encBtn,
  alertEl:    encAlert,
  onFileClear: () => hideAlert(encAlert),
});

encBtn.addEventListener("click", async () => {
  hideAlert(encAlert);

  const file     = encFile.files[0];
  const password = encPassword.value.trim();

  if (!file) {
    showAlert(encAlert, "error", "Please select a file first.");
    return;
  }
  if (!password) {
    showAlert(encAlert, "error", "Please enter a password.");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  form.append("password", password);

  setLoading(encBtn, encProgress, true);

  try {
    const resp = await fetch(API.encrypt, { method: "POST", body: form });
    if (!resp.ok) {
      const data = await resp.json();
      showAlert(encAlert, "error", data.error || "Encryption failed.");
      return;
    }
    const blob     = await resp.blob();
    const fname    = getDownloadName(resp) || `${file.name}.enc`;
    triggerDownload(blob, fname);
    showAlert(encAlert, "success", "File encrypted successfully. Download started.");
  } catch (err) {
    showAlert(encAlert, "error", `Network error: ${err.message}`);
  } finally {
    setLoading(encBtn, encProgress, false);
  }
});

/* ==========================================================================
   DECRYPT panel
   ========================================================================== */
const decDropZone  = document.getElementById("decDropZone");
const decFile      = document.getElementById("decFile");
const decFileInfo  = document.getElementById("decFileInfo");
const decFileName  = document.getElementById("decFileName");
const decFileSize  = document.getElementById("decFileSize");
const decClearBtn  = document.getElementById("decClearBtn");
const decBtn       = document.getElementById("decBtn");
const decPassword  = document.getElementById("decPassword");
const decProgress  = document.getElementById("decProgress");
const decAlert     = document.getElementById("decAlert");

setupDropZone({
  dropZone:   decDropZone,
  fileInput:  decFile,
  fileInfo:   decFileInfo,
  fileNameEl: decFileName,
  fileSizeEl: decFileSize,
  clearBtn:   decClearBtn,
  actionBtn:  decBtn,
  alertEl:    decAlert,
  onFileClear: () => hideAlert(decAlert),
});

decBtn.addEventListener("click", async () => {
  hideAlert(decAlert);

  const file     = decFile.files[0];
  const password = decPassword.value.trim();

  if (!file) {
    showAlert(decAlert, "error", "Please select an encrypted file first.");
    return;
  }
  if (!password) {
    showAlert(decAlert, "error", "Please enter the decryption password.");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  form.append("password", password);

  setLoading(decBtn, decProgress, true);

  try {
    const resp = await fetch(API.decrypt, { method: "POST", body: form });
    if (!resp.ok) {
      const data = await resp.json();
      showAlert(decAlert, "error", data.error || "Decryption failed.");
      return;
    }
    const blob  = await resp.blob();
    const fname = getDownloadName(resp) ||
                  (file.name.toLowerCase().endsWith(".enc")
                    ? file.name.slice(0, -4)
                    : file.name);
    triggerDownload(blob, fname);
    showAlert(decAlert, "success", "File decrypted successfully. Download started.");
  } catch (err) {
    showAlert(decAlert, "error", `Network error: ${err.message}`);
  } finally {
    setLoading(decBtn, decProgress, false);
  }
});

/* ==========================================================================
   HASH panel
   ========================================================================== */
const hashDropZone  = document.getElementById("hashDropZone");
const hashFile      = document.getElementById("hashFile");
const hashFileInfo  = document.getElementById("hashFileInfo");
const hashFileName  = document.getElementById("hashFileName");
const hashFileSize  = document.getElementById("hashFileSize");
const hashClearBtn  = document.getElementById("hashClearBtn");
const hashBtn       = document.getElementById("hashBtn");
const hashProgress  = document.getElementById("hashProgress");
const hashAlert     = document.getElementById("hashAlert");
const hashResult    = document.getElementById("hashResult");
const hashValue     = document.getElementById("hashValue");
const hashMeta      = document.getElementById("hashMeta");
const copyBtn       = document.getElementById("copyBtn");

setupDropZone({
  dropZone:   hashDropZone,
  fileInput:  hashFile,
  fileInfo:   hashFileInfo,
  fileNameEl: hashFileName,
  fileSizeEl: hashFileSize,
  clearBtn:   hashClearBtn,
  actionBtn:  hashBtn,
  alertEl:    hashAlert,
  onFileClear: () => {
    hideAlert(hashAlert);
    hashResult.classList.add("hidden");
  },
});

hashBtn.addEventListener("click", async () => {
  hideAlert(hashAlert);
  hashResult.classList.add("hidden");

  const file = hashFile.files[0];
  if (!file) {
    showAlert(hashAlert, "error", "Please select a file first.");
    return;
  }

  const form = new FormData();
  form.append("file", file);

  setLoading(hashBtn, hashProgress, true);

  try {
    const resp = await fetch(API.hash, { method: "POST", body: form });
    const data = await resp.json();

    if (!resp.ok) {
      showAlert(hashAlert, "error", data.error || "Hashing failed.");
      return;
    }

    hashValue.textContent = data.sha256;
    hashMeta.textContent  =
      `File: ${data.filename} · Size: ${formatSize(data.size)} · Algorithm: SHA-256`;
    hashResult.classList.remove("hidden");
  } catch (err) {
    showAlert(hashAlert, "error", `Network error: ${err.message}`);
  } finally {
    setLoading(hashBtn, hashProgress, false);
  }
});

/* Copy hash to clipboard */
copyBtn.addEventListener("click", async () => {
  const text = hashValue.textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.classList.add("copied");
    copyBtn.querySelector("i").className = "fa-solid fa-check";
    setTimeout(() => {
      copyBtn.classList.remove("copied");
      copyBtn.querySelector("i").className = "fa-solid fa-copy";
    }, 1800);
  } catch {
    // Fallback for browsers without clipboard API
    const sel = document.createRange();
    sel.selectNodeContents(hashValue);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(sel);
    document.execCommand("copy");
    window.getSelection().removeAllRanges();
  }
});

/* ==========================================================================
   Utility functions
   ========================================================================== */

/** Format bytes as a human-readable string (B, KB, MB). */
function formatSize(bytes) {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Trigger a file download from a Blob. */
function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement("a");
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Extract the filename from the Content-Disposition header.
 * Returns null if the header is absent or does not contain a filename.
 */
function getDownloadName(response) {
  const cd = response.headers.get("Content-Disposition") || "";
  const match = cd.match(/filename[^;=\n]*=(?:(['"])([^'"]*)\1|([^;\n]*))/i);
  return match ? (match[2] || match[3] || "").trim() : null;
}

/** Show / hide the loading state on a button + progress bar pair. */
function setLoading(btn, progressEl, loading) {
  btn.disabled = loading;
  if (loading) {
    progressEl.classList.remove("hidden");
  } else {
    progressEl.classList.add("hidden");
    // Re-enable btn only if a file is still selected (let drop-zone manage it)
    btn.disabled = false;
  }
}

/** Display a dismissible alert banner using safe DOM methods (no innerHTML). */
function showAlert(el, type, message) {
  // Wipe previous content without using innerHTML
  while (el.firstChild) el.removeChild(el.firstChild);
  el.className = `alert alert-${type}`;

  // Build icon element safely
  const icon = document.createElement("i");
  icon.className = type === "success"
    ? "fa-solid fa-circle-check"
    : "fa-solid fa-circle-exclamation";
  el.appendChild(icon);
  el.appendChild(document.createTextNode("\u00A0" + message));
}

/** Hide an alert banner. */
function hideAlert(el) {
  el.className = "alert hidden";
  while (el.firstChild) el.removeChild(el.firstChild);
}
