const bytesToSize = (bytes) => {
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
};

const setMessage = (formId, text, isError = false) => {
  const el = document.querySelector(`[data-msg-for="${formId}"]`);
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("error", Boolean(text && isError));
  el.classList.toggle("success", Boolean(text && !isError));
};

const updateFileMeta = (formId, file) => {
  const el = document.querySelector(`[data-meta-for="${formId}"]`);
  if (!el) return;
  el.textContent = file ? `${file.name} (${bytesToSize(file.size)})` : "";
};

const evaluatePassword = (password) => {
  const checks = {
    length: password.length >= 12,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /\d/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
  };
  const passed = Object.values(checks).filter(Boolean).length;

  let label = "Weak";
  if (passed >= 5) label = "Strong";
  else if (passed >= 3) label = "Medium";

  return { passed, label };
};

const setupPasswordMeter = (formId) => {
  const form = document.getElementById(formId);
  if (!form) return;

  const passwordInput = form.querySelector('input[type="password"][name="password"]');
  const bar = document.querySelector(`[data-meter-bar-for="${formId}"]`);
  const hint = document.querySelector(`[data-hint-for="${formId}"]`);
  if (!passwordInput || !bar || !hint) return;

  const render = () => {
    const { passed, label } = evaluatePassword(passwordInput.value || "");
    const pct = Math.max(6, (passed / 5) * 100);
    bar.style.width = `${pct}%`;
    bar.dataset.strength = label.toLowerCase();
    hint.textContent = `Password strength: ${label}`;
  };

  passwordInput.addEventListener("input", render);
  render();
};

const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const extractFilename = (contentDisposition, fallback) => {
  const value = contentDisposition || "";
  const encodedMatch = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(value);
  if (encodedMatch?.[1]) {
    try {
      return decodeURIComponent(encodedMatch[1]);
    } catch {
      return fallback;
    }
  }

  // Support both quoted and unquoted filename formats.
  const quotedMatch = /filename\s*=\s*"([^"]+)"/i.exec(value);
  if (quotedMatch?.[1]) return quotedMatch[1];

  const unquotedMatch = /filename\s*=\s*([^;\r\n]+)/i.exec(value);
  if (unquotedMatch?.[1]) return unquotedMatch[1].trim();

  return fallback;
};

const setupDropzone = (formId) => {
  const form = document.getElementById(formId);
  const dropzone = form?.querySelector(".dropzone");
  const fileInput = form?.querySelector('input[type="file"]');
  if (!form || !dropzone || !fileInput) return;

  fileInput.addEventListener("change", () => updateFileMeta(formId, fileInput.files[0]));

  ["dragenter", "dragover"].forEach((eventName) =>
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add("drag-over");
    }),
  );
  ["dragleave", "drop"].forEach((eventName) =>
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-over");
    }),
  );
  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    updateFileMeta(formId, file);
  });
};

const handleBinaryForm = (formId, endpoint, fallbackName) => {
  const form = document.getElementById(formId);
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setMessage(formId, "Processing...");

    const formData = new FormData(form);
    try {
      const response = await fetch(endpoint, { method: "POST", body: formData });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || "Request failed.");
      }

      const blob = await response.blob();
      const filename = extractFilename(response.headers.get("Content-Disposition"), fallbackName);
      downloadBlob(blob, filename);
      setMessage(formId, "Done. File downloaded successfully.");
    } catch (err) {
      setMessage(formId, err.message || "Unable to process file. Please check your file and try again.", true);
    }
  });
};

const setupHashForm = () => {
  const formId = "hashForm";
  const form = document.getElementById(formId);
  const hashInput = document.getElementById("hashValue");
  const copyBtn = document.getElementById("copyHashBtn");
  if (!form || !hashInput || !copyBtn) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setMessage(formId, "Generating hash...");
    hashInput.value = "";

    const formData = new FormData(form);
    try {
      const response = await fetch("/api/hash", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Hashing failed.");

      hashInput.value = payload.sha256;
      setMessage(formId, `SHA-256 generated for ${payload.fileName}`);
    } catch (err) {
      setMessage(formId, err.message || "Unable to generate hash. Please check your file and try again.", true);
    }
  });

  copyBtn.addEventListener("click", async () => {
    if (!hashInput.value) {
      setMessage(formId, "Generate a hash first.", true);
      return;
    }
    try {
      await navigator.clipboard.writeText(hashInput.value);
      setMessage(formId, "Hash copied to clipboard.");
    } catch {
      setMessage(formId, "Could not copy hash automatically.", true);
    }
  });
};

const setupVerifyForm = () => {
  const formId = "verifyForm";
  const form = document.getElementById(formId);
  const resultEl = document.getElementById("verifyResult");
  if (!form || !resultEl) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setMessage(formId, "Verifying hash...");
    resultEl.textContent = "";
    resultEl.className = "hash-verify-result";

    const formData = new FormData(form);
    try {
      const response = await fetch("/api/verify-hash", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Verification failed.");

      if (payload.matches) {
        resultEl.textContent = `Match confirmed for ${payload.fileName}`;
        resultEl.classList.add("ok");
      } else {
        resultEl.textContent = `Mismatch. Expected ${payload.expected}, got ${payload.actual}`;
        resultEl.classList.add("bad");
      }
      setMessage(formId, "Verification complete.");
    } catch (err) {
      setMessage(formId, err.message || "Could not verify file hash.", true);
    }
  });
};

setupDropzone("encryptForm");
setupDropzone("decryptForm");
setupDropzone("hashForm");
setupDropzone("verifyForm");
setupPasswordMeter("encryptForm");
setupPasswordMeter("decryptForm");
handleBinaryForm("encryptForm", "/api/encrypt", "encrypted.enc");
handleBinaryForm("decryptForm", "/api/decrypt", "decrypted_file");
setupHashForm();
setupVerifyForm();
