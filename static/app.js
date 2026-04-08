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

const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const extractFilename = (contentDisposition, fallback) => {
  const encodedMatch = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(contentDisposition || "");
  if (encodedMatch?.[1]) {
    try {
      return decodeURIComponent(encodedMatch[1]);
    } catch {
      return fallback;
    }
  }
  const match = /filename="([^"]+)"/i.exec(contentDisposition || "");
  return match?.[1] || fallback;
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

setupDropzone("encryptForm");
setupDropzone("decryptForm");
setupDropzone("hashForm");
handleBinaryForm("encryptForm", "/api/encrypt", "encrypted.enc");
handleBinaryForm("decryptForm", "/api/decrypt", "decrypted_file");
setupHashForm();
