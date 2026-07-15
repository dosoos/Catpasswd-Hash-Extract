import { useId, useRef, useState, type ChangeEvent } from "react";
import "./App.css";

type AppPhase = "idle" | "inspecting" | "ready";
type AppMode = "file" | "disk" | "text";

const MODES: { id: AppMode; label: string }[] = [
  { id: "file", label: "File" },
  { id: "disk", label: "Disk" },
  { id: "text", label: "Text" },
];

type FileDetails = {
  name: string;
  formatLabel: string;
  sizeLabel: string;
  modifiedLabel: string;
  crc32: string;
  md5: string;
  sha256: string;
  sha512: string;
};

type HashPreview = {
  format: string;
  hashLine: string;
  warnings: string[];
};

const ACCEPT =
  ".zip,.rar,.7z,.docx,.xlsx,.pptx,.doc,.xls,.ppt,.pdf,.odt,.ods,.odp";

/** UI mock: guess format from extension; real detection comes later via Rust. */
function guessFormat(name: string): { id: string; label: string } {
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, { id: string; label: string }> = {
    zip: { id: "zip", label: "ZIP" },
    rar: { id: "rar", label: "RAR / RAR5" },
    "7z": { id: "7z", label: "7-Zip" },
    docx: { id: "office", label: "Microsoft Office" },
    xlsx: { id: "office", label: "Microsoft Office" },
    pptx: { id: "office", label: "Microsoft Office" },
    doc: { id: "office", label: "Microsoft Office" },
    xls: { id: "office", label: "Microsoft Office" },
    ppt: { id: "office", label: "Microsoft Office" },
    pdf: { id: "pdf", label: "PDF" },
  };
  return map[ext] ?? { id: "unknown", label: "Unknown" };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatModified(ms: number): string {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(ms));
}

/** Placeholder digests for UI preview only. */
function mockDigest(seed: string, len: number): string {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  let out = "";
  while (out.length < len) {
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    out += (h >>> 0).toString(16).padStart(8, "0");
  }
  return out.slice(0, len);
}

function CopyIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
      <path
        fill="currentColor"
        d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"
      />
    </svg>
  );
}

function CopyableValue({
  value,
  label,
  onCopy,
}: {
  value: string;
  label: string;
  onCopy: (value: string, label: string) => void;
}) {
  return (
    <button
      type="button"
      className="copyable mono"
      onClick={() => onCopy(value, label)}
      title={`Copy ${label}`}
      aria-label={`Copy ${label}`}
    >
      <span className="copyable-text">{value}</span>
      <span className="copyable-icon">
        <CopyIcon />
      </span>
    </button>
  );
}

function buildMockPreview(file: File): { details: FileDetails; hash: HashPreview } {
  const guessed = guessFormat(file.name);
  const seed = `${file.name}:${file.size}:${file.lastModified}`;
  return {
    details: {
      name: file.name,
      formatLabel: guessed.label,
      sizeLabel: formatBytes(file.size),
      modifiedLabel: formatModified(file.lastModified),
      crc32: mockDigest(seed + ":crc32", 8),
      md5: mockDigest(seed + ":md5", 32),
      sha256: mockDigest(seed + ":sha256", 64),
      sha512: mockDigest(seed + ":sha512", 128),
    },
    hash: {
      format: guessed.id,
      hashLine:
        guessed.id === "unknown"
          ? ""
          : `$mock$${guessed.id}$${mockDigest(seed + ":hash", 40)}`,
      warnings:
        guessed.id === "unknown"
          ? ["UI preview: unrecognized file extension."]
          : ["UI preview: placeholder hash — native extraction not wired yet."],
    },
  };
}

function App() {
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<AppMode>("file");
  const [phase, setPhase] = useState<AppPhase>("idle");
  const [details, setDetails] = useState<FileDetails | null>(null);
  const [hash, setHash] = useState<HashPreview | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(null), 2200);
  }

  function resetFileState() {
    setPhase("idle");
    setDetails(null);
    setHash(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  function switchMode(next: AppMode) {
    if (next === mode) return;
    setMode(next);
    resetFileState();
  }

  function openPicker() {
    inputRef.current?.click();
  }

  function reset() {
    resetFileState();
  }

  function onFileChosen(file: File | undefined) {
    if (!file) return;
    setPhase("inspecting");
    setDetails(null);
    setHash(null);

    // Mock inspect delay; replace with Rust IPC later.
    window.setTimeout(() => {
      const preview = buildMockPreview(file);
      setDetails(preview.details);
      setHash(preview.hash);
      setPhase("ready");
    }, 480);
  }

  function onInputChange(e: ChangeEvent<HTMLInputElement>) {
    onFileChosen(e.target.files?.[0]);
  }

  function copyText(value: string, label: string) {
    if (!value) {
      showToast("Nothing to copy");
      return;
    }
    void navigator.clipboard.writeText(value).then(
      () => showToast(`${label} copied`),
      () => showToast("Copy failed"),
    );
  }

  function copyHash() {
    if (!hash?.hashLine) {
      showToast("Nothing to copy");
      return;
    }
    copyText(hash.hashLine, "Hash");
  }

  function exportHash() {
    showToast("Export not wired yet — UI preview only");
  }

  const showModeTabs = mode !== "file" || phase === "idle";

  return (
    <div className={showModeTabs ? "app" : "app app-result"}>
      {showModeTabs && (
        <nav className="mode-tabs" aria-label="Source type">
          {MODES.map((item) => (
            <button
              key={item.id}
              type="button"
              className={mode === item.id ? "mode-tab is-active" : "mode-tab"}
              aria-current={mode === item.id ? "page" : undefined}
              onClick={() => switchMode(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
      )}

      <input
        id={inputId}
        ref={inputRef}
        className="sr-only"
        type="file"
        accept={ACCEPT}
        onChange={onInputChange}
      />

      {mode === "file" && phase === "idle" && (
        <section className="hero" aria-labelledby="brand-title">
          <p className="brand" id="brand-title">
            Catpasswd Hash Extract
          </p>
          <p className="tagline">
            Pick an encrypted file to detect details and export a crack-ready hash —
            all locally.
          </p>
          <button type="button" className="btn btn-primary btn-hero" onClick={openPicker}>
            Select encrypted file
          </button>
          <p className="formats">
            Supports: ZIP · RAR/RAR5 · 7z · Microsoft Office · PDF
          </p>
        </section>
      )}

      {mode === "disk" && (
        <section className="hero" aria-labelledby="disk-title">
          <p className="brand" id="disk-title">
            Disk
          </p>
          <p className="tagline">
            Extract hashes from encrypted volumes such as BitLocker. Coming soon.
          </p>
          <button type="button" className="btn btn-primary btn-hero" disabled>
            Select volume
          </button>
          <p className="formats">Supports: BitLocker (planned)</p>
        </section>
      )}

      {mode === "text" && (
        <section className="hero" aria-labelledby="text-title">
          <p className="brand" id="text-title">
            Text
          </p>
          <p className="tagline">
            Hash plaintext or encrypted text strings for cracking workflows. Coming soon.
          </p>
          <button type="button" className="btn btn-primary btn-hero" disabled>
            Enter text
          </button>
          <p className="formats">Supports: plaintext → hash (planned)</p>
        </section>
      )}

      {mode === "file" && phase === "inspecting" && (
        <section className="status-panel" aria-live="polite">
          <div className="spinner" aria-hidden="true" />
          <p className="status-title">Inspecting file…</p>
          <p className="status-hint">Reading metadata and fingerprints (preview)</p>
        </section>
      )}

      {mode === "file" && phase === "ready" && details && hash && (
        <section className="workspace" aria-label="File result">
          <header className="workspace-head">
            <h1 className="file-name" title={details.name}>
              {details.name}
            </h1>
          </header>

          <div className="workspace-body">
            <div className="detail-block">
              <h2 className="block-label">File details</h2>
              <dl className="detail-grid">
                <div>
                  <dt>Format</dt>
                  <dd>{details.formatLabel}</dd>
                </div>
                <div>
                  <dt>Size</dt>
                  <dd>{details.sizeLabel}</dd>
                </div>
                <div>
                  <dt>Modified</dt>
                  <dd>{details.modifiedLabel}</dd>
                </div>
                <div className="span-2">
                  <dt>CRC32</dt>
                  <dd>
                    <CopyableValue
                      value={details.crc32}
                      label="CRC32"
                      onCopy={copyText}
                    />
                  </dd>
                </div>
                <div className="span-2">
                  <dt>MD5</dt>
                  <dd>
                    <CopyableValue
                      value={details.md5}
                      label="MD5"
                      onCopy={copyText}
                    />
                  </dd>
                </div>
                <div className="span-2">
                  <dt>SHA-256</dt>
                  <dd>
                    <CopyableValue
                      value={details.sha256}
                      label="SHA-256"
                      onCopy={copyText}
                    />
                  </dd>
                </div>
                <div className="span-2">
                  <dt>SHA-512</dt>
                  <dd>
                    <CopyableValue
                      value={details.sha512}
                      label="SHA-512"
                      onCopy={copyText}
                    />
                  </dd>
                </div>
              </dl>
            </div>

            <div className="hash-block">
              <h2 className="block-label">Hash</h2>
              {hash.hashLine ? (
                <pre className="hash-line" tabIndex={0}>
                  {hash.hashLine}
                </pre>
              ) : (
                <p className="hash-empty">No hash preview</p>
              )}
              {hash.warnings.length > 0 && (
                <ul className="warnings">
                  {hash.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              )}
              <div className="actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={copyHash}
                  disabled={!hash.hashLine}
                >
                  Copy hash
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={exportHash}
                  disabled={!hash.hashLine}
                >
                  Export .hash
                </button>
                <button
                  type="button"
                  className="btn btn-icon"
                  onClick={reset}
                  aria-label="Reset"
                  title="Reset"
                >
                  <svg
                    className="icon-reset"
                    viewBox="0 0 24 24"
                    width="18"
                    height="18"
                    aria-hidden="true"
                  >
                    <path
                      fill="currentColor"
                      d="M17.65 6.35A7.96 7.96 0 0 0 12 4a8 8 0 1 0 7.73 10h-2.08A6 6 0 1 1 12 6c1.66 0 3.14.69 4.22 1.78L13 11h7V4z"
                    />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}

export default App;
