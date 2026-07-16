import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";

type AppPhase = "idle" | "inspecting" | "ready";
type AppMode = "file" | "disk" | "text";

const MODES: { id: AppMode; label: string }[] = [
  { id: "file", label: "File" },
  { id: "disk", label: "Disk" },
  { id: "text", label: "Text" },
];

/** Mirrors Rust `FileMeta` (snake_case JSON). */
type FileMeta = {
  name: string;
  format_label: string;
  size: number;
  modified_ms: number | null;
  crc32: string;
  md5: string;
  sha256: string;
  sha512: string;
};

/** Mirrors Rust `HashResult` (snake_case JSON). */
type HashResult = {
  format: string;
  source_name: string;
  hash_line: string;
  hashcat_mode: number | null;
  warnings: string[];
  error: string | null;
};

type InspectResult = {
  meta: FileMeta;
  hash: HashResult;
};

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

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatModified(ms: number | null): string {
  if (ms == null) return "—";
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

function toDetails(meta: FileMeta): FileDetails {
  return {
    name: meta.name,
    formatLabel: meta.format_label,
    sizeLabel: formatBytes(meta.size),
    modifiedLabel: formatModified(meta.modified_ms),
    crc32: meta.crc32,
    md5: meta.md5,
    sha256: meta.sha256,
    sha512: meta.sha512,
  };
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

function App() {
  const [mode, setMode] = useState<AppMode>("file");
  const [phase, setPhase] = useState<AppPhase>("idle");
  const [details, setDetails] = useState<FileDetails | null>(null);
  const [hash, setHash] = useState<HashResult | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(null), 2200);
  }

  function resetFileState() {
    setPhase("idle");
    setDetails(null);
    setHash(null);
  }

  function switchMode(next: AppMode) {
    if (next === mode) return;
    setMode(next);
    resetFileState();
  }

  async function openPicker() {
    try {
      const selected = await open({
        multiple: false,
        title: "Select encrypted file",
        filters: [
          {
            name: "Encrypted archives & documents",
            extensions: [
              "zip",
              "rar",
              "7z",
              "docx",
              "xlsx",
              "pptx",
              "doc",
              "xls",
              "ppt",
              "pdf",
            ],
          },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (selected == null) return;
      const path = typeof selected === "string" ? selected : selected[0];
      if (!path) return;
      await inspectPath(path);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Open dialog failed");
    }
  }

  async function inspectPath(path: string) {
    setPhase("inspecting");
    setDetails(null);
    setHash(null);
    try {
      const result = await invoke<InspectResult>("inspect_file", { path });
      setDetails(toDetails(result.meta));
      setHash(result.hash);
      setPhase("ready");
    } catch (err) {
      resetFileState();
      const message =
        typeof err === "string"
          ? err
          : err instanceof Error
            ? err.message
            : "Inspection failed";
      showToast(message);
    }
  }

  function reset() {
    resetFileState();
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
    if (!hash?.hash_line) {
      showToast("Nothing to copy");
      return;
    }
    copyText(hash.hash_line, "Hash");
  }

  async function exportHash() {
    if (!hash?.hash_line || !details) {
      showToast("Nothing to export");
      return;
    }
    const base = details.name.replace(/\.[^.]+$/, "") || details.name;
    try {
      const path = await save({
        title: "Export hash",
        defaultPath: `${base}.hash`,
        filters: [{ name: "Hash file", extensions: ["hash", "txt"] }],
      });
      if (path == null) return;
      await invoke("write_text_file", {
        path,
        contents: `${hash.hash_line}\n`,
      });
      showToast("Hash saved");
    } catch (err) {
      const message =
        typeof err === "string"
          ? err
          : err instanceof Error
            ? err.message
            : "Export failed";
      showToast(message);
    }
  }

  const showModeTabs = mode !== "file" || phase === "idle";
  const noticeLines =
    hash == null
      ? []
      : [
          ...(hash.error ? [hash.error] : []),
          ...hash.warnings,
          ...(hash.hashcat_mode != null
            ? [`hashcat -m ${hash.hashcat_mode}`]
            : []),
        ];

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

      {mode === "file" && phase === "idle" && (
        <section className="hero" aria-labelledby="brand-title">
          <p className="brand" id="brand-title">
            Catpasswd Hash Extract
          </p>
          <p className="tagline">
            Pick an encrypted file to detect details and export a crack-ready hash —
            all locally.
          </p>
          <button type="button" className="btn btn-primary btn-hero" onClick={() => void openPicker()}>
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
        <section className="status-panel" aria-live="polite" aria-busy="true">
          <div className="spinner" aria-hidden="true" />
          <p className="status-title">
            Inspecting file<span className="status-ellipsis" aria-hidden="true" />
          </p>
          <p className="status-hint">
            Large files may take a while — please wait
          </p>
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
              {hash.hash_line ? (
                <pre className="hash-line" tabIndex={0}>
                  {hash.hash_line}
                </pre>
              ) : (
                <p className="hash-empty">No hash extracted</p>
              )}
              {noticeLines.length > 0 && (
                <ul className="warnings">
                  {noticeLines.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              )}
              <div className="actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={copyHash}
                  disabled={!hash.hash_line}
                >
                  Copy hash
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => void exportHash()}
                  disabled={!hash.hash_line}
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
