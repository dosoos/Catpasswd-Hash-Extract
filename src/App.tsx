import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";

type AppPhase = "idle" | "picking" | "inspecting" | "ready";
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

type PartitionInfo = {
  id: string;
  disk_index: number;
  partition_index: number;
  offset: number;
  size: number;
  letter: string | null;
  label: string;
  file_system: string | null;
  kind: string;
  status: string;
  selectable: boolean;
};

type DiskInfo = {
  index: number;
  name: string;
  layout: string;
  size: number;
  status: string;
  partitions: PartitionInfo[];
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
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
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

/** Clipboard copy is disabled above this size (UTF-16 code units ≈ bytes for hex). */
const HASH_COPY_MAX_CHARS = 256 * 1024;
/** Rough budget so the preview wraps to about three lines (no scrollbar). */
const HASH_PREVIEW_HEAD = 100;
const HASH_PREVIEW_TAIL = 24;

/** Truncate long hashes as `head......tail` for a short wrapped preview. */
function previewHashLine(hash: string): string {
  const ellipsis = "......";
  const maxShown = HASH_PREVIEW_HEAD + ellipsis.length + HASH_PREVIEW_TAIL;
  if (hash.length <= maxShown) return hash;
  return `${hash.slice(0, HASH_PREVIEW_HEAD)}${ellipsis}${hash.slice(-HASH_PREVIEW_TAIL)}`;
}

function isHashTooLargeToCopy(hash: string): boolean {
  return hash.length > HASH_COPY_MAX_CHARS;
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

function partitionTitle(part: PartitionInfo): string {
  if (part.kind === "unallocated") return "Unallocated";
  const letter = part.letter ? `(${part.letter}:)` : "";
  const label = part.label.trim();
  if (label && letter) return `${label} ${letter}`;
  if (label) return label;
  if (letter) return letter;
  return part.kind.charAt(0).toUpperCase() + part.kind.slice(1);
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
  const [disks, setDisks] = useState<DiskInfo[]>([]);
  const [selectedPartId, setSelectedPartId] = useState<string | null>(null);
  const [diskLoading, setDiskLoading] = useState(false);

  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(null), 2200);
  }

  function resetSourceState() {
    setPhase("idle");
    setDetails(null);
    setHash(null);
    setDisks([]);
    setSelectedPartId(null);
    setDiskLoading(false);
  }

  function switchMode(next: AppMode) {
    if (next === mode) return;
    setMode(next);
    resetSourceState();
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
      resetSourceState();
      const message =
        typeof err === "string"
          ? err
          : err instanceof Error
            ? err.message
            : "Inspection failed";
      showToast(message);
    }
  }

  async function openDiskPicker() {
    setDiskLoading(true);
    setSelectedPartId(null);
    try {
      const list = await invoke<DiskInfo[]>("list_disks");
      setDisks(list);
      setPhase("picking");
      if (list.length === 0) {
        showToast("No disks found");
      }
    } catch (err) {
      const raw =
        typeof err === "string"
          ? err
          : err instanceof Error
            ? err.message
            : "Failed to list disks";
      const message = /admin|access|denied|permission/i.test(raw)
        ? "Need Administrator to list disks — close the app and Run as administrator."
        : raw;
      showToast(message);
      setPhase("idle");
    } finally {
      setDiskLoading(false);
    }
  }

  async function confirmDiskSelection() {
    const part = disks
      .flatMap((d) => d.partitions)
      .find((p) => p.id === selectedPartId);
    if (!part || !part.selectable) {
      showToast("Select a partition");
      return;
    }
    setPhase("inspecting");
    setDetails(null);
    setHash(null);
    try {
      const result = await invoke<InspectResult>("inspect_volume", {
        diskIndex: part.disk_index,
        partitionIndex: part.partition_index,
      });
      setDetails(toDetails(result.meta));
      setHash(result.hash);
      setPhase("ready");
    } catch (err) {
      setPhase("picking");
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
    resetSourceState();
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
    if (isHashTooLargeToCopy(hash.hash_line)) {
      showToast("Hash too large to copy — use Export .hash");
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

  const showModeTabs = phase === "idle" || phase === "picking";
  const hashTooLargeToCopy =
    hash != null && hash.hash_line.length > 0 && isHashTooLargeToCopy(hash.hash_line);

  const noticeLines =
    hash == null
      ? []
      : [
          ...(hash.error ? [hash.error] : []),
          ...hash.warnings,
          ...(hash.hashcat_mode != null
            ? [`hashcat -m ${hash.hashcat_mode}`]
            : []),
          ...(hashTooLargeToCopy
            ? ["Hash too large to copy — use Export .hash"]
            : []),
        ];

  const selectedPart = disks
    .flatMap((d) => d.partitions)
    .find((p) => p.id === selectedPartId);

  return (
    <div
      className={
        phase === "picking" ? "app app-disk-pick" : showModeTabs ? "app" : "app app-result"
      }
    >
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
          <button
            type="button"
            className="btn btn-primary btn-hero"
            onClick={() => void openPicker()}
          >
            Select encrypted file
          </button>
          <p className="formats">
            Supports: ZIP · RAR/RAR5 · 7z · Microsoft Office · PDF
          </p>
        </section>
      )}

      {mode === "disk" && phase === "idle" && (
        <section className="hero" aria-labelledby="disk-title">
          <p className="brand" id="disk-title">
            Disk
          </p>
          <p className="tagline">
            Select a volume to extract a BitLocker hash locally — same result flow as
            files.
          </p>
          <button
            type="button"
            className="btn btn-primary btn-hero"
            onClick={() => void openDiskPicker()}
            disabled={diskLoading}
          >
            {diskLoading ? "Loading disks…" : "Select volume"}
          </button>
          <p className="formats">
            Supports: BitLocker (Windows). If listing fails, restart the app as
            Administrator.
          </p>
        </section>
      )}

      {mode === "disk" && phase === "picking" && (
        <section className="disk-picker" aria-label="Disk and partition map">
          <header className="disk-picker-head">
            <h1 className="disk-picker-title">Select a volume</h1>
            <p className="disk-picker-hint">
              Click a partition, then confirm. Unallocated space cannot be selected.
            </p>
          </header>

          <div className="disk-map" role="list">
            {disks.map((disk) => {
              const total = Math.max(disk.size, 1);
              return (
                <div key={disk.index} className="disk-row" role="listitem">
                  <div className="disk-meta">
                    <div className="disk-meta-name">{disk.name}</div>
                    <div className="disk-meta-line">{disk.layout}</div>
                    <div className="disk-meta-line">{formatBytes(disk.size)}</div>
                    <div className="disk-meta-line">{disk.status}</div>
                  </div>
                  <div className="disk-track" role="group" aria-label={disk.name}>
                    {disk.partitions.map((part) => {
                      const weight = Math.max(part.size / total, 0.01);
                      const selected = part.id === selectedPartId;
                      const title = partitionTitle(part);
                      return (
                        <button
                          key={part.id}
                          type="button"
                          className={[
                            "disk-part",
                            `kind-${part.kind}`,
                            selected ? "is-selected" : "",
                            part.selectable ? "" : "is-disabled",
                          ]
                            .filter(Boolean)
                            .join(" ")}
                          style={{ flexGrow: weight }}
                          disabled={!part.selectable}
                          aria-pressed={selected}
                          title={`${title} · ${formatBytes(part.size)}`}
                          onClick={() => setSelectedPartId(part.id)}
                        >
                          <span className="disk-part-bar" aria-hidden="true" />
                          <span className="disk-part-body">
                            <span className="disk-part-title">{title}</span>
                            <span className="disk-part-size">
                              {formatBytes(part.size)}
                            </span>
                            {part.file_system && (
                              <span className="disk-part-fs">{part.file_system}</span>
                            )}
                            <span className="disk-part-status">{part.status}</span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          <ul className="disk-legend" aria-label="Partition colors">
            <li>
              <span className="swatch kind-unallocated" /> Unallocated
            </li>
            <li>
              <span className="swatch kind-primary" /> Primary
            </li>
            <li>
              <span className="swatch kind-logical" /> Logical
            </li>
            <li>
              <span className="swatch kind-efi" /> EFI / System
            </li>
            <li>
              <span className="swatch kind-recovery" /> Recovery
            </li>
          </ul>

          <div className="disk-picker-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setPhase("idle");
                setDisks([]);
                setSelectedPartId(null);
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!selectedPart?.selectable}
              onClick={() => void confirmDiskSelection()}
            >
              Confirm selection
            </button>
          </div>
        </section>
      )}

      {mode === "text" && phase === "idle" && (
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

      {phase === "inspecting" && (
        <section className="status-panel" aria-live="polite" aria-busy="true">
          <div className="spinner" aria-hidden="true" />
          <p className="status-title">
            Inspecting {mode === "disk" ? "volume" : "file"}
            <span className="status-ellipsis" aria-hidden="true" />
          </p>
          <p className="status-hint">
            Large sources may take a while — please wait
          </p>
        </section>
      )}

      {phase === "ready" && details && hash && (
        <section className="workspace" aria-label="Extraction result">
          <header className="workspace-head">
            <h1 className="file-name" title={details.name}>
              {details.name}
            </h1>
          </header>

          <div className="workspace-body">
            <div className="detail-block">
              <h2 className="block-label">
                {mode === "disk" ? "Volume details" : "File details"}
              </h2>
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
                  {previewHashLine(hash.hash_line)}
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
                  disabled={!hash.hash_line || hashTooLargeToCopy}
                  title={
                    hashTooLargeToCopy
                      ? "Hash too large to copy — use Export .hash"
                      : undefined
                  }
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
