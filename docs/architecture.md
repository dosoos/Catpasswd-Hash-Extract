# Architecture & constraints

Norms for **Catpasswd Hash Extract**. Docs describe **behavior and constraints**, not a required folder tree. Keep them short; expand only for special features.

## Vision

Historically, encrypted-file hash extraction depended on John the Ripper’s `*2john` scripts — a mix of C, Python, Perl, and other one-off tools. That is hard to install, hard to maintain, and inconsistent across formats and platforms.

**This project’s goal:** a single, native, cross-platform hash extractor that:

- Supports **many encrypted formats** (grow toward broad coverage over time)
- Runs on **multiple platforms** (desktop via Tauri)
- Emits a **unified hash result contract** usable with John, hashcat, and other crackers
- Becomes the **practical standard** for adding new format extractors in one place, instead of another ad-hoc script

Keep product docs and UI **neutral** and open-source focused — describe what the tool does, not third-party services.

## Purpose (product)

1. Extract crack-oriented hashes **locally** from encrypted files  
2. Export for John / hashcat / other tools  

## Logic flow

```
pick source (File | Disk | Text) → detect → extract hash → show / export
```

| Source tab | Intent |
|------------|--------|
| File | Encrypted archives / documents (v1 focus) |
| Disk | Encrypted volumes (e.g. BitLocker) — planned |
| Text | Hash / convert text input — planned |

| Concern | Rule |
|---------|------|
| Format parsing / extraction | Native (Rust / Tauri), not in the webview; not shelling out to `*2john` for production |
| Export | Clipboard, `.hash` file, John/hashcat-compatible lines when applicable |
| New formats | Extend the same detect → extract → `HashResult` path; keep output contract stable |

## Product constraints

- Authorized recovery only (files the user owns or may unlock).
- Replace the Tauri `greet` demo when real features land.
- MIT License — do not relicense without maintainer agreement.

## Planned formats (v1)

ZIP, RAR/RAR5, 7z, Microsoft Office, PDF (selected encryption types). More formats follow the same pipeline.

## Unified result contract (`HashResult`)

Stable fields the UI, exporters, and crackers should agree on:

| Field | Meaning |
|-------|---------|
| `format` | Detected format id |
| `source_name` | Basename for display / default export name |
| `hash_line` | Primary crack hash line (prefer John-compatible where a stable format exists) |
| `hashcat_mode` | hashcat `-m` if known, else null |
| `warnings` / `error` | Non-fatal notes / fatal message |

Prefer one coherent `HashResult` over format-specific ad-hoc strings in the UI.

## Special: optional hash-only cloud upload

- Always keep “save `.hash`” so users can upload manually elsewhere.
- In-app upload must not attach the original archive/document.
- Note concrete API endpoints here when integration lands (keep brief; no marketing copy).
