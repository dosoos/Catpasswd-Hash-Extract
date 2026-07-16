# Catpasswd Hash Extract

**Unified, cross-platform hash extraction** for encrypted files — a native alternative to scattered John `*2john` scripts (C / Python / Perl / …).

Extract crack-ready hashes **locally**, then:

- feed [John the Ripper](https://www.openwall.com/john/), [hashcat](https://hashcat.net/), or other crackers, or upload to [Catpasswd](https://www.catpasswd.com/) for cloud recovery

One app, many formats, one result contract — source files never need to leave your machine.

## Goals

| Goal | Meaning |
|------|---------|
| Broad format coverage | Archives, documents, and more over time — one extractor surface |
| Multi-platform | Desktop app via Tauri (Windows / macOS / Linux) |
| Unified hash contract | Stable `HashResult` / export lines for John, hashcat, and other crackers |
| Replace script chaos | First-party native extractors instead of maintaining a zoo of `*2john` scripts |

## Supported formats (v1)

Archives: ZIP (ZipCrypto / WinZip AES), RAR3 (`-hp`) / RAR5, 7z · Documents: Microsoft Office (2007–2013+), PDF (revisions 2–6)

## Architecture

Norms: [`docs/architecture.md`](./docs/architecture.md) · agents: [`AGENTS.md`](./AGENTS.md)

## Tech stack

Tauri 2 · React 19 + TypeScript + Vite · Rust (native extraction)

## Getting started

Prerequisites: [Node.js](https://nodejs.org/) LTS, [Rust](https://www.rust-lang.org/tools/install), [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run tauri dev    # develop
npm run tauri build  # release
```

## Security & ethics

Use only on files you own or are authorized to recover. Prefer hash extraction over uploading encrypted sources when privacy matters.

## License

[MIT License](./LICENSE)
