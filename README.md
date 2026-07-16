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

Archives: ZIP (ZipCrypto / WinZip AES), RAR3 (`-hp`) / RAR5, 7z · Documents: Microsoft Office (2007–2013+), PDF (revisions 2–6) · Volumes: BitLocker (Windows Disk tab)

More formats (crypto wallets, KeePass, LUKS, TrueCrypt/VeraCrypt, GPG, SSH, …) are sequenced in the [format roadmap](./docs/architecture.md#format-roadmap-native-2john-replacements).

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

## Releases

GitHub Actions builds installers for Windows / macOS / Linux when you push a version tag. Keep `package.json`, `src-tauri/tauri.conf.json`, and `src-tauri/Cargo.toml` versions in sync, then:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow creates a **draft** GitHub Release with the artifacts; publish it from the Releases page when ready. You can also run **Release** manually under Actions → workflow_dispatch.

## Security & ethics

Use only on files you own or are authorized to recover. Prefer hash extraction over uploading encrypted sources when privacy matters.

## License

[MIT License](./LICENSE)
