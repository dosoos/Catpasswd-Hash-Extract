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

## Supported formats

**Archives:** ZIP (ZipCrypto / WinZip AES), RAR3 (`-hp`) / RAR5, 7z · **Documents:** Microsoft Office (2007–2013+), PDF (revisions 2–6) · **Volumes:** BitLocker (Windows Disk tab)

**Crypto wallets (v2):** Ethereum Keystore (UTC/JSON, scrypt/pbkdf2, presale), Bitcoin Core (`wallet.dat`), Electrum, Monero (`.keys`), MetaMask / browser extension vaults, BIP38 encrypted private keys, Blockchain.com, MultiBit Classic, Coinomi.

More formats (KeePass, LUKS, TrueCrypt/VeraCrypt, GPG, SSH, …) are sequenced in the [format roadmap](./docs/architecture.md#format-roadmap-native-2john-replacements).

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

GitHub Actions builds installers for Windows / macOS / Linux when you push a version tag. CI reads the tag (e.g. `v1.0.0`) and syncs `package.json` / `tauri.conf.json` / `Cargo.toml` automatically — you do not need to bump those files by hand:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow creates a **draft** GitHub Release with the artifacts; publish it from the Releases page when ready. You can also run **Release** manually under Actions → workflow_dispatch (enter a version such as `1.0.0`).

Installer assets are named with a platform suffix:

| Asset suffix | Platform |
|--------------|----------|
| `_macos-apple-silicon.dmg` | macOS Apple Silicon (M1 / M2 / M3 / M4) |
| `_macos-intel.dmg` | macOS Intel |
| `_windows-x64.msi` / `_windows-x64-setup.exe` / `_windows-x64-portable.exe` | Windows x64 |
| `_windows-x86.msi` / `_windows-x86-setup.exe` / `_windows-x86-portable.exe` | Windows x86 32-bit |
| `_windows-arm64-setup.exe` / `_windows-arm64-portable.exe` | Windows ARM64 (NSIS + portable; no MSI) |
| `_linux-x64.AppImage` / `.deb` / `.rpm` | Linux |

**Windows `*-portable.exe`:** download and run directly (no installer). It still needs the [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) — usually already present on Windows 10/11. This is not a fully static single-binary like a Go CLI; the UI uses the system WebView2.

On Apple Silicon, use the apple-silicon DMG. The Intel DMG runs under Rosetta and may show a soon-unsupported warning.


## Security & ethics

Use only on files you own or are authorized to recover. Prefer hash extraction over uploading encrypted sources when privacy matters.

## License

[MIT License](./LICENSE)
