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
| Disk | Lists physical disks/partitions and extracts BitLocker hashes (Windows) |
| Text | Hash / convert text input — planned |

| Concern | Rule |
|---------|------|
| Format parsing / extraction | Native (Rust / Tauri), not in the webview; not shelling out to `*2john` for production |
| Export | Clipboard, `.hash` file, John/hashcat-compatible lines when applicable |
| New formats | Extend the same detect → extract → `HashResult` path; keep output contract stable |

## Product constraints

- Authorized recovery only (files the user owns or may unlock).
- File tab opens a native dialog and passes a filesystem path to Rust `inspect_file` (no `*2john` shell-out).
- MIT License — do not relicense without maintainer agreement.

## Formats (v1, implemented)

Native Rust extractors, one per format, all sharing the detect → extract → `HashResult` path. Each takes `(path, source_name)` and returns a `HashResult` (never a hard error), so meta + a message are always available.

| Format | Output line | hashcat `-m` |
|--------|-------------|--------------|
| ZIP (WinZip AES) | `$zip2$…` (John `zip2john`; inline DF hex) | — (John-first; hashcat later) |
| ZIP (ZipCrypto) | `$pkzip$…` (John `zip2john`) | — (John-first; hashcat later) |
| RAR5 | `$rar5$…` | 13000 |
| RAR3 (`-hp`) | `$RAR3$*0*…` | 12500 |
| 7-Zip (AES) | `$7z$…` | 11600 |
| Office 2010/2013+ (Agile) | `$office$*2010/2013*…` | 9500 / 9600 |
| Office 2007 (Standard) | `$office$*2007*…` | 9400 |
| PDF (R2–R6) | `$pdf$…` | 10400 / 10500 / 10600 / 10700 |
| BitLocker (password VMK) | `$bitlocker$0$…` | 22100 |

Limitations are surfaced as `warnings` (e.g. RAR3 `-p`, legacy Office XOR/RC4, header-encrypted RAR5 IV placeholder, multi-coder 7z). Unencrypted inputs return a clear "not encrypted" warning.

## Disk source (Windows)

The Disk tab enumerates physical disks and partitions via native Win32 IOCTLs (no PowerShell/WMI), mirroring the Disk Management view: `list_disks()` returns `DiskInfo`/`PartitionInfo` including synthesized **unallocated** gaps (non-selectable), drive letters, labels, and file systems.

`inspect_volume(disk_index, partition_index)` returns the same `InspectResult` contract as files. It reads the raw partition (via the physical drive so metadata is visible even on an unlocked volume), parses the BitLocker (FVE) volume header, and scans the FVE metadata blocks:

| Case | Result |
|------|--------|
| Password-protected VMK | `$bitlocker$0$…` hash line, hashcat `-m 22100` |
| Only TPM / recovery / startup-key / clear | `warning`: not crackable with 22100 |
| Not BitLocker | `warning`: volume is not BitLocker-encrypted |

Constraints: raw disk access requires **Administrator** (else an access-denied error advising to elevate); disks are never streamed in full — `FileMeta` digests are computed from the **volume header only** (first 1 MiB) and flagged with a warning. Disk enumeration/inspection are Windows-only; other platforms return a clear error.

## Format roadmap (native `*2john` replacements)

Same detect → extract → `HashResult` path for every new format. Priority = how often users need it for local recovery / forensics, not John’s script count. Duplicate scripts (`.py` / `.pl` / binary) map to **one** extractor. `test_*` scripts are out of scope.

| Version | Theme | Target formats (John script → product) |
|---------|--------|----------------------------------------|
| **v1** (done) | Archives, docs, BitLocker | `zip2john`, `rar2john`, `7z2john`, `office2john`, `pdf2john`, `bitlocker2john` |
| **v2** | Crypto wallets | `bitcoin2john`, `ethereum2john`, `electrum2john`, `monero2john`, `multibit2john`, `blockchain2john`, `coinomi2john`, `bitshares2john`, `cardano2john`, `tezos2john`, `keplr2john`, `neo2john`, `restic2john` |
| **v3** | Password managers + common vaults | `keepass2john`, `1password2john`, `bitwarden2john`, `lastpass2john`, `enpass2john`, `dashlane2john`, `pwsafe2john`, `padlock2john`, `authenticator2john`, `andotp2john` |
| **v4** | Disk / volume encryption (cross-platform) | `truecrypt2john` (+ VeraCrypt), `luks2john`, `dmg2john`, `fvde2john`, `diskcryptor2john`, `bestcrypt2john` / `bestcryptve2john`, `encfs2john`, `ecryptfs2john`, `geli2john`, `openbsd_softraid2john`, `pgpdisk2john` / `pgpwde2john` / `pgpsda2john`, `vdi2john` |
| **v5** | Keys, certs, SSH, browsers | `gpg2john`, `ssh2john`, `putty2john`, `pfx2john`, `pem2john`, `keystore2john`, `keychain2john`, `keyring2john`, `mozilla2john`, `filezilla2john`, `openssl2john`, `known_hosts2john` |
| **v6** | Office/docs leftovers + Apple / mobile backups | `libreoffice2john`, `iwork2john`, `staroffice2john`, `applenotes2john`, `itunes_backup2john`, `androidbackup2john`, `androidfde2john`, `money2john` |
| **v7** | Messaging & cloud apps | `signal2john`, `telegram2john`, `ansible2john`, `gitea2john`, `axcrypt2john`, `strip2john`, `zed2john`, `oubliette2john`, `encdatavault2john`, `deepsound2john` |
| **v8** | Network / Wi‑Fi / auth captures | `wpapcap2john`, `hccap2john` / `hccapx2john`, `pcap2john`, `vncpcap2john`, `radius2john`, `apop2john`, `ikescan2john`, `sipdump2john`, `krb2john` / `kirbi2john` / `ccache2john` / `kdcdump2john`, `DPAPImk2john` |
| **v9** | Enterprise / niche / OS hashes | `aix2john`, `oracle2john`, `sap2john`, `racf2john`, `lotus2john`, `cisco2john`, `mongodb2john`, `ejabberd2john`, `prosody2john`, `mosquitto2john`, `mcafee_epo2john`, `ibmiscanner2john`, `sspr2john`, `ldif2john`, `htdigest2john`, `mac2john` / `lion2john`, `uaf2john`, `cracf2john`, `kwallet2john`, `bks2john`, `pse2john`, `ps_token2john`, `vmx2john`, `aem2john`, `apex2john`, `atmail2john`, `aruba2john`, `sense2john`, `adxcsouf2john`, `network2john`, remaining one-offs |

**Rules for later versions**

- Prefer formats with a stable hashcat `-m` (or clear John format id); document gaps as `warnings`.
- Disk formats that need raw device access follow the Disk tab + privilege notes; file-based images (DMG, VDI, LUKS container files) stay on the File tab.
- Skip or defer items that are mainly online protocol dumps with no durable file artifact, unless Text/Disk mode needs them.
- Reorder within a version if real user demand shifts; do not invent a parallel architecture.

## Unified result contract

Detection + whole-file digests produce a `FileMeta`; the extractor produces a `HashResult`; the IPC command returns `InspectResult { meta, hash }`.

`FileMeta`: `name`, `format_label`, `size`, `modified_ms`, `crc32`, `md5`, `sha256`, `sha512`.

`HashResult` — stable fields the UI, exporters, and crackers agree on:

| Field | Meaning |
|-------|---------|
| `format` | Detected format id |
| `source_name` | Basename for display / default export name |
| `hash_line` | Primary crack hash line (hashcat/John-compatible shape) |
| `hashcat_mode` | hashcat `-m` if known, else null |
| `warnings` / `error` | Non-fatal notes / fatal message |

Prefer one coherent `HashResult` over format-specific ad-hoc strings in the UI.

## Special: optional hash-only cloud upload

- Always keep “save `.hash`” so users can upload manually elsewhere.
- In-app upload must not attach the original archive/document.
- Note concrete API endpoints here when integration lands (keep brief; no marketing copy).
