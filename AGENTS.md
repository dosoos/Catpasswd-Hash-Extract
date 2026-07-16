# AGENTS.md

Agent entry for **Catpasswd Hash Extract**. Overview: [`README.md`](./README.md). Norms: [`docs/architecture.md`](./docs/architecture.md).

## Project

Tauri 2 + React + TypeScript: **unified native hash extraction** for encrypted files (multi-format, multi-platform), with a stable result contract for John / hashcat / exporters.

## Read order

1. User instruction  
2. This file  
3. [`docs/architecture.md`](./docs/architecture.md)  
4. Existing code

## Docs ↔ code

Align on **behavior and constraints**, not folder layout. Update `docs/architecture.md` when product logic, privacy, `HashResult`, or format support changes. Keep docs short.

## Constraints

- New formats extend the same detect → extract → `HashResult` pipeline; do not invent a parallel architecture  
- Extraction in Rust; UI only invokes IPC and displays/exports  
- MIT — no relicensing without an explicit request  
- No unsolicited extra markdown; ask before commit/push  
