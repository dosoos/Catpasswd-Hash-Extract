#!/usr/bin/env node
/**
 * Sync package.json / tauri.conf.json / Cargo.toml [package].version
 * from a release tag (e.g. v1.0.0) or a bare semver (1.0.0).
 * Used by CI so maintainers only need to push a tag.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const raw = process.argv[2] ?? process.env.RELEASE_VERSION ?? "";
const version = String(raw).trim().replace(/^v/i, "");

if (!/^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(
    `Invalid version "${raw}". Expected v1.2.3 or 1.2.3 (optional pre-release suffix).`,
  );
  process.exit(1);
}

const root = resolve(import.meta.dirname, "..");

function writeJson(relPath, mutate) {
  const path = resolve(root, relPath);
  const data = JSON.parse(readFileSync(path, "utf8"));
  mutate(data);
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
}

writeJson("package.json", (pkg) => {
  pkg.version = version;
});

writeJson("src-tauri/tauri.conf.json", (conf) => {
  conf.version = version;
});

const cargoPath = resolve(root, "src-tauri/Cargo.toml");
const cargo = readFileSync(cargoPath, "utf8");
const updated = cargo.replace(
  /(\[package\][^\[]*?^version\s*=\s*")[^"]*(")/m,
  `$1${version}$2`,
);
if (updated === cargo) {
  console.error("Failed to update [package].version in src-tauri/Cargo.toml");
  process.exit(1);
}
writeFileSync(cargoPath, updated);

console.log(`Synced version to ${version}`);
