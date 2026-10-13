// Run a release build with local paths (home dir, cargo registry, repo) remapped,
// so published binaries do not contain the builder's username or directory layout.
// Usage: node scripts/release.mjs <command> [args...]
// ponytail: replace with `trim-paths = "all"` in [profile.release] once it is stable in cargo.
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [cmd, ...args] = process.argv.slice(2);
if (!cmd) {
  console.error("usage: node scripts/release.mjs <command> [args...]");
  process.exit(2);
}

const repo = resolve(fileURLToPath(import.meta.url), "..", "..");
const cargoHome = process.env.CARGO_HOME || join(homedir(), ".cargo");
// rustc applies the last matching prefix, so the most specific comes last.
const remaps = [
  [homedir(), "/home"],
  [cargoHome, "/cargo"],
  [repo, "/neuralav"],
];
const flags = remaps.map(([from, to]) => `--remap-path-prefix=${from}=${to}`);
// CARGO_ENCODED_RUSTFLAGS (0x1f-separated) survives paths with spaces; it overrides RUSTFLAGS, so merge them.
const existing = (process.env.RUSTFLAGS || "").split(/\s+/).filter(Boolean);
const CARGO_ENCODED_RUSTFLAGS = [...existing, ...flags].join("\x1f");

const r = spawnSync(cmd, args, {
  stdio: "inherit",
  shell: process.platform === "win32",
  env: { ...process.env, CARGO_ENCODED_RUSTFLAGS },
});
process.exit(r.status ?? 1);
