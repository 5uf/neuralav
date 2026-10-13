# Neural-AV target architecture

This is the contract for the rebuild. Each phase must leave `cargo test --workspace`, `cargo check`, and `npm run build` green.

## Shape

```
UI (Tauri v2, unprivileged)  ── local socket, JSON lines ──►  neuralav-service (Rust)
  src-tauri/  thin client                                      crates/service/
  depends on crates/proto only                                 ├─ crates/engine  (scan pipeline)
                                                               ├─ SQLite store + quarantine vault
                                                               ├─ watcher (real-time, post-write)
                                                               └─ updater (minisign-signed bundles)
```

Cargo workspace at the repo root. Members: `src-tauri`, `crates/proto`, `crates/engine`, `crates/service`.

- `crates/proto`: serde request and response enums shared by the UI and the service. No heavy dependencies.
- `crates/engine`: a library with no IPC and no UI.
  - `scan_file(path) -> Verdict`, `scan_tree(root, cb)`.
  - Layers, cheapest first:
    1. SHA-256 lookup in the allowlist and the known-bad hash DB.
    2. YARA rules (`yara-x`, pure Rust). Bundled rules include EICAR.
    3. ML model (tract-onnx plus tokenizers). It is optional (cargo feature `ml`), lazy-loaded once, and outputs **Suspicious** only, never Malicious. The label order is unverified (see CLAUDE.md).
  - `Verdict { status: Clean | Suspicious | Malicious, reasons: Vec<Reason{layer, detail}>, sha256 }`.
- `crates/service`: binary `neuralav-service`.
  - Subcommands: `run` (daemon), `scan <path> [--json]` (one-shot CLI, used by tests and benchmarks), `version`.
  - Owns the SQLite DB (`rusqlite`, bundled), the quarantine vault, the watcher and the updater.

## Security rules (non-negotiable)

- The UI never names a path for a destructive action. Delete, quarantine and restore take an **id** issued by the service: a detection id or a quarantine id. Scan requests may take a path, and they are read-only.
- Quarantine works like this:
  1. Content is XOR-obfuscated with a fixed key so it can't run or be indexed.
  2. It is stored as `<vault>/<sha256>.bin`.
  3. Metadata (original path, sha256, size, reasons, time) goes in SQLite.
  4. Restore refuses to overwrite an existing file and verifies the sha256 after decoding.
- Data dir per OS:
  - Windows: `%ProgramData%\NeuralAV`
  - Linux: `/var/lib/neuralav`
  - macOS: `/Library/Application Support/NeuralAV`
  - Dev and non-root runs: `NEURALAV_DATA_DIR`, or the per-user data dir.
- No shell scripts. No elevation prompts. No `unwrap()` on IO or user input in the engine or the service.
- Updates are applied only after `minisign-verify` passes against the public key compiled into the binary. On failure, the previous bundle stays.

## Platform support matrix (target)

| Capability | Windows 10/11 | Linux (x86-64, ARM64) | macOS 13+ (Intel, Apple Silicon) | Android | iOS |
|---|---|---|---|---|---|
| On-demand scan | yes | yes | yes | later (separate app) | no (sandbox) |
| Real-time, post-write (`notify`) | yes | yes | yes | — | — |
| Real-time, pre-exec blocking | no: needs a signed minifilter driver | possible: fanotify `FAN_OPEN_EXEC_PERM` as root (future) | no: needs Apple ES entitlement | — | — |
| Service install | Windows service (`windows-service`) | systemd unit | launchd plist | — | — |

## Phases

1. **Engine**: proto + engine crates and the `scan` CLI. Python and `cpython` are removed. Fake stats are removed.
2. **Service + store**: SQLite, the quarantine vault, IPC, the UI as a client, and service install files.
3. **Real-time**: watcher over configured dirs. A hash or YARA hit triggers auto-quarantine; ML alone only notifies.
4. **Updates**: signed rule and hash bundles.
5. **Verification**: the test corpus, the benchmark harness, and `docs/TESTING.md`.
