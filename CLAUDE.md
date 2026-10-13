# Neural-AV

Desktop anti-malware (v1.2.1), being rebuilt toward a cross-platform AV. Tauri v2 shell, SolidJS UI, Rust backend, Python ONNX models (to be replaced by Rust).
`AGENTS.md` is a symlink to this file. Edit `CLAUDE.md` only.

## Safety
- `Whatsapp.exe` in the repo root is a suspected live malware sample. Never execute, open, import, copy or move it. Static analysis only, and only when asked. `*.exe` is gitignored.

## Layout
- `src/`: SolidJS UI (vite-plugin-solid). `src/App.jsx` exports `Layout` and `routes`. `src/index.jsx` mounts `<Router root={Layout}>`. Pages are in `src/components/`.
- `src-tauri/src/main.rs`: every `#[tauri::command]`, the `generate_handler!` list, the tray (built in `setup()`), and the `SCANNED` allowlist.
- `src-tauri/src/engine/`: `scanner.rs` (tract ONNX, currently uncalled), `func.rs` (path walking), `utils.rs` (quarantine, CSV DB, optimize/clean), `python.rs` (CPython bridge for `identify`/`classify` only).
- `src-tauri/capabilities/default.json`: main window, `core:default` only.
- `src-tauri/neuralib/main.py`: onnxruntime inference over `src-tauri/models/{Identifier,Classifier}/`. The models dir comes from `NEURALAV_MODELS` (default `models`, relative to cwd).
- Optimize page: `utils::flush_dns` (OS tool by absolute path) and `utils::clean_temp` (user temp files older than 7 days, symlinks never followed, no elevation). The old `.bat` scripts are gone. Never reintroduce shell scripts or elevation for these.
- `dist/`, `node_modules/`, `src-tauri/target/`, `neuralib/build/`, `*.egg-info`: generated. Do not edit.

## Scan pipeline
1. UI calls `invoke("identify" | "classify" | "multiscan" | "remote_inference", ...)`.
2. Rust resolves single-file and multiscan names against hardcoded `FOLDER` (`main.rs`, `C:\Users\muhds\Desktop\Test`). Drive scans use `walkdir` without following links.
3. `python.rs` embeds CPython (`cpython` crate) and calls `neuralib.identify`/`classify`.
4. `identify` returns `"Malicious"` or `"Harmless"`. `classify` returns `label,accuracy,text`.
5. Only paths with a `"Malicious"` verdict enter `SCANNED`. `quarantine_file` and `remote_delete` reject any other path.

## Known traps
- The label order (index 1 = Malicious) is unverified. Check it against known samples before trusting verdicts.
- The quarantine "DB" is a hand-split CSV at `C:/neural-av/database.csv`, with no locking. Quarantine is only a rename to `.txt`, not neutralization.
- `engine.rs` (folder watcher) compares against `"Malware"`, which is never returned.
- The glob, comparison and statistics charts show hardcoded numbers, not measured results.
- `README.md` is the Tauri template default. `Workflow.txt` holds BERT notes.

## Commands
- `npm run dev`: Vite only, port 1420 (strict). `npm run build` writes to `dist/`.
- `npm run tauri dev` / `npm run tauri build`: full app. It needs Python with `neuralib` deps (transformers, onnxruntime, numpy).
- `cd src-tauri && cargo check`: compiles on macOS (Xcode license must be accepted).
- No tests, lint or CI exist. Not a git repo. Back up before destructive edits.

## Conventions
- Each new Tauri command needs `#[tauri::command]` in `main.rs` and an entry in `generate_handler!`. Frontend arg keys are camelCase, and Tauri maps them to snake_case.
- `invoke` comes from `@tauri-apps/api/core`. Internal links use `<A>` or `useNavigate`, never `<a href>`.
- Write UI text from data with `textContent`/JSX, never `innerHTML`.
- Keep CRLF line endings on files that already use CRLF.
- Each component imports its own CSS file from the same directory.
