# Neural AV

A small, cross-platform anti-malware app written in Rust, built to catch polymorphic and AI-generated malware.

Started as my final year project and research paper (a Tauri app with fine-tuned BERT models). It is now being rebuilt as a tiny, pure-Rust engine. The BERT models are retired: they showed no evidence of learning, and their training data is lost.

> **Status: rebuild in progress.** Not ready for real protection yet.

## Goals

- **Smallest footprint.** Pure Rust, no Python, no ONNX runtime, no ClamAV. Every engine change reports binary size and peak RAM.
- **Catch polymorphic AI malware.** Malware like BlackMamba asks an LLM for new code at runtime, so every run looks different and hashes or payload signatures miss it. Neural AV targets what stays the same: the carrier that calls the model, and the behavior of the generated code.

## Detection layers

Cheapest first. Later layers run only on files that earlier layers leave undecided or flag.

1. **Hash lists:** known-good and known-bad SHA-256.
2. **Rule matcher:** strings and imports, including AI-carrier rules (LLM endpoint + dynamic code execution + keylogging, screen capture or exfiltration).
3. **Gradient-boosted trees** on EMBER-style static features, trained on EMBER2024. Can mark a file Suspicious, never Malicious on its own.
4. **Lifter:** disassembles flagged code into a small normalized IR and matches API-call sequences and known-bad functions, so rewritten variants still match.
5. **Behavior correlation:** watches processes at runtime (ETW on Windows, eBPF on Linux). Example: an unknown process calls an LLM API, then installs a keyboard hook. The service kills it and quarantines the file.

Design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Platforms

| | Windows 10/11 | Linux | macOS 13+ |
|---|---|---|---|
| On-demand scan | yes | yes | yes |
| Behavior monitoring | yes (ETW) | yes (eBPF) | limited (polling) |

Android may come later as a separate app. iOS is not possible because of the app sandbox.

## Build

Requirements: Rust (stable), Node.js 20+.

```sh
npm install
npm run tauri dev        # run the desktop app
cargo test --workspace   # run the tests
```

## Safety

Tests use only the harmless EICAR test string, built at runtime. Never commit real malware samples; `*.exe` is ignored by git.

## License

MIT. See [LICENSE](LICENSE).

Author: Muhammad Sufi Afifi

## Third-party notices

The static model `crates/engine/rules/models/ember2024_pe.navgbdt` is converted from the EMBER2024 PE LightGBM model (Apache-2.0, FutureComputing4AI, via Hugging Face `joyce8/EMBER2024-benchmark-models`). The feature definitions follow the `thrember` package of the same project. See [NOTICE](NOTICE).
