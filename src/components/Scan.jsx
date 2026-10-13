import { A } from "@solidjs/router";
import { createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { downloadDir, desktopDir, tempDir } from "@tauri-apps/api/path";
import { describeRow, saveLastScan, showPath } from "../util";
import "./Scan.css";

// Scan state lives outside the component so a running scan and its results survive navigation.
const [type, setType] = createSignal("quick");
const [target, setTarget] = createSignal("");
const [drives, setDrives] = createSignal([]);
const [drive, setDrive] = createSignal("");
const [busy, setBusy] = createSignal(false);
const [summary, setSummary] = createSignal(null);
const [results, setResults] = createSignal([]);
const [picked, setPicked] = createSignal(new Set());
const [shown, setShown] = createSignal(null);
const [message, setMessage] = createSignal("");
const [confirmDelete, setConfirmDelete] = createSignal(false);
const [acting, setActing] = createSignal(false);
const [noDrives, setNoDrives] = createSignal(false);

// Drive letters exist on Windows only; disable "Full drive" when there are none.
invoke("get_drives").then((l) => setNoDrives(l.length === 0)).catch(() => {});

const types = [
  { id: "quick", label: "Quick" },
  { id: "custom", label: "Custom" },
  { id: "drive", label: "Full drive" },
  { id: "usb", label: "USB drive", soon: true },
];

async function pickType(id) {
  setType(id);
  if (id === "drive") {
    try {
      const list = await invoke("get_drives");
      setDrives(list);
      if (!list.includes(drive())) setDrive(list[0] || "");
    } catch (e) {
      setMessage(`Could not list drives: ${e}`);
    }
  }
}

async function browse(directory) {
  try {
    const chosen = await open({ directory, multiple: false });
    if (typeof chosen === "string") setTarget(chosen);
  } catch (e) {
    setMessage(`Could not open the picker: ${e}`);
  }
}

async function targets() {
  if (type() === "quick") return [await downloadDir(), await desktopDir(), await tempDir()];
  if (type() === "drive") return [drive()];
  return [target().trim()];
}

async function startScan() {
  setMessage("");
  setConfirmDelete(false);
  setBusy(true);
  setResults([]);
  setShown(null);
  setSummary(null);
  const began = Date.now();
  const rows = [];
  try {
    const paths = (await targets()).filter(Boolean);
    if (paths.length === 0) throw new Error("Choose something to scan first");
    for (const p of paths) {
      try {
        const part = type() === "drive" ? await invoke("remote_inference", { drive: p }) : await invoke("scan_path", { path: p });
        for (const r of part) rows.push(r);
      } catch (e) {
        // Keep what was already collected; report the path that failed as an error row.
        rows.push([p, `Error: Could not open ${p}`, "Safe"]);
      }
    }
  } catch (e) {
    setMessage(`Scan failed: ${e}`);
    setBusy(false);
    return;
  }
  const all = rows.map(describeRow);
  const flagged = all.filter((r) => r.status !== "Clean");
  const secs = Math.max((Date.now() - began) / 1000, 0.001);
  const s = {
    files: all.length,
    seconds: secs,
    threats: all.filter((r) => r.status === "Malicious" || r.status === "Suspicious").length,
    notFull: all.filter((r) => r.status === "Not fully scanned").length,
    clean: all.length - flagged.length,
  };
  setSummary(s);
  setResults(flagged);
  setPicked(new Set(flagged.filter((r) => r.status === "Malicious").map((r) => r.path)));
  saveLastScan({ time: Date.now(), files: s.files, threats: s.threats });
  setBusy(false);
}

function toggle(path) {
  const next = new Set(picked());
  next.has(path) ? next.delete(path) : next.add(path);
  setPicked(next);
}

function toggleAll() {
  const all = results().filter((r) => r.status === "Malicious");
  setPicked(picked().size === all.length ? new Set() : new Set(all.map((r) => r.path)));
}

async function act(command, done) {
  const paths = [...picked()];
  if (paths.length === 0 || acting()) return;
  setActing(true);
  const lines = [];
  const gone = new Set();
  for (const path of paths) {
    const row = results().find((r) => r.path === path);
    try {
      const args = { filepath: path, classification: (row?.label || "Malicious").replace(/,/g, " ") };
      const out = await invoke(command, args);
      lines.push(`${showPath(path)}: ${out}`);
      if (out === done) gone.add(path);
    } catch (e) {
      lines.push(`${showPath(path)}: ${e}`);
    }
  }
  setResults(results().filter((r) => !gone.has(r.path)));
  setPicked(new Set([...picked()].filter((p) => !gone.has(p))));
  setConfirmDelete(false);
  setMessage(lines.join("\n"));
  setActing(false);
}

function layerRows(r) {
  const known = r.label === "Known malware";
  if (r.status === "Not fully scanned") return [["Hash list", "Not scanned"], ["Signature", "Not scanned"]];
  const sig = !known && !["Unknown", "None"].includes(r.label);
  return [
    ["Hash list", known ? r.reason : "No match"],
    ["Signature", sig ? r.label : "No match"],
  ];
}

export default function Scan() {
  const result = () => results().find((r) => r.path === shown());
  const selectable = () => results().filter((r) => r.status === "Malicious");

  return (
    <main class="nv-main">
      <header class="page-head"><h1>Scan</h1></header>

      <section class="card stack" style={{ gap: "12px" }} aria-label="New scan">
        <div class="scan-types" role="radiogroup" aria-label="Scan type">
          <For each={types}>
            {(t) => (
              <button type="button" role="radio" class="scan-type" aria-checked={type() === t.id} disabled={t.soon || busy() || (t.id === "drive" && noDrives())} title={t.soon ? "Coming soon" : t.id === "drive" && noDrives() ? "Windows only for now" : undefined} onClick={() => pickType(t.id)}>
                {t.label}{t.id === "drive" && noDrives() ? " (Windows only for now)" : ""}
              </button>
            )}
          </For>
        </div>
        <div class="scan-target">
          <Show when={type() === "quick"}>
            <label for="scan-target">Folders</label>
            <input id="scan-target" class="field scan-path" type="text" value="Downloads, Desktop, Temp" readOnly />
          </Show>
          <Show when={type() === "custom"}>
            <label for="scan-target">File or folder</label>
            <input id="scan-target" class="field scan-path" type="text" placeholder="Choose a file or folder" value={target()} onInput={(e) => setTarget(e.currentTarget.value)} />
            <button type="button" class="btn" disabled={busy()} onClick={() => browse(true)}>Browse folder</button>
            <button type="button" class="btn" disabled={busy()} onClick={() => browse(false)}>Choose file</button>
          </Show>
          <Show when={type() === "drive"}>
            <label for="scan-drive">Drive</label>
            <select id="scan-drive" class="field scan-path" value={drive()} onChange={(e) => setDrive(e.currentTarget.value)}>
              <Show when={drives().length === 0}><option value="">No drives found</option></Show>
              <For each={drives()}>{(d) => <option value={d}>{d}</option>}</For>
            </select>
          </Show>
          <button type="button" class="btn btn-primary" disabled={busy() || (type() === "drive" && !drive())} onClick={startScan}>{busy() ? "Scanning…" : "Start scan"}</button>
        </div>
        <div class="scan-opts">
          <label class="check"><input type="checkbox" disabled />Look inside archives and installers <span class="soon">Coming soon</span></label>
          <label class="check"><input type="checkbox" disabled />Deep code analysis on flagged files <span class="soon">Coming soon</span></label>
          <label class="check"><input type="checkbox" disabled />Include hidden and system files <span class="soon">Coming soon</span></label>
          <span class="muted">Exclusions: — · <A href="/settings">Edit</A></span>
        </div>
      </section>

      <Show when={busy() || summary()}>
        <section class="card scan-progress" aria-labelledby="progress-title">
          <div class="scan-progress-head">
            <h2 id="progress-title">{busy() ? "Scanning…" : "Scan finished"}</h2>
            <Show when={summary()}>
              {(s) => (
                <>
                  <span class="mono muted" style={{ "font-size": "12px" }}>{s().files} files · {s().seconds.toFixed(1)} s · {(s().files / s().seconds).toFixed(0)} files/s</span>
                  <span class="scan-counts">
                    <span class="warn-tx"><strong>{s().threats}</strong> {s().threats === 1 ? "threat" : "threats"}</span>
                    <span><strong>{s().notFull}</strong> not fully scanned</span>
                    <span><strong>{s().clean}</strong> clean</span>
                  </span>
                </>
              )}
            </Show>
          </div>
          <Show when={busy()} fallback={<div class="bar" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="100"><div style={{ width: "100%" }} /></div>}>
            <div class="bar bar-busy" role="progressbar" aria-label="Scan progress"><div /></div>
          </Show>
        </section>
      </Show>

      <Show when={message()}><p class="msg" role="status" style={{ "white-space": "pre-line", margin: 0 }}>{message()}</p></Show>

      <Show when={summary()}>
        <div class="split">
          <section class="card scan-results split-main" aria-labelledby="results-title" style={{ padding: "12px 0 4px" }}>
            <div class="scan-results-head">
              <h2 id="results-title">Results</h2>
              <div class="page-actions btn-row">
                <button type="button" class="btn btn-sm btn-warn" disabled={picked().size === 0 || acting()} onClick={() => act("quarantine_file", "File quarantined")}>Quarantine selected</button>
                <Show when={!confirmDelete()} fallback={<button type="button" class="btn btn-sm btn-warn-soft" disabled={acting()} onClick={() => act("remote_delete", "File deleted")}>Confirm delete {picked().size}</button>}>
                  <button type="button" class="btn btn-sm" disabled={picked().size === 0} onClick={() => setConfirmDelete(true)}>Delete selected</button>
                </Show>
                <button type="button" class="btn btn-sm" disabled title="Coming soon">Export report</button>
              </div>
            </div>
            <Show when={results().some((r) => r.status === "Suspicious")}><p class="muted" style={{ margin: "0 16px 8px", "font-size": "12px" }}>Suspicious files can't be removed automatically; review them manually.</p></Show>
            <Show when={results().length > 0} fallback={<p class="empty">Nothing found.</p>}>
              <div style={{ "overflow-x": "auto" }}>
                <table class="tbl">
                  <thead>
                    <tr>
                      <th scope="col" class="w-check"><input type="checkbox" aria-label="Select all threats" checked={selectable().length > 0 && picked().size === selectable().length} disabled={selectable().length === 0} onChange={toggleAll} /></th>
                      <th scope="col">Status</th><th scope="col">File</th><th scope="col">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={results()}>
                      {(r) => (
                        <tr classList={{ "row-warn": r.status === "Malicious" || r.status === "Suspicious", "row-sel": shown() === r.path }}>
                          <td class="w-check">
                            <Show when={r.status === "Malicious"}>
                              <input type="checkbox" aria-label={`Select ${showPath(r.path)}`} checked={picked().has(r.path)} onChange={() => toggle(r.path)} />
                            </Show>
                          </td>
                          <td><span class="pill" classList={{ "pill-warn": r.status !== "Not fully scanned" }}>{r.status}</span></td>
                          <td><button type="button" class="link-btn cell-path" onClick={() => setShown(r.path)}>{showPath(r.path)}</button></td>
                          <td>{r.reason}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </section>

          <aside class="card scan-aside split-aside" aria-labelledby="file-title">
            <Show when={result()} fallback={<p class="muted" id="file-title">Select a file to see details.</p>}>
              {(r) => (
                <>
                  <div><span class="muted" style={{ "font-size": "12px" }}>Selected file</span><h2 id="file-title" class="cell-path" style={{ color: "var(--tx)", "font-size": "13px" }}>{showPath(r().path)}</h2></div>
                  <dl class="kv">
                    <For each={layerRows(r())}>{([k, v]) => (<><dt>{k}</dt><dd class={v !== "No match" ? "warn-tx" : ""}>{v}</dd></>)}</For>
                    <dt>Static model</dt><dd class="muted">Coming soon</dd>
                    <dt>Code analysis</dt><dd class="muted">Coming soon</dd>
                    <dt>Size</dt><dd class="mono">—</dd>
                    <dt>SHA-256</dt><dd class="mono">—</dd>
                  </dl>
                  <div class="btn-row">
                    <button type="button" class="btn btn-sm" disabled title="Coming soon">Copy hash</button>
                    <button type="button" class="btn btn-sm" disabled title="Coming soon">Show in folder</button>
                    <button type="button" class="btn btn-sm" disabled title="Coming soon">Not a threat</button>
                  </div>
                </>
              )}
            </Show>
          </aside>
        </div>
      </Show>
    </main>
  );
}
