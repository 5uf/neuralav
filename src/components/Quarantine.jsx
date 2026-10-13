import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { showPath } from "../util";
import "./Quarantine.css";

// Rows are "name,classification,original path"; blank trailing lines are dropped.
async function load() {
  try {
    return (await invoke("get_quarantine")).filter((r) => r.length >= 3 && r[0] !== "");
  } catch {
    return [];
  }
}

export default function Quarantine() {
  const [rows, { refetch }] = createResource(load);
  const [query, setQuery] = createSignal("");
  const [picked, setPicked] = createSignal(new Set());
  const [message, setMessage] = createSignal("");
  const [confirmDelete, setConfirmDelete] = createSignal(false);

  const list = () => rows() || [];
  const visible = createMemo(() => {
    const q = query().trim().toLowerCase();
    return q ? list().filter((r) => r.join(" ").toLowerCase().includes(q)) : list();
  });
  const allPicked = () => visible().length > 0 && visible().every((r) => picked().has(r[0]));

  function toggle(name) {
    const next = new Set(picked());
    next.has(name) ? next.delete(name) : next.add(name);
    setPicked(next);
  }

  function toggleAll() {
    setPicked(allPicked() ? new Set() : new Set(visible().map((r) => r[0])));
  }

  async function run(command) {
    const lines = [];
    for (const name of picked()) {
      try {
        lines.push(`${name}: ${await invoke(command, { filename: name })}`);
      } catch (e) {
        lines.push(`${name}: ${e}`);
      }
    }
    setMessage(lines.join("\n"));
    setPicked(new Set());
    setConfirmDelete(false);
    refetch();
  }

  return (
    <main class="nv-main">
      <header class="page-head">
        <h1>Quarantine</h1>
        <span class="page-sub">{list().length} files · size — · renamed to .txt, not encoded</span>
        <div class="page-actions">
          <label for="q-search" class="sr-only">Search quarantine</label>
          <input id="q-search" class="field q-search" type="search" placeholder="Search name or path" value={query()} onInput={(e) => setQuery(e.currentTarget.value)} />
        </div>
      </header>

      <section class="card q-card" aria-label="Quarantined files">
        <div class="q-bar">
          <span class="page-sub">{picked().size} selected</span>
          <div class="btn-row">
            <button type="button" class="btn btn-sm" disabled={picked().size === 0} onClick={() => run("restore")}>Restore</button>
            <button type="button" class="btn btn-sm" disabled title="Coming soon">Restore and trust</button>
            <Show when={!confirmDelete()} fallback={<button type="button" class="btn btn-sm btn-warn-soft" onClick={() => run("del_quarantine")}>Confirm: delete {picked().size} forever</button>}>
              <button type="button" class="btn btn-sm btn-warn-soft" disabled={picked().size === 0} onClick={() => setConfirmDelete(true)}>Delete forever</button>
            </Show>
          </div>
        </div>
        <Show when={message()}><p class="msg" role="status" style={{ "white-space": "pre-line", margin: "0 16px 8px" }}>{message()}</p></Show>
        <Show when={visible().length > 0} fallback={<p class="empty">{rows.loading ? "Loading…" : list().length ? "No files match." : "Nothing in quarantine."}</p>}>
          <div class="q-table">
            <table class="tbl">
              <thead>
                <tr>
                  <th scope="col" class="w-check"><input type="checkbox" aria-label="Select all" checked={allPicked()} onChange={toggleAll} /></th>
                  <th scope="col">File</th><th scope="col">Threat</th><th scope="col">Found by</th><th scope="col">Size</th><th scope="col" class="right">Quarantined</th>
                </tr>
              </thead>
              <tbody>
                <For each={visible()}>
                  {(r) => (
                    <tr classList={{ "row-sel": picked().has(r[0]) }}>
                      <td class="w-check"><input type="checkbox" aria-label={`Select ${r[0]}`} checked={picked().has(r[0])} onChange={() => toggle(r[0])} /></td>
                      <td><div class="cell-name">{r[0]}</div><div class="cell-path">{showPath(r[2])}</div></td>
                      <td><span class="pill pill-warn">{r[1]}</span></td>
                      <td class="muted">—</td>
                      <td class="mono">—</td>
                      <td class="right mono muted">—</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </section>

      <section class="card q-policy" aria-label="Quarantine policy">
        <label class="check"><input type="checkbox" disabled />Delete files older than</label>
        <label for="q-days" class="sr-only">Days</label>
        <select id="q-days" class="field field-sm" disabled><option>30 days</option><option>90 days</option><option>Never</option></select>
        <span class="soon">Coming soon</span>
        <span class="muted">Restoring never overwrites an existing file.</span>
      </section>
    </main>
  );
}
