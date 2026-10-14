import { A } from "@solidjs/router";
import { createResource, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { formatWhen, loadLastScan, showPath } from "../util";
import "./Dashboard.css";

async function safe(command) {
  try {
    return await invoke(command);
  } catch {
    return [];
  }
}

const layers = (model) => [
  { name: "Hash lists", state: "Active" },
  { name: "Signature rules", state: "Active" },
  { name: "PyInstaller unpacker", state: "Active" },
  { name: "AI-malware carrier rules", soon: true },
  { name: "Static model", note: "(Windows apps)", state: model == null ? "—" : model ? "Active" : "Off" },
  { name: "Code analysis", soon: true },
  { name: "Behavior monitor", soon: true },
];

const schedules = ["Quick scan", "Full scan", "Rule updates"];

export default function Dashboard() {
  const last = loadLastScan();
  const [noti] = createResource(() => safe("get_noti"));
  const [status] = createResource(() => invoke("engine_status").catch(() => null));

  const events = () => (noti() || []).filter((r) => r.length >= 4 && r[0] !== "");
  // Log rows are "time,action,threat,path".
  const isHandled = (r) => r[1] === "Quarantined" || r[1] === "Deleted";
  const handled = () => events().filter(isHandled);
  const recent = () => handled().slice(-5).reverse();
  // A path counts while its latest event is Quarantined or Deleted; a restore un-counts it.
  const handledCount = () => {
    const last = new Map();
    for (const r of events()) last.set(r[3], r);
    return [...last.values()].filter(isHandled).length;
  };

  return (
    <main class="nv-main">
      <header class="page-head">
        <h1>Dashboard</h1>
        <span class="dash-status">
          <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5 9-10" /></svg>
          On-demand scanning
        </span>
        <div class="page-actions">
          <button type="button" class="btn" disabled title="Coming soon">Update rules</button>
          <A href="/scan" class="btn btn-primary">Quick scan</A>
        </div>
      </header>

      <section class="stats" aria-label="Status">
        <div class="stat"><span class="stat-label">Real-time monitor</span><span class="stat-value">Coming soon</span></div>
        <div class="stat"><span class="stat-label">Last scan</span><span class="stat-value">{last ? formatWhen(last.time) : "—"}</span></div>
        <div class="stat"><span class="stat-label">Files scanned</span><span class="stat-value">{last ? last.files : "—"}</span></div>
        <div class="stat"><span class="stat-label">Threats handled</span><span class="stat-value">{noti.loading ? "—" : handledCount()}</span></div>
        <div class="stat"><span class="stat-label">Rules</span><span class="stat-value">{status()?.rules ?? "—"}</span></div>
      </section>

      <div class="dash-grid">
        <section class="card stack" aria-labelledby="layers-title">
          <h2 id="layers-title" class="card-head">Protection layers</h2>
          <For each={layers(status()?.model)}>
            {(l) => (
              <div class="dash-row">
                <span>{l.name} <Show when={l.note}><span class="muted">{l.note}</span></Show></span>
                <Show when={l.soon} fallback={<span class="dash-state">{l.state}</span>}><span class="soon">Coming soon</span></Show>
              </div>
            )}
          </For>
        </section>

        <section class="card stack" aria-labelledby="ai-title">
          <div class="card-head"><h2 id="ai-title">Apps using AI services</h2><A href="/monitor">Open monitor</A></div>
          <p class="empty">No data yet. The live monitor is coming soon.</p>
          <p class="dash-note">Will flag unknown apps that call an AI service and then run new code, log keys or capture the screen.</p>
        </section>

        <section class="card stack" aria-labelledby="sched-title">
          <div class="card-head"><h2 id="sched-title">Scheduled scans</h2><A href="/settings">Edit</A></div>
          <For each={schedules}>
            {(s) => (
              <div class="dash-row"><span>{s}</span><span class="soon">Coming soon</span></div>
            )}
          </For>
        </section>
      </div>

      <section class="card dash-recent" aria-labelledby="recent-title">
        <div class="card-head"><h2 id="recent-title">Recent detections</h2><A href="/activity">View all</A></div>
        <Show when={recent().length > 0} fallback={<p class="empty">{noti.loading ? "Loading…" : "No detections handled yet."}</p>}>
          <div class="table-card">
            <table class="tbl">
              <thead><tr><th scope="col">Threat</th><th scope="col">File</th><th scope="col">Result</th><th scope="col" class="right">When</th></tr></thead>
              <tbody>
                <For each={recent()}>
                  {(r) => (
                    <tr>
                      <td class="cell-name">{r[2] || "—"}</td>
                      <td class="cell-path">{showPath(r[3])}</td>
                      <td class="warn-tx">{r[1]}</td>
                      <td class="right mono muted">{r[0]}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </section>
    </main>
  );
}
