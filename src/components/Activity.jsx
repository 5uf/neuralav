import { createResource, createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { showPath } from "../util";
import "./Activity.css";

const filters = [
  { id: "all", label: "All" },
  { id: "threats", label: "Threats" },
  { id: "monitor", label: "Monitor", soon: true },
  { id: "scans", label: "Scans", soon: true },
  { id: "updates", label: "Updates", soon: true },
];

const ranges = [
  { id: "7", label: "Last 7 days", days: 7 },
  { id: "30", label: "Last 30 days", days: 30 },
  { id: "all", label: "All time" },
];

const icons = {
  Quarantined: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>,
  Deleted: <><path d="M3 6h18" /><path d="M8 6V4h8v2" /><path d="M6 6l1 14h10l1-14" /></>,
  Restored: <path d="M5 12l5 5 9-10" />,
};

const details = {
  Quarantined: "Moved to quarantine",
  Deleted: "Deleted",
  Restored: "Restored from quarantine",
};

// Log rows are "time,action,path"; blank trailing lines are dropped.
async function load() {
  try {
    return (await invoke("get_noti")).filter((r) => r.length >= 3 && r[0] !== "").reverse();
  } catch {
    return [];
  }
}

export default function Activity() {
  const [rows] = createResource(load);
  const [filter, setFilter] = createSignal("all");
  const [range, setRange] = createSignal("7");

  const visible = () => {
    const days = ranges.find((r) => r.id === range())?.days;
    const cutoff = days ? Date.now() - days * 86400000 : 0;
    return (rows() || []).filter((r) => {
      if (filter() === "threats" && r[1] !== "Quarantined" && r[1] !== "Deleted") return false;
      // "YYYY-MM-DD HH:MM:SS" local time; an unparseable stamp is kept rather than hidden.
      const t = new Date(r[0].replace(" ", "T")).getTime();
      return Number.isNaN(t) || t >= cutoff;
    });
  };

  return (
    <main class="nv-main">
      <header class="page-head">
        <h1>Activity</h1>
        <div class="act-filters" role="group" aria-label="Filter">
          <For each={filters}>
            {(f) => (
              <button type="button" class="act-chip" aria-pressed={filter() === f.id} disabled={f.soon} title={f.soon ? "Coming soon" : undefined} onClick={() => setFilter(f.id)}>{f.label}</button>
            )}
          </For>
        </div>
        <div class="page-actions">
          <label for="a-range" class="sr-only">Time range</label>
          <select id="a-range" class="field field-sm" value={range()} onChange={(e) => setRange(e.currentTarget.value)}>
            <For each={ranges}>{(r) => <option value={r.id}>{r.label}</option>}</For>
          </select>
          <button type="button" class="btn btn-sm" disabled title="Coming soon">Export log</button>
        </div>
      </header>

      <section class="table-card act-table" aria-label="Events">
        <Show when={visible().length > 0} fallback={<p class="empty">{rows.loading ? "Loading…" : "No events in this view."}</p>}>
          <table class="tbl">
            <thead><tr><th scope="col" class="act-time">Time</th><th scope="col">Event</th><th scope="col">Details</th><th scope="col">Source</th></tr></thead>
            <tbody>
              <For each={visible()}>
                {(r) => (
                  <tr>
                    <td class="mono muted">{r[0]}</td>
                    <td>
                      <span class="act-event" classList={{ threat: r[1] === "Quarantined" || r[1] === "Deleted" }}>
                        <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{icons[r[1]] || <circle cx="12" cy="12" r="3" />}</svg>
                        {r[1]}
                      </span>
                    </td>
                    <td><div class="cell-path" style={{ color: "var(--tx)" }}>{showPath(r[2])}</div><div class="muted" style={{ "font-size": "12px" }}>{details[r[1]] || ""}</div></td>
                    <td>App</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </section>
    </main>
  );
}
