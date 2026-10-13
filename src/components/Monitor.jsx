import "./Monitor.css";

const totals = ["Apps watched", "Using AI services", "Needs review", "Stopped today"];

export default function Monitor() {
  return (
    <main class="nv-main">
      <header class="page-head">
        <h1>Monitor</h1>
        <span class="page-sub">Live view of running apps</span>
        <span class="soon">Coming soon</span>
        <div class="page-actions mon-tools">
          <label for="mon-search" class="sr-only">Search apps</label>
          <input id="mon-search" class="field mon-search" type="search" placeholder="Search apps" disabled />
          <label class="check-box"><input type="checkbox" checked disabled />AI or network only</label>
          <button type="button" class="btn" disabled>Pause</button>
        </div>
      </header>

      <section class="stats" aria-label="Monitor totals">
        {totals.map((t) => (
          <div class="stat"><span class="stat-label">{t}</span><span class="stat-value">—</span></div>
        ))}
      </section>

      <div class="split">
        <section class="table-card mon-table split-main" aria-label="Running apps">
          <table class="tbl">
            <thead><tr><th scope="col">App</th><th scope="col">Signed</th><th scope="col">AI service</th><th scope="col">Behavior</th><th scope="col">Risk</th></tr></thead>
          </table>
          <p class="empty">No live data. The behavior monitor is not available yet, so no apps are listed.</p>
        </section>

        <aside class="card mon-aside split-aside" aria-labelledby="detail-title">
          <h2 id="detail-title">App details</h2>
          <p class="muted" style={{ margin: 0 }}>Select an app to see its timeline once the monitor is available.</p>
          <div class="btn-row">
            <button type="button" class="btn btn-warn" disabled>Stop and quarantine</button>
            <button type="button" class="btn" disabled>Trust this app</button>
            <button type="button" class="btn" disabled>Open location</button>
          </div>
        </aside>
      </div>
    </main>
  );
}
