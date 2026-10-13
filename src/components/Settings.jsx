import { createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { theme, setTheme } from "../theme";
import "./Settings.css";

const themes = [
  { id: "auto", label: "System" },
  { id: "dark", label: "Dark" },
  { id: "light", label: "Light" },
];

// Keywords per section, used by the search box.
const keywords = {
  prot: "protection quarantine automatically behavior monitor ai generated code suspicious",
  sched: "schedule quick scan full scan usb plugged in",
  excl: "exclusions trusted apps folder app",
  upd: "updates rules automatically version signature",
  priv: "privacy cloud hash lookup activity log keep",
  app: "app theme system dark light start login notify threats tray",
  tools: "tools clean temp files flush dns cache hash",
  about: "about version license author source diagnostics",
};

function SoonRow(props) {
  return (
    <label class="set-row">
      <span class="set-sub"><span>{props.label}</span><Show when={props.hint}><small>{props.hint}</small></Show></span>
      <input type="checkbox" disabled />
    </label>
  );
}

export default function Settings() {
  const [query, setQuery] = createSignal("");
  const [version, setVersion] = createSignal("—");
  const [busy, setBusy] = createSignal(false);
  const [toolMsg, setToolMsg] = createSignal("");

  getVersion().then(setVersion).catch(() => {});

  const show = (id) => {
    const q = query().trim().toLowerCase();
    return !q || keywords[id].includes(q);
  };

  async function tool(command) {
    setBusy(true);
    setToolMsg("Working…");
    try {
      setToolMsg(await invoke(command));
    } catch (e) {
      setToolMsg(`Failed: ${e}`);
    }
    setBusy(false);
  }

  return (
    <main class="nv-main">
      <header class="page-head">
        <h1>Settings</h1>
        <div class="page-actions">
          <label for="s-search" class="sr-only">Search settings</label>
          <input id="s-search" class="field set-search" type="search" placeholder="Search settings" value={query()} onInput={(e) => setQuery(e.currentTarget.value)} />
        </div>
      </header>

      <div class="set-grid">
        <section class="card set-card" aria-labelledby="s-prot" hidden={!show("prot")}>
          <h2 id="s-prot">Protection <span class="soon">Coming soon</span></h2>
          <SoonRow label="Quarantine malicious files automatically" />
          <SoonRow label="Behavior monitor" />
          <SoonRow label="Stop unknown apps that run AI-generated code" />
          <SoonRow label="Ask before acting on Suspicious files" />
        </section>

        <section class="card set-card" aria-labelledby="s-sched" hidden={!show("sched")}>
          <h2 id="s-sched">Schedule <span class="soon">Coming soon</span></h2>
          <div class="set-row set-row-static"><label for="s-quick">Quick scan</label><select id="s-quick" class="field field-sm" disabled><option>Off</option></select></div>
          <div class="set-row set-row-static"><label for="s-full">Full scan</label><select id="s-full" class="field field-sm" disabled><option>Off</option></select></div>
          <SoonRow label="Scan USB drives when connected" />
          <SoonRow label="Only when plugged in" />
        </section>

        <section class="card set-card" aria-labelledby="s-excl" hidden={!show("excl")}>
          <h2 id="s-excl">Exclusions and trusted apps <span class="soon">Coming soon</span></h2>
          <p class="muted" style={{ margin: "6px 0" }}>No exclusions. Nothing is skipped by scans.</p>
          <div><button type="button" class="btn btn-sm" disabled>Add</button></div>
        </section>

        <section class="card set-card" aria-labelledby="s-upd" hidden={!show("upd")}>
          <h2 id="s-upd">Updates <span class="soon">Coming soon</span></h2>
          <SoonRow label="Update rules automatically" />
          <div class="set-row set-row-static"><span>Rules <span class="mono muted">—</span></span><button type="button" class="btn btn-sm" disabled>Check now</button></div>
          <div class="set-row set-row-static last"><span>App {version()}</span></div>
        </section>

        <section class="card set-card" aria-labelledby="s-priv" hidden={!show("priv")}>
          <h2 id="s-priv">Privacy <span class="soon">Coming soon</span></h2>
          <SoonRow label="Cloud hash lookup" hint="Sends file hashes, never files" />
          <label class="set-row last"><span>Keep activity log for</span><select class="field field-sm" disabled><option>90 days</option></select></label>
        </section>

        <section class="card set-card" aria-labelledby="s-app" hidden={!show("app")}>
          <h2 id="s-app">App</h2>
          <fieldset class="set-theme">
            <legend>Theme</legend>
            <For each={themes}>
              {(t) => (
                <label class="check"><input type="radio" name="theme" value={t.id} checked={theme() === t.id} onChange={() => setTheme(t.id)} />{t.label}</label>
              )}
            </For>
          </fieldset>
          <SoonRow label="Start at login" />
          <SoonRow label="Notify me about threats" />
          <SoonRow label="Close to tray" />
        </section>

        <section class="card set-card" aria-labelledby="s-tools" hidden={!show("tools")}>
          <h2 id="s-tools">Tools</h2>
          <div class="set-row set-row-static"><span class="set-sub"><span>Clean temp files</span><small>Older than 7 days, yours only</small></span><button type="button" class="btn btn-sm" disabled={busy()} onClick={() => tool("clean")}>Clean</button></div>
          <div class="set-row set-row-static"><span class="set-sub"><span>Flush DNS cache</span><small>May need administrator rights</small></span><button type="button" class="btn btn-sm" disabled={busy()} onClick={() => tool("optimize")}>Flush</button></div>
          <div class="set-row set-row-static last"><span class="set-sub"><span>Check a file hash</span><small>Coming soon</small></span><button type="button" class="btn btn-sm" disabled>Open</button></div>
          <p class="set-msg" role="status">{toolMsg()}</p>
        </section>

        <section class="card set-card" aria-labelledby="s-about" hidden={!show("about")}>
          <h2 id="s-about">About</h2>
          <dl class="set-about">
            <dt>Version</dt><dd class="mono">{version()}</dd>
            <dt>License</dt><dd>MIT</dd>
            <dt>Author</dt><dd>Muhammad Sufi Afifi</dd>
            <dt>Source</dt><dd class="mono">github.com/5uf/neuralav</dd>
          </dl>
        </section>
      </div>
    </main>
  );
}
