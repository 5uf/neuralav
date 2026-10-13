import { A } from "@solidjs/router";
import { createSignal, onMount } from "solid-js";
import { getVersion } from "@tauri-apps/api/app";
import { theme } from "./theme";
import Dashboard from "./components/Dashboard";
import Scan from "./components/Scan";
import Monitor from "./components/Monitor";
import Quarantine from "./components/Quarantine";
import Activity from "./components/Activity";
import Settings from "./components/Settings";
import "./App.css";

const svg = { "aria-hidden": "true", width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round" };

const links = [
  { href: "/", label: "Dashboard", end: true, icon: () => (<><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>) },
  { href: "/scan", label: "Scan", icon: () => (<><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></>) },
  { href: "/monitor", label: "Monitor", icon: () => (<><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>) },
  { href: "/quarantine", label: "Quarantine", icon: () => (<><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>) },
  { href: "/activity", label: "Activity", icon: () => <path d="M3 12h4l3-8 4 16 3-8h4" /> },
  { href: "/settings", label: "Settings", icon: () => (<><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" /></>) },
];

export function Layout(props) {
  const [version, setVersion] = createSignal("—");
  onMount(async () => {
    try {
      setVersion(await getVersion());
    } catch {
      // Not running inside Tauri (plain `npm run dev`).
    }
  });

  return (
    <div class={`nv t-${theme()}`}>
      <nav class="nv-nav" aria-label="Main">
        <div class="nv-brand">
          <svg aria-hidden="true" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
          <span class="nv-brand-name">Neural AV</span>
        </div>
        <div class="nv-links">
          {links.map((l) => (
            <A href={l.href} end={l.end}>
              <svg {...svg}>{l.icon()}</svg>
              {l.label}
            </A>
          ))}
        </div>
        <div class="nv-foot">
          <strong>Engine {version()}</strong>
          <span class="mono">RAM — · CPU —</span>
        </div>
      </nav>
      {props.children}
    </div>
  );
}

// Plain config, not JSX: JSX at module level runs outside a reactive root and leaks.
export const routes = [
  { path: "/", component: Dashboard },
  { path: "/scan", component: Scan },
  { path: "/monitor", component: Monitor },
  { path: "/quarantine", component: Quarantine },
  { path: "/activity", component: Activity },
  { path: "/settings", component: Settings },
  { path: "*", component: Dashboard },
];
