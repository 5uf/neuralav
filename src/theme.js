import { createSignal } from "solid-js";

const KEY = "nv-theme";
const THEMES = ["auto", "dark", "light"];

function read() {
  try {
    const v = localStorage.getItem(KEY);
    return THEMES.includes(v) ? v : "auto";
  } catch {
    return "auto";
  }
}

export const [theme, setThemeSignal] = createSignal(read());

export function setTheme(t) {
  if (!THEMES.includes(t)) return;
  setThemeSignal(t);
  try {
    localStorage.setItem(KEY, t);
  } catch {
    // Storage can be blocked; the choice still applies for this session.
  }
}
