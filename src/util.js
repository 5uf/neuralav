// Windows canonical paths carry a \\?\ prefix; hide it from the UI only.
export function showPath(p) {
  return String(p ?? "").replace(/^\\\\\?\\/, "");
}

export function baseName(p) {
  return showPath(p).split(/[\\/]/).pop() || showPath(p);
}

const LAST_SCAN = "nv-last-scan";

export function loadLastScan() {
  try {
    return JSON.parse(localStorage.getItem(LAST_SCAN)) || null;
  } catch {
    return null;
  }
}

export function saveLastScan(summary) {
  try {
    localStorage.setItem(LAST_SCAN, JSON.stringify(summary));
  } catch {
    // Storage can be blocked; the dashboard then shows "—".
  }
}

export function formatWhen(ms) {
  return ms ? new Date(ms).toLocaleString() : "—";
}

export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${u[i]}`;
}

// Splits a scan row [path, identity, "label,text", sizeBytes, sha256] into what the screens show.
export function describeRow(row) {
  const [path, id = "", cls = "", sizeStr = "", sha256 = ""] = row;
  const [label = "", ...rest] = cls.split(",");
  const text = rest.join(",");
  let status = "Clean";
  if (id === "Malicious") status = "Malicious";
  else if (id === "Suspicious") status = "Suspicious";
  else if (id.startsWith("Error")) status = "Not fully scanned";
  const reason = status === "Not fully scanned" ? id.replace(/^Error: /, "") : status === "Clean" ? "" : text || label || "—";
  return { path, status, label, reason, size: sizeStr === "" ? NaN : Number(sizeStr), sha256 };
}
