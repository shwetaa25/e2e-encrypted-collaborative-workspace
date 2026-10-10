import { useEffect, useMemo, useRef, useState } from "react";
import { adminApi, type NetworkLogEntry, type NetworkField, type NetworkBody } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

const VERDICT_STYLE: Record<NetworkLogEntry["verdict"], { label: string; cls: string }> = {
  encrypted: { label: "🔒 Encrypted payload", cls: "pill-green" },
  auth: { label: "🔑 Authentication", cls: "pill-warn" },
  metadata: { label: "ℹ Metadata only", cls: "pill-blue" },
  warning: { label: "⚠ Check payload", cls: "pill-danger" },
};

const KIND_STYLE: Record<string, { cls: string; hint: string }> = {
  ciphertext: { cls: "pill-green", hint: "AES-256-GCM ciphertext" },
  wrapped_key: { cls: "pill-green", hint: "RSA-OAEP wrapped key" },
  search_token: { cls: "pill-green", hint: "HMAC keyword token" },
  "iv/salt": { cls: "pill-blue", hint: "public parameter" },
  public_key: { cls: "pill-blue", hint: "public key" },
  jwt: { cls: "pill-blue", hint: "session token" },
  credential: { cls: "pill-warn", hint: "password (redacted)" },
  metadata: { cls: "pill-gray", hint: "ids / numbers / emails" },
  "PLAINTEXT?": { cls: "pill-danger", hint: "readable text — investigate" },
};

type Filter = "all" | "encrypted" | "auth" | "warning";

export function NetworkLogPanel() {
  const { token } = useSessionStore();
  const [entries, setEntries] = useState<NetworkLogEntry[]>([]);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [live, setLive] = useState(true);
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const sinceRef = useRef(0);

  useEffect(() => {
    if (!token || !live) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await adminApi.networkLog(sinceRef.current, token);
        if (cancelled) return;
        if (res.latest_seq < sinceRef.current) { sinceRef.current = 0; setEntries([]); }   // server restarted
        if (res.entries.length) {
          sinceRef.current = res.latest_seq;
          setEntries((prev) => [...prev, ...res.entries].slice(-500));
        }
        setError(null);
      } catch { if (!cancelled) setError("Cannot reach the server"); }
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => { cancelled = true; clearInterval(id); };
  }, [token, live]);

  const clear = async () => {
    if (!token) return;
    await adminApi.clearNetworkLog(token).catch(() => {});
    setEntries([]); setSelectedSeq(null);
  };

  const summary = useMemo(() => {
    const encrypted = entries.filter((e) => e.verdict === "encrypted").length;
    const warnings = entries.filter((e) => e.verdict === "warning").length;
    const opaqueFields = entries.reduce((n, e) =>
      n + [...e.request.fields, ...e.response.fields].filter((f) => ["ciphertext", "wrapped_key", "search_token"].includes(f.kind)).length, 0);
    return { total: entries.length, encrypted, warnings, opaqueFields };
  }, [entries]);

  const visible = useMemo(
    () => entries.filter((e) => filter === "all" || e.verdict === filter).slice().reverse(),
    [entries, filter],
  );
  const selected = entries.find((e) => e.seq === selectedSeq) ?? null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14, height: "100%" }}>
      {/* Summary banner */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <Stat label="Requests observed" value={summary.total} />
        <Stat label="Carrying encrypted payloads" value={summary.encrypted} color="var(--encrypted)" />
        <Stat label="Opaque fields seen" value={summary.opaqueFields} color="var(--encrypted)" />
        <Stat label="Plaintext content found" value={summary.warnings}
          color={summary.warnings ? "var(--danger)" : "var(--encrypted)"}
          sub={summary.warnings ? "investigate the ⚠ rows" : "none — as designed"} />
      </div>

      <div className="info-box" style={{ margin: 0 }}>
        This is exactly what the <strong>server receives</strong>, captured before any processing. Document titles,
        contents, comments, workspace names and keys arrive as random-looking ciphertext — you don't need browser
        DevTools. Passwords are redacted here (they are only ever sent over TLS to be bcrypt-hashed).
        Use the app in another window and requests appear below in real time.
      </div>

      {/* Toolbar */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        {(["all", "encrypted", "auth", "warning"] as Filter[]).map((f) => (
          <button key={f} className={`btn btn-sm ${filter === f ? "btn-primary" : "btn-ghost"}`} onClick={() => setFilter(f)}>
            {f === "all" ? "All" : f === "encrypted" ? "🔒 Encrypted" : f === "auth" ? "🔑 Auth" : "⚠ Warnings"}
          </button>
        ))}
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          {error && <span style={{ fontSize: 12, color: "var(--danger)" }}>{error}</span>}
          <button className={`btn btn-sm ${live ? "btn-primary" : "btn-ghost"}`} onClick={() => setLive((v) => !v)}>
            {live ? "● Live" : "○ Paused"}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={clear}>Clear</button>
        </div>
      </div>

      {/* List + detail */}
      <div style={{ display: "flex", gap: 14, flex: 1, minHeight: 0 }}>
        <div className="card" style={{ flex: "1 1 55%", padding: 0, overflow: "auto", minWidth: 0 }}>
          <table className="admin-table">
            <thead>
              <tr><th>Time</th><th>Request</th><th>Status</th><th>Verdict</th><th style={{ textAlign: "right" }}>Size</th></tr>
            </thead>
            <tbody>
              {visible.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: 28 }}>
                  No requests yet — use the workspace in another tab or window.
                </td></tr>
              )}
              {visible.map((e) => (
                <tr key={e.seq} className={e.seq === selectedSeq ? "selected" : ""} onClick={() => setSelectedSeq(e.seq)}>
                  <td className="mono muted">{new Date(e.ts).toLocaleTimeString()}</td>
                  <td className="mono"><span style={{ color: methodColor(e.method), fontWeight: 600 }}>{e.method}</span> {e.path.replace("/api/v1", "")}</td>
                  <td className="mono" style={{ color: e.status >= 400 ? "var(--danger)" : "var(--text-secondary)" }}>{e.status}</td>
                  <td><span className={`pill ${VERDICT_STYLE[e.verdict].cls}`}>{VERDICT_STYLE[e.verdict].label}</span></td>
                  <td className="mono muted" style={{ textAlign: "right" }}>{fmtBytes(e.request.bytes)} → {fmtBytes(e.response.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card" style={{ flex: "1 1 45%", overflow: "auto", minWidth: 0 }}>
          {selected ? <Detail entry={selected} /> : (
            <div className="empty-state" style={{ padding: "40px 12px" }}>
              <p>Select a request to inspect its fields.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Detail({ entry }: { entry: NetworkLogEntry }) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
        <span className="mono" style={{ fontWeight: 600 }}>{entry.method} {entry.path}{entry.query ? `?${entry.query}` : ""}</span>
        <span className={`pill ${VERDICT_STYLE[entry.verdict].cls}`}>{VERDICT_STYLE[entry.verdict].label}</span>
      </div>
      <div className="muted" style={{ fontSize: 11, marginBottom: 12 }}>
        {entry.status} · {entry.duration_ms} ms · {entry.authenticated ? "Bearer token sent (hidden)" : "no auth header"}
      </div>
      <BodyView title="Request body (what the server received)" body={entry.request} />
      <BodyView title="Response body (what the server sent back)" body={entry.response} />
    </div>
  );
}

function BodyView({ title, body }: { title: string; body: NetworkBody }) {
  const [showRaw, setShowRaw] = useState(false);
  if (!body.present) {
    return <div style={{ marginBottom: 14 }}><div className="section-title">{title}</div><div className="muted" style={{ fontSize: 12 }}>— empty —</div></div>;
  }
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div className="section-title">{title}</div>
        <button className="btn btn-ghost btn-xs" onClick={() => setShowRaw((v) => !v)}>{showRaw ? "Fields" : "Raw JSON"}</button>
      </div>
      {showRaw ? (
        <pre className="raw-json">{body.raw}</pre>
      ) : (
        <table className="admin-table compact">
          <thead><tr><th>Field</th><th>Type</th><th>Value seen by server</th></tr></thead>
          <tbody>
            {body.fields.map((f, i) => <FieldRow key={i} f={f} />)}
          </tbody>
        </table>
      )}
    </div>
  );
}

function FieldRow({ f }: { f: NetworkField }) {
  const style = KIND_STYLE[f.kind] ?? KIND_STYLE.metadata;
  return (
    <tr>
      <td className="mono" style={{ wordBreak: "break-all" }}>{f.key}</td>
      <td><span className={`pill ${style.cls}`} title={style.hint}>{f.kind}</span></td>
      <td className="mono" style={{ wordBreak: "break-all" }}>
        <span style={{ color: f.ok ? "var(--text-secondary)" : "var(--danger)" }}>{f.preview}</span>
        {(f.bytes || f.entropy) && (
          <div className="muted" style={{ fontSize: 10 }}>
            {f.bytes ? `${f.bytes} bytes` : ""}{f.entropy ? ` · entropy ${f.entropy}/8 bits per byte` : ""}
          </div>
        )}
        {f.note && <div className="muted" style={{ fontSize: 10 }}>{f.note}</div>}
      </td>
    </tr>
  );
}

function Stat({ label, value, color, sub }: { label: string; value: number; color?: string; sub?: string }) {
  return (
    <div className="card" style={{ flex: "1 1 150px", minWidth: 150 }}>
      <div className="muted" style={{ fontSize: 11 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 600, color: color ?? "var(--text-primary)" }}>{value}</div>
      {sub && <div className="muted" style={{ fontSize: 10 }}>{sub}</div>}
    </div>
  );
}

function methodColor(m: string) {
  return m === "GET" ? "var(--accent)" : m === "POST" ? "var(--encrypted)" : m === "DELETE" ? "var(--danger)" : "var(--warn)";
}
function fmtBytes(n: number) {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
}
