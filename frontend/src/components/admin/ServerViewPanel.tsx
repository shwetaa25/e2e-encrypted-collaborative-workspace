import { useEffect, useState } from "react";
import { adminApi, type DbView } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

export function ServerViewPanel() {
  const { token } = useSessionStore();
  const [table, setTable] = useState("documents");
  const [view, setView] = useState<DbView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    if (!token) return;
    setLoading(true);
    adminApi.dbView(table, token)
      .then((v) => { setView(v); setError(null); })
      .catch(() => setError("Could not load table"))
      .finally(() => setLoading(false));
  };
  useEffect(load, [table, token]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="info-box" style={{ margin: 0 }}>
        The rows below are read straight from PostgreSQL — the same thing an attacker with database access (or a
        curious administrator) would see. Every content column is ciphertext; there is no plaintext title, body,
        comment or workspace name anywhere.
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {(view?.tables ?? ["documents", "document_keys", "workspaces", "workspace_members", "comments", "search_index", "users"]).map((t) => (
          <button key={t} className={`btn btn-sm ${t === table ? "btn-primary" : "btn-ghost"}`} onClick={() => setTable(t)}>{t}</button>
        ))}
        <button className="btn btn-ghost btn-sm" style={{ marginLeft: "auto" }} onClick={load}>↻ Refresh</button>
      </div>
      {error && <div className="error-box">{error}</div>}
      <div className="card" style={{ padding: 0, overflow: "auto" }}>
        {loading ? (
          <div style={{ display: "flex", justifyContent: "center", padding: 24 }}><div className="spinner" /></div>
        ) : !view || view.rows.length === 0 ? (
          <div className="empty-state" style={{ padding: 28 }}><p>No rows in <code>{table}</code> yet.</p></div>
        ) : (
          <table className="admin-table compact">
            <thead><tr>{view.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
            <tbody>
              {view.rows.map((row, i) => (
                <tr key={i}>
                  {view.columns.map((c) => {
                    const isSecret = /ciphertext|wrapped|hash|token|public_key/.test(c);
                    return (
                      <td key={c} className="mono" style={{ maxWidth: 220, wordBreak: "break-all", color: isSecret ? "var(--encrypted)" : undefined }}>
                        {row[c].value}
                        {row[c].length > row[c].value.length && <span className="muted"> ({row[c].length} chars)</span>}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="muted" style={{ fontSize: 11 }}>
        Green = opaque cryptographic material. Values are truncated for display; the newest 8 rows are shown.
      </div>
    </div>
  );
}
