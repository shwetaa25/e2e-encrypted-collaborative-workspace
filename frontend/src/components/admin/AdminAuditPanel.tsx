import { useEffect, useState } from "react";
import { adminApi, type AuditEntry, type AuditVerify } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

export function AdminAuditPanel() {
  const { token } = useSessionStore();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (token) adminApi.audit(token).then(setEntries).catch(() => {});
  }, [token]);

  const runVerify = async () => {
    if (!token) return;
    setChecking(true);
    try { setVerify(await adminApi.verifyAudit(token)); } finally { setChecking(false); }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="card" style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>Tamper-evident audit chain</div>
          <div className="muted" style={{ fontSize: 12 }}>
            Every entry stores the SHA-256 hash of the previous one. Re-computing the chain proves nothing was edited or deleted.
          </div>
        </div>
        {verify && (
          <span className={`pill ${verify.valid ? "pill-green" : "pill-danger"}`}>
            {verify.valid ? `✓ Chain intact (${verify.total_entries} entries)` : `✕ Broken at ${verify.broken_at}`}
          </span>
        )}
        <button className="btn btn-primary btn-sm" onClick={runVerify} disabled={checking}>
          {checking ? "Verifying…" : "Verify chain"}
        </button>
      </div>
      <div className="card" style={{ padding: 0, overflow: "auto" }}>
        <table className="admin-table compact">
          <thead><tr><th>Hour (UTC)</th><th>Action</th><th>Actor (pseudonym)</th><th>Entry hash</th></tr></thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="mono muted">{new Date(e.created_at_hour).toISOString().slice(0, 13)}:00</td>
                <td>{e.action_type}</td>
                <td className="mono muted">{e.actor_pseudonym.slice(0, 12)}…</td>
                <td className="mono muted">{e.entry_hash.slice(0, 16)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
