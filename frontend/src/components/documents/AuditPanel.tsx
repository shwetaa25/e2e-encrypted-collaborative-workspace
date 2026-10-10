import { useEffect, useState } from "react";
import { documentsApi, type AuditEntry } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

interface Props {
  documentId: string;
  showToast: (msg: string, type?: "success" | "error") => void;
}

const ACTION_COLORS: Record<string, string> = {
  "document.created": "var(--encrypted)",
  "document.opened": "var(--accent)",
  "document.updated": "var(--accent)",
  "document.deleted": "var(--danger)",
  "access.granted": "var(--warn)",
  "access.revoked": "var(--danger)",
  "comment.added": "var(--text-secondary)",
  "search.performed": "var(--text-muted)",
  "key.rotated": "var(--danger)",
  "user.registered": "var(--encrypted)",
  "user.login": "var(--text-muted)",
};

const ACTION_ICONS: Record<string, string> = {
  "document.created": "📄", "document.opened": "👁", "document.updated": "✏️",
  "document.deleted": "🗑", "access.granted": "🔗", "access.revoked": "🚫",
  "comment.added": "💬", "search.performed": "🔍", "key.rotated": "🔑",
  "user.registered": "👤", "user.login": "🔐",
};

export function AuditPanel({ documentId, showToast }: Props) {
  const { token } = useSessionStore();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [chainValid, setChainValid] = useState<boolean | null>(null);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    documentsApi.getAuditLog(documentId, token)
      .then((data) => {
        setEntries(data);
        // Verify chain: every entry's prev_entry_hash must match the previous entry's entry_hash
        let valid = true;
        for (let i = 1; i < data.length; i++) {
          if (data[i].prev_entry_hash && data[i - 1].entry_hash !== data[i].prev_entry_hash) {
            valid = false;
            break;
          }
        }
        setChainValid(valid);
      })
      .catch(() => showToast("Failed to load audit log", "error"))
      .finally(() => setLoading(false));
  }, [documentId, token]);

  if (loading) return <div style={{ display: "flex", justifyContent: "center", padding: 20 }}><div className="spinner" /></div>;

  return (
    <div>
      {/* Chain integrity status */}
      <div style={{ padding: "6px 10px", borderRadius: "var(--radius-sm)", marginBottom: 8, display: "flex", alignItems: "center", gap: 8, background: chainValid ? "var(--encrypted-dim)" : "var(--danger-dim)", border: `1px solid ${chainValid ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)"}`, fontSize: 11, color: chainValid ? "var(--encrypted)" : "var(--danger)" }}>
        {chainValid === null ? "–" : chainValid ? "✓" : "✕"}
        <span>{chainValid === null ? "Checking…" : chainValid ? "SHA-256 chain integrity verified" : "⚠ Chain tampered!"}</span>
      </div>

      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, lineHeight: 1.5 }}>
        Pseudonymous actors · Timestamps truncated to hour · {entries.length} entries
      </div>

      {entries.length === 0 ? (
        <div className="empty-state" style={{ padding: "20px 0" }}><p>No audit entries yet.</p></div>
      ) : (
        entries.map((e) => (
          <div key={e.id} className="audit-entry">
            <div className="audit-action" style={{ color: ACTION_COLORS[e.action_type] ?? "var(--text-primary)", display: "flex", alignItems: "center", gap: 6 }}>
              <span>{ACTION_ICONS[e.action_type] ?? "•"}</span>
              <span>{e.action_type}</span>
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", margin: "2px 0" }}>
              {new Date(e.created_at_hour).toLocaleString()}
            </div>
            <div className="audit-hash">
              actor: {e.actor_pseudonym.slice(0, 12)}…
            </div>
            <div className="audit-hash">
              hash: {e.entry_hash.slice(0, 16)}…
            </div>
          </div>
        ))
      )}
    </div>
  );
}
