import { useEffect, useState } from "react";
import { adminApi, ApiError, type AdminWorkspace } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

export function WorkspacesPanel() {
  const { token } = useSessionStore();
  const [items, setItems] = useState<AdminWorkspace[]>([]);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = () => { if (token) adminApi.workspaces(token).then(setItems).catch(() => {}); };
  useEffect(load, [token]);

  const remove = async (w: AdminWorkspace) => {
    if (!token) return;
    if (!confirm(
      `Delete this workspace owned by @${w.owner_username}?\n\n` +
      `${w.document_count} file(s) inside it are deleted and its ${w.member_count} member(s) lose access.\n\nThis cannot be undone.`
    )) return;
    setBusyId(w.id); setMsg(null);
    try {
      await adminApi.deleteWorkspace(w.id, token);
      setMsg({ text: "Workspace deleted", ok: true });
      load();
    } catch (err) {
      setMsg({ text: err instanceof ApiError ? err.detail : "Could not delete workspace", ok: false });
    } finally { setBusyId(null); }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div className="info-box" style={{ margin: 0 }}>
        Workspace names are encrypted for their members, so the admin sees only the ciphertext. You can still remove any workspace.
      </div>
      {msg && <div className={msg.ok ? "info-box" : "error-box"} style={{ margin: 0 }}>{msg.text}</div>}
      <div className="card" style={{ padding: 0, overflow: "auto" }}>
        <table className="admin-table">
          <thead><tr><th>Owner</th><th>Name (ciphertext)</th><th>Members</th><th>Files</th><th>Created</th><th /></tr></thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>No workspaces yet.</td></tr>
            )}
            {items.map((w) => (
              <tr key={w.id}>
                <td>@{w.owner_username}</td>
                <td className="mono" style={{ color: "var(--encrypted)" }}>{w.name_ciphertext_preview}</td>
                <td>{w.member_count}</td>
                <td>{w.document_count}</td>
                <td className="muted">{w.created_at ? new Date(w.created_at).toLocaleString() : "—"}</td>
                <td style={{ textAlign: "right" }}>
                  <button className="btn btn-danger btn-xs" disabled={busyId === w.id} onClick={() => remove(w)}>
                    {busyId === w.id ? "Deleting…" : "Delete"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
