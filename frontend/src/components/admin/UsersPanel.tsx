import { useEffect, useState } from "react";
import { adminApi, ApiError, type AdminUser } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

export function UsersPanel() {
  const { token, userId } = useSessionStore();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = () => { if (token) adminApi.users(token).then(setUsers).catch(() => {}); };
  useEffect(load, [token]);

  const remove = async (u: AdminUser) => {
    if (!token) return;
    const who = u.username ? `@${u.username}` : u.email;
    const ok = confirm(
      `Permanently delete ${who}?\n\n` +
      `• ${u.documents_owned} document(s) they own will be deleted (shared copies vanish for everyone)\n` +
      `• ${u.workspaces_owned} workspace(s) they own will be deleted with all files inside\n` +
      `• Their comments, keys and memberships are removed\n\nThis cannot be undone.`
    );
    if (!ok) return;
    setBusyId(u.id); setMsg(null);
    try {
      await adminApi.deleteUser(u.id, token);
      setMsg({ text: `${who} deleted`, ok: true });
      load();
    } catch (err) {
      setMsg({ text: err instanceof ApiError ? err.detail : "Could not delete user", ok: false });
    } finally { setBusyId(null); }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {msg && <div className={msg.ok ? "info-box" : "error-box"} style={{ margin: 0 }}>{msg.text}</div>}
      <div className="card" style={{ padding: 0, overflow: "auto" }}>
        <table className="admin-table">
          <thead><tr><th>Username</th><th>Email</th><th>Created</th><th>Last sign-in</th><th>Owns</th><th>Role</th><th /></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username ? `@${u.username}` : "—"}</td>
                <td>{u.email}</td>
                <td className="muted">{u.created_at ? new Date(u.created_at).toLocaleString() : "—"}</td>
                <td className="muted">{u.last_seen_at ? new Date(u.last_seen_at).toLocaleString() : "never"}</td>
                <td className="muted">{u.documents_owned} docs · {u.workspaces_owned} ws</td>
                <td>{u.is_admin ? <span className="pill pill-blue">admin</span> : <span className="muted">user</span>}</td>
                <td style={{ textAlign: "right" }}>
                  {!u.is_admin && u.id !== userId && (
                    <button className="btn btn-danger btn-xs" disabled={busyId === u.id} onClick={() => remove(u)}>
                      {busyId === u.id ? "Deleting…" : "Delete"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="muted" style={{ fontSize: 11, padding: 10 }}>
          Admins can manage accounts but can never read any user's documents, titles, keys or comments. Admin accounts cannot be deleted here.
        </div>
      </div>
    </div>
  );
}
