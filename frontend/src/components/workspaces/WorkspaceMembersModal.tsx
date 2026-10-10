import { useEffect, useState } from "react";
import { authApi, workspacesApi, ApiError, type WorkspaceMemberResponse } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";
import { importPublicKey, wrapDocumentKey } from "../../crypto";
import type { DecryptedWorkspace } from "./types";

interface Props {
  workspace: DecryptedWorkspace;
  onClose: () => void;
  onMembersChanged: (count: number) => void;
  onLeftOrDeleted: () => void;
  onDeleteWorkspace: () => void;
  showToast: (msg: string, type?: "success" | "error") => void;
}

export function WorkspaceMembersModal({ workspace, onClose, onMembersChanged, onLeftOrDeleted, onDeleteWorkspace, showToast }: Props) {
  const { token, userId } = useSessionStore();
  const [members, setMembers] = useState<WorkspaceMemberResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isOwner = workspace.role === "owner";

  const load = () => {
    if (!token) return;
    workspacesApi.members(workspace.id, token)
      .then((m) => { setMembers(m); onMembersChanged(m.length); })
      .catch(() => setError("Could not load members"))
      .finally(() => setLoading(false));
  };
  useEffect(load, [workspace.id, token]);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setBusy(true); setError(null);
    try {
      const user = await authApi.getUserByUsername(username.trim().replace(/^@/, ""), token);
      // Wrap the workspace key for the invitee — server never sees it
      const pub = await importPublicKey(user.public_key_spki);
      const wrapped = await wrapDocumentKey(workspace.key, pub);
      await workspacesApi.addMember(workspace.id, { user_id: user.user_id, wrapped_workspace_key: wrapped }, token);
      setUsername("");
      showToast(`@${user.username} added to ${workspace.name} 🔒`);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not add member");
    } finally { setBusy(false); }
  };

  const handleRemove = async (m: WorkspaceMemberResponse) => {
    if (!token) return;
    const self = m.user_id === userId;
    const msg = self
      ? `Leave “${workspace.name}”? You will lose access to files shared with you here.`
      : `Remove @${m.username} from “${workspace.name}”?\n\nThey immediately lose access to every file in this workspace.`;
    if (!confirm(msg)) return;
    try {
      await workspacesApi.removeMember(workspace.id, m.user_id, token);
      if (self) { onLeftOrDeleted(); return; }
      showToast(`@${m.username} removed`);
      load();
    } catch (err) {
      showToast(err instanceof ApiError ? err.detail : "Could not remove member", "error");
    }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal">
        <h2 className="modal-title">{workspace.name}</h2>
        <p className="modal-sub">
          Members can see that the workspace exists. They only open files whose owner has shared them.
        </p>

        {isOwner && (
          <form onSubmit={handleAdd} style={{ marginBottom: 14 }}>
            <label className="input-label">Add a person by username</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input className="input" placeholder="e.g. bob_dev" value={username} autoComplete="off"
                onChange={(e) => setUsername(e.target.value)} required disabled={busy} />
              <button className="btn btn-primary" type="submit" disabled={busy || !username.trim()}>
                {busy ? "Adding…" : "Add"}
              </button>
            </div>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>They need an account first.</span>
          </form>
        )}
        {error && <div className="error-box">{error}</div>}

        <div className="input-label">Members ({members.length})</div>
        {loading ? (
          <div style={{ display: "flex", justifyContent: "center", padding: 16 }}><div className="spinner" /></div>
        ) : members.map((m) => (
          <div key={m.user_id} className="member-card">
            <div className="avatar">{m.username[0].toUpperCase()}</div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                @{m.username}{m.user_id === userId && <span style={{ color: "var(--text-muted)" }}> (you)</span>}
              </div>
              <div style={{ fontSize: 11, color: m.role === "owner" ? "var(--accent)" : "var(--text-muted)" }}>{m.role}</div>
            </div>
            {m.role !== "owner" && (isOwner || m.user_id === userId) && (
              <button className="btn btn-danger btn-xs" onClick={() => handleRemove(m)}>
                {m.user_id === userId ? "Leave" : "Remove"}
              </button>
            )}
          </div>
        ))}

        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 14 }}>
          {isOwner ? (
            <button className="btn btn-danger btn-sm"
              onClick={() => { if (confirm(`Delete “${workspace.name}” and ALL files inside it? This cannot be undone.`)) onDeleteWorkspace(); }}>
              Delete workspace
            </button>
          ) : <span />}
          <button className="btn btn-ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
