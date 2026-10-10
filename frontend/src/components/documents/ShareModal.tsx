import { useEffect, useState } from "react";
import { authApi, documentsApi, workspacesApi, ApiError, type WorkspaceMemberResponse } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";
import { wrapDocumentKey, importPublicKey } from "../../crypto";

interface Props {
  documentId: string;
  documentKey: CryptoKey;
  /** When the file lives in a workspace, sharing is limited to that workspace's members. */
  workspaceId?: string | null;
  onClose: () => void;
  onShared: (summary: string) => void;
}

const LEVELS = [
  { value: "viewer", label: "Viewer", desc: "Can read only" },
  { value: "commenter", label: "Commenter", desc: "Can read + comment" },
  { value: "editor", label: "Editor", desc: "Can read + edit" },
];

export function ShareModal({ documentId, documentKey, workspaceId, onClose, onShared }: Props) {
  const { token, userId } = useSessionStore();
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState("");
  const [busy, setBusy] = useState(false);

  // ── Workspace mode: pick specific members ──
  const [candidates, setCandidates] = useState<WorkspaceMemberResponse[]>([]);
  const [alreadyHave, setAlreadyHave] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(!!workspaceId);
  const [selected, setSelected] = useState<Record<string, string>>({}); // userId → access level

  // ── Personal mode: by email ──
  const [username, setUsername] = useState("");
  const [level, setLevel] = useState("viewer");

  useEffect(() => {
    if (!workspaceId || !token) return;
    Promise.all([
      workspacesApi.members(workspaceId, token),
      documentsApi.getMembers(documentId, token),
    ])
      .then(([members, docMembers]) => {
        setCandidates(members.filter((m) => m.user_id !== userId));
        setAlreadyHave(new Set(docMembers.map((m) => m.user_id)));
      })
      .catch(() => setError("Could not load workspace members"))
      .finally(() => setLoading(false));
  }, [workspaceId, documentId, token, userId]);

  const shareWith = async (recipientId: string, pubKeyB64: string, accessLevel: string) => {
    const pub = await importPublicKey(pubKeyB64);
    const wrappedKey = await wrapDocumentKey(documentKey, pub); // RSA-OAEP, in the browser
    await documentsApi.share(documentId, {
      recipient_user_id: recipientId, wrapped_key: wrappedKey, access_level: accessLevel,
    }, token!);
  };

  const handleShareSelected = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    const picks = Object.entries(selected);
    if (picks.length === 0) { setError("Select at least one person"); return; }
    setError(null); setBusy(true);
    try {
      for (const [uid, lvl] of picks) {
        const member = candidates.find((c) => c.user_id === uid)!;
        setProgress(`Wrapping key for ${member.username}…`);
        await shareWith(uid, member.public_key_spki, lvl);
      }
      onShared(`Shared with ${picks.length} ${picks.length === 1 ? "person" : "people"}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : (err as Error).message ?? "Share failed");
      setBusy(false); setProgress("");
    }
  };

  const handleShareByEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setError(null); setBusy(true);
    try {
      setProgress("Looking up recipient…");
      let user;
      try { user = await authApi.getUserByUsername(username.trim().replace(/^@/, ""), token); }
      catch (err) {
        setError(err instanceof ApiError ? err.detail : "No user found with that username.");
        setBusy(false); setProgress(""); return;
      }
      setProgress("Wrapping key with RSA-2048…");
      await shareWith(user.user_id, user.public_key_spki, level);
      onShared(`Shared with @${user.username}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : (err as Error).message ?? "Share failed");
      setBusy(false); setProgress("");
    }
  };

  const toggle = (uid: string) =>
    setSelected((s) => {
      const next = { ...s };
      if (next[uid]) delete next[uid]; else next[uid] = "viewer";
      return next;
    });

  const available = candidates.filter((c) => !alreadyHave.has(c.user_id));

  return (
    <div className="modal-backdrop" onClick={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
      <div className="modal">
        <h2 className="modal-title">Share document</h2>
        <p className="modal-sub">
          {workspaceId
            ? "Choose exactly who can open this file. Workspace members you don't select cannot see it."
            : "The document key is wrapped with the recipient's RSA public key in your browser."}
        </p>
        <div className="info-box">
          🔑 The server only receives an RSA-encrypted key blob that just the recipient can unwrap.
        </div>

        {workspaceId ? (
          <form onSubmit={handleShareSelected}>
            {loading ? (
              <div style={{ display: "flex", justifyContent: "center", padding: 20 }}><div className="spinner" /></div>
            ) : available.length === 0 ? (
              <div className="empty-state" style={{ padding: "16px 0" }}>
                <p>{candidates.length === 0
                  ? "This workspace has no other members yet. Add people from the workspace's Members screen first."
                  : "Everyone in this workspace already has access to this file."}</p>
              </div>
            ) : (
              <div className="form-group">
                <label className="input-label">People in this workspace ({Object.keys(selected).length} selected)</label>
                <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 260, overflowY: "auto" }}>
                  {available.map((m) => {
                    const on = !!selected[m.user_id];
                    return (
                      <div key={m.user_id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: "var(--radius-sm)", background: on ? "var(--accent-dim)" : "var(--bg-elevated)", border: `1px solid ${on ? "rgba(79,142,247,0.3)" : "var(--border)"}` }}>
                        <input type="checkbox" checked={on} onChange={() => toggle(m.user_id)} disabled={busy} style={{ accentColor: "var(--accent)" }} />
                        <div className="avatar">{m.username[0].toUpperCase()}</div>
                        <div style={{ flex: 1, minWidth: 0, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>@{m.username}</div>
                        {on && (
                          <select className="input" style={{ width: 118, padding: "3px 6px", fontSize: 12 }}
                            value={selected[m.user_id]} disabled={busy}
                            onChange={(e) => setSelected((s) => ({ ...s, [m.user_id]: e.target.value }))}>
                            {LEVELS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
                          </select>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {error && <div className="error-box">{error}</div>}
            {busy && progress && <Progress text={progress} />}

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button type="button" className="btn btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={busy || Object.keys(selected).length === 0}>
                {busy ? "Working…" : `Share with ${Object.keys(selected).length || ""} selected`}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleShareByEmail}>
            <div className="form-group">
              <label className="input-label">Recipient username</label>
              <input className="input" placeholder="e.g. bob_dev" value={username} autoComplete="off"
                onChange={(e) => setUsername(e.target.value)} required disabled={busy} />
            </div>
            <div className="form-group">
              <label className="input-label">Access level</label>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {LEVELS.map((l) => (
                  <label key={l.value} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: "var(--radius-sm)", background: level === l.value ? "var(--accent-dim)" : "var(--bg-elevated)", border: `1px solid ${level === l.value ? "rgba(79,142,247,0.3)" : "var(--border)"}`, cursor: "pointer" }}>
                    <input type="radio" name="level" value={l.value} checked={level === l.value} onChange={() => setLevel(l.value)} style={{ accentColor: "var(--accent)" }} />
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 500, color: "var(--text-primary)" }}>{l.label}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{l.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
            {error && <div className="error-box">{error}</div>}
            {busy && progress && <Progress text={progress} />}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button type="button" className="btn btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={busy || !username.trim()}>{busy ? "Working…" : "Share"}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function Progress({ text }: { text: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderRadius: "var(--radius-sm)", background: "var(--accent-dim)", marginBottom: 12 }}>
      <div className="spinner" />
      <span style={{ fontSize: 12, color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{text}</span>
    </div>
  );
}
