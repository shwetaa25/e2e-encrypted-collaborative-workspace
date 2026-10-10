import { useState } from "react";
import { workspacesApi, ApiError } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";
import { generateDocumentKey, encryptField, wrapDocumentKey } from "../../crypto";
import type { DecryptedWorkspace } from "./types";

interface Props {
  onClose: () => void;
  onCreated: (ws: DecryptedWorkspace) => void;
}

export function CreateWorkspaceModal({ onClose, onCreated }: Props) {
  const { token, publicKey, userId } = useSessionStore();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !publicKey || !userId) return;
    const trimmed = name.trim();
    if (!trimmed) return;
    setBusy(true); setError(null);
    try {
      // 1. fresh AES workspace key   2. encrypt the name   3. wrap the key for ourselves
      const key = await generateDocumentKey();
      const enc = await encryptField(trimmed, key);
      const wrapped = await wrapDocumentKey(key, publicKey);
      const ws = await workspacesApi.create({
        name_ciphertext: enc.ciphertext, name_iv: enc.iv, wrapped_workspace_key: wrapped,
      }, token);
      onCreated({ id: ws.id, name: trimmed, role: "owner", ownerId: userId, memberCount: 1, key });
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not create workspace");
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
      <div className="modal">
        <h2 className="modal-title">New workspace</h2>
        <p className="modal-sub">
          A workspace groups people and files. Its name is encrypted in your browser — the server stores only ciphertext.
        </p>
        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label className="input-label">Workspace name</label>
            <input className="input" autoFocus placeholder="e.g. Capstone Team" maxLength={80}
              value={name} onChange={(e) => setName(e.target.value)} disabled={busy} required />
          </div>
          <div className="info-box">
            Adding someone to a workspace does <strong>not</strong> show them your files. For every file you upload,
            you choose which members can open it.
          </div>
          {error && <div className="error-box">{error}</div>}
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button type="button" className="btn btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={busy || !name.trim()}>
              {busy ? "Encrypting…" : "Create workspace"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
