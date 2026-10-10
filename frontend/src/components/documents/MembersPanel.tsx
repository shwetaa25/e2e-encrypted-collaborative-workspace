import { useEffect, useState } from "react";
import { documentsApi, type MemberResponse } from "../../api/client";
import { useSessionStore, type DecryptedDoc } from "../../store/sessionStore";
import { generateDocumentKey, encryptDocument, wrapDocumentKey, importPublicKey } from "../../crypto";

interface Props {
  documentId: string;
  doc: DecryptedDoc;
  onShare: () => void;
  onRevoked: (doc: DecryptedDoc) => void;
  /** Bump to force a reload (e.g. after sharing) */
  refreshKey?: number;
  showToast: (msg: string, type?: "success" | "error") => void;
}

export function MembersPanel({ documentId, doc, onShare, onRevoked, refreshKey = 0, showToast }: Props) {
  const { token, userId } = useSessionStore();
  const [members, setMembers] = useState<MemberResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    documentsApi.getMembers(documentId, token)
      .then(setMembers)
      .catch(() => showToast("Failed to load members", "error"))
      .finally(() => setLoading(false));
  }, [documentId, token, refreshKey]);

  const handleRevoke = async (member: MemberResponse) => {
    if (!token || !confirm(`Revoke @${member.username}'s access?\n\nThe document will be re-encrypted with a new key.`)) return;
    setRevoking(member.user_id);
    try {
      // 1. Generate a new AES key
      const newDocKey = await generateDocumentKey();
      // 2. Re-encrypt document content
      const enc = await encryptDocument(doc.title, doc.content, newDocKey);
      // 3. Wrap new key for all remaining members
      const remaining = members.filter((m) => m.user_id !== member.user_id);
      const newWrappedKeys = await Promise.all(
        remaining.map(async (m) => {
          const pubKey = await importPublicKey(m.public_key_spki);
          const wrappedKey = await wrapDocumentKey(newDocKey, pubKey);
          return { user_id: m.user_id, wrapped_key: wrappedKey, access_level: m.access_level };
        })
      );
      // 4. Send atomic revoke payload
      await documentsApi.revokeAccess(documentId, member.user_id, {
        revoked_user_id: member.user_id,
        new_title_ciphertext: enc.titleCiphertext,
        new_title_iv: enc.titleIv,
        new_content_ciphertext: enc.contentCiphertext,
        new_content_iv: enc.contentIv,
        new_wrapped_keys: newWrappedKeys,
      }, token);
      setMembers(remaining);
      onRevoked({ ...doc, documentKey: newDocKey });
      showToast(`@${member.username}'s access revoked — document re-encrypted ✓`);
    } catch {
      showToast("Revoke failed", "error");
    } finally {
      setRevoking(null);
    }
  };

  const handleLevelChange = async (member: MemberResponse, level: string) => {
    if (!token) return;
    const previous = members;
    setMembers((ms) => ms.map((m) => (m.user_id === member.user_id ? { ...m, access_level: level } : m)));
    try {
      await documentsApi.updateAccess(documentId, member.user_id, level, token);
      showToast(`@${member.username} is now ${level}`);
    } catch {
      setMembers(previous);
      showToast("Could not change permission", "error");
    }
  };

  const accessColor: Record<string, string> = {
    owner: "var(--accent)", editor: "var(--encrypted)",
    commenter: "var(--warn)", viewer: "var(--text-muted)",
  };

  if (loading) return <div style={{ display: "flex", justifyContent: "center", padding: 20 }}><div className="spinner" /></div>;

  return (
    <div>
      {doc.accessLevel === "owner" && (
        <button className="btn btn-primary btn-sm" style={{ width: "100%", marginBottom: 10 }} onClick={onShare}>
          + Share with someone
        </button>
      )}

      {members.length === 0 ? (
        <div className="empty-state" style={{ padding: "20px 0" }}><p>No members yet.</p></div>
      ) : (
        members.map((m) => (
          <div key={m.user_id} className="member-card">
            <div className="avatar">{m.username[0].toUpperCase()}</div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>@{m.username}</div>
              {doc.accessLevel === "owner" && m.user_id !== userId && m.access_level !== "owner" ? (
                <select
                  value={m.access_level}
                  onChange={(e) => handleLevelChange(m, e.target.value)}
                  style={{ marginTop: 2, background: "var(--bg-app)", color: accessColor[m.access_level] ?? "var(--text-muted)", border: "1px solid var(--border-mid)", borderRadius: 4, fontSize: 11, padding: "1px 4px" }}
                >
                  <option value="viewer">viewer</option>
                  <option value="commenter">commenter</option>
                  <option value="editor">editor</option>
                </select>
              ) : (
                <div style={{ fontSize: 11, color: accessColor[m.access_level] ?? "var(--text-muted)", marginTop: 1 }}>{m.access_level}</div>
              )}
            </div>
            {doc.accessLevel === "owner" && m.user_id !== userId && (
              <button
                className="btn btn-danger btn-xs"
                onClick={() => handleRevoke(m)}
                disabled={revoking === m.user_id}
              >
                {revoking === m.user_id ? <div className="spinner" /> : "Revoke"}
              </button>
            )}
            {m.user_id === userId && <span style={{ fontSize: 10, color: "var(--text-muted)" }}>you</span>}
          </div>
        ))
      )}

      <div className="info-box" style={{ marginTop: 8 }}>
        Revoking re-encrypts with a new key. The removed user's old key becomes cryptographically useless.
      </div>
    </div>
  );
}
