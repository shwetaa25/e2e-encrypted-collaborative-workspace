import { useEffect, useRef, useState } from "react";
import { documentsApi } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";
import { encryptComment, decryptComment } from "../../crypto";

interface DecryptedComment {
  id: string;
  text: string;
  createdAt: string;
}

interface Props {
  documentId: string;
  documentKey: CryptoKey;
  showToast: (msg: string, type?: "success" | "error") => void;
}

export function CommentsPanel({ documentId, documentKey, showToast }: Props) {
  const { token } = useSessionStore();
  const [comments, setComments] = useState<DecryptedComment[]>([]);
  const [loading, setLoading] = useState(true);
  const [newText, setNewText] = useState("");
  const [posting, setPosting] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    documentsApi.getComments(documentId, token)
      .then(async (raw) => {
        const decrypted = await Promise.all(
          raw.filter((c) => !c.is_deleted).map(async (c) => ({
            id: c.id,
            text: await decryptComment(c.content_ciphertext, c.content_iv, documentKey).catch(() => "[could not decrypt]"),
            createdAt: c.created_at,
          }))
        );
        setComments(decrypted);
      })
      .catch(() => showToast("Failed to load comments", "error"))
      .finally(() => setLoading(false));
  }, [documentId, token]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [comments]);

  const handlePost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !newText.trim()) return;
    setPosting(true);
    try {
      const { ciphertext, iv } = await encryptComment(newText.trim(), documentKey);
      await documentsApi.addComment(documentId, { content_ciphertext: ciphertext, content_iv: iv }, token);
      setComments((p) => [...p, { id: Date.now().toString(), text: newText.trim(), createdAt: new Date().toISOString() }]);
      setNewText("");
    } catch {
      showToast("Failed to post comment", "error");
    } finally {
      setPosting(false);
    }
  };

  if (loading) return <div style={{ display: "flex", justifyContent: "center", padding: 20 }}><div className="spinner" /></div>;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div className="info-box">🔒 Comments are AES-encrypted before sending</div>

      <div style={{ flex: 1, overflowY: "auto", marginBottom: 8 }}>
        {comments.length === 0 ? (
          <div className="empty-state" style={{ padding: "20px 0" }}><p>No comments yet. Add one below.</p></div>
        ) : (
          comments.map((c) => (
            <div key={c.id} className="comment-card">
              <div className="comment-text">{c.text}</div>
              <div className="comment-meta">{new Date(c.createdAt).toLocaleString()}</div>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>

      <form onSubmit={handlePost} style={{ flexShrink: 0, display: "flex", flexDirection: "column", gap: 6 }}>
        <textarea
          className="input"
          placeholder="Add an encrypted comment…"
          value={newText}
          onChange={(e) => setNewText(e.target.value)}
          rows={2}
          style={{ resize: "none", fontFamily: "var(--font-ui)" }}
          onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) handlePost(e as any); }}
        />
        <button type="submit" className="btn btn-primary btn-sm" disabled={posting || !newText.trim()}>
          {posting ? <><div className="spinner" style={{ borderTopColor: "white" }} />Encrypting…</> : "Post comment"}
        </button>
      </form>
    </div>
  );
}
