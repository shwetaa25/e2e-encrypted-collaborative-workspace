import { useEffect, useState } from "react";
import { documentsApi, type VersionResponse } from "../../api/client";
import { useSessionStore } from "../../store/sessionStore";

interface Props {
  documentId: string;
  currentVersion: number;
  showToast: (msg: string, type?: "success" | "error") => void;
}

export function VersionsPanel({ documentId, currentVersion, showToast }: Props) {
  const { token } = useSessionStore();
  const [versions, setVersions] = useState<VersionResponse[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;
    setLoading(true);
    documentsApi.getVersions(documentId, token)
      .then(setVersions)
      .catch(() => showToast("Failed to load versions", "error"))
      .finally(() => setLoading(false));
  }, [documentId, token]);

  if (loading) return <div style={{ display: "flex", justifyContent: "center", padding: 20 }}><div className="spinner" /></div>;

  return (
    <div>
      <div className="info-box">🔒 All versions stored as encrypted snapshots</div>

      {versions.length === 0 ? (
        <div className="empty-state" style={{ padding: "20px 0" }}><p>No versions yet.</p></div>
      ) : (
        versions.map((v) => (
          <div key={v.id} className="version-card">
            <div>
              <div style={{ fontSize: 13, fontWeight: 500, color: "var(--text-primary)" }}>
                Version {v.version_number}
                {v.version_number === currentVersion && (
                  <span className="pill pill-green" style={{ marginLeft: 6, fontSize: 10 }}>current</span>
                )}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                {new Date(v.created_at).toLocaleString()}
              </div>
              {/* Show ciphertext preview — proof it's encrypted */}
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", marginTop: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 180 }}>
                {v.content_ciphertext.slice(0, 28)}…
              </div>
            </div>
            <span className="pill pill-blue" style={{ fontSize: 10 }}>
              {v.version_number === currentVersion ? "latest" : "archived"}
            </span>
          </div>
        ))
      )}

      <div style={{ marginTop: 8, padding: "8px 10px", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>
        The ciphertext preview above is proof the server stores only encrypted data — no plaintext visible.
      </div>
    </div>
  );
}
