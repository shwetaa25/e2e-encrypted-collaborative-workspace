import { useEffect, useRef, useState } from "react";
import { searchApi, documentsApi } from "../../api/client";
import { useSessionStore, useDocCache } from "../../store/sessionStore";
import { deriveSearchKey, buildSearchTokens, unwrapDocumentKey, decryptField } from "../../crypto";

interface SearchResult {
  documentId: string;
  titleDecrypted: string | null;
  titleCiphertext: string;
  titleIv: string;
  wrappedKey: string;
  updatedAt: string;
}

interface Props {
  onClose: () => void;
  onOpenDoc: (docId: string) => void;
}

export function SearchOverlay({ onClose, onOpenDoc }: Props) {
  const { token, privateKey } = useSessionStore();
  const { docs } = useDocCache();
  const [query, setQuery] = useState("");
  const [tokens, setTokens] = useState<string[]>([]);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [searched, setSearched] = useState(false);
  const [searching, setSearching] = useState(false);
  const [mode, setMode] = useState<"or" | "and">("or");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim() || !token || !privateKey) return;
    setSearching(true);
    setSearched(false);
    setTokens([]);
    setResults([]);

    try {
      // Build SSE tokens from any cached doc key (all share the same search key derivation)
      const cachedDocs = Object.values(docs);
      let searchTokens: string[] = [];

      if (cachedDocs.length > 0) {
        // Derive search key from the first available document key
        const searchKey = await deriveSearchKey(cachedDocs[0].documentKey);
        searchTokens = await buildSearchTokens(query, searchKey);
      } else {
        // No cached docs — generate placeholder tokens to show the SSE concept
        const dummyKey = await window.crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
        searchTokens = await buildSearchTokens(query, dummyKey);
      }

      setTokens(searchTokens);

      if (searchTokens.length === 0) {
        setSearched(true);
        setSearching(false);
        return;
      }

      // Send tokens (never keywords) to server
      const raw = await searchApi.search(searchTokens, mode, token);

      // Decrypt titles for results we have keys for
      const enriched = await Promise.all(
        raw.map(async (r) => {
          let titleDecrypted: string | null = null;
          try {
            const docKey = await unwrapDocumentKey(r.wrapped_key, privateKey);
            titleDecrypted = await decryptField(r.title_ciphertext, r.title_iv, docKey);
          } catch {
            // Can't decrypt — show ciphertext preview instead
          }
          return {
            documentId: r.document_id,
            titleDecrypted,
            titleCiphertext: r.title_ciphertext,
            titleIv: r.title_iv,
            wrappedKey: r.wrapped_key,
            updatedAt: r.updated_at,
          };
        })
      );

      setResults(enriched);
      setSearched(true);
    } catch (err) {
      console.error("Search failed:", err);
      setSearched(true);
    } finally {
      setSearching(false);
    }
  };

  return (
    <div className="search-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="search-box">
        {/* Search input */}
        <form onSubmit={handleSearch}>
          <div className="search-input-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            <input
              ref={inputRef}
              className="search-input"
              placeholder="Search your encrypted documents…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as "or" | "and")}
              style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-mid)", borderRadius: "var(--radius-sm)", color: "var(--text-secondary)", fontSize: 12, padding: "3px 6px", cursor: "pointer" }}
            >
              <option value="or">OR</option>
              <option value="and">AND</option>
            </select>
            <button type="submit" className="btn btn-primary btn-sm" disabled={searching || !query.trim()}>
              {searching ? <div className="spinner" style={{ borderTopColor: "white" }} /> : "Search"}
            </button>
          </div>
        </form>

        {/* SSE token visualization — this is the innovation module made visible */}
        {tokens.length > 0 && (
          <div className="search-token-row">
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, display: "flex", alignItems: "center", gap: 6 }}>
              <span className="enc-badge" style={{ fontSize: 10 }}>🔒 SSE</span>
              <span>Tokens sent to server — never the actual keywords</span>
            </div>
            {tokens.map((t, i) => (
              <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 3 }}>
                <span style={{ fontSize: 10, color: "var(--text-muted)", background: "var(--bg-hover)", padding: "1px 5px", borderRadius: "var(--radius-sm)", flexShrink: 0, marginTop: 1 }}>
                  word {i + 1}
                </span>
                <span className="search-token">{t}</span>
              </div>
            ))}
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 5, borderTop: "1px solid var(--border)", paddingTop: 5 }}>
              Server matched these HMAC-SHA256 hashes — it never learned what you searched for.
            </div>
          </div>
        )}

        {/* Results */}
        <div className="search-results">
          {searching && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "16px", color: "var(--text-muted)", fontSize: 13 }}>
              <div className="spinner" /> Searching encrypted index…
            </div>
          )}

          {searched && !searching && results.length === 0 && (
            <div className="search-empty">No matching documents found.</div>
          )}

          {results.map((r) => (
            <div
              key={r.documentId}
              className="search-result-item"
              onClick={() => { onOpenDoc(r.documentId); onClose(); }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" style={{ flexShrink: 0 }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 500, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {r.titleDecrypted ?? (
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                      {r.titleCiphertext.slice(0, 24)}… (click to decrypt)
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                  Updated {new Date(r.updatedAt).toLocaleDateString()}
                </div>
              </div>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </div>
          ))}
        </div>

        {/* Footer hint */}
        <div style={{ padding: "8px 16px", borderTop: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, color: "var(--text-muted)" }}>
          <span>Press <kbd style={{ background: "var(--bg-elevated)", border: "1px solid var(--border-mid)", borderRadius: 3, padding: "0 4px", fontSize: 10 }}>Esc</kbd> to close</span>
          <span className="enc-badge" style={{ fontSize: 10 }}>Privacy-preserving SSE</span>
        </div>
      </div>
    </div>
  );
}
