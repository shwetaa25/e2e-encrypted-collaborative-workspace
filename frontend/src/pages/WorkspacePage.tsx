import { useState, useEffect, useRef, useCallback } from "react";
import { useSessionStore, useDocCache, type DecryptedDoc } from "../store/sessionStore";
import { documentsApi, workspacesApi, syncApi, ApiError } from "../api/client";
import type { DocumentListItem } from "../api/client";
import {
  generateDocumentKey, encryptDocument, decryptDocument,
  wrapDocumentKey, unwrapDocumentKey, deriveSearchKey, buildSearchIndex, decryptField,
} from "../crypto";
import { CreateWorkspaceModal } from "../components/workspaces/CreateWorkspaceModal";
import { WorkspaceMembersModal } from "../components/workspaces/WorkspaceMembersModal";
import type { DecryptedWorkspace } from "../components/workspaces/types";
import { ShareModal } from "../components/documents/ShareModal";
import { MembersPanel } from "../components/documents/MembersPanel";
import { CommentsPanel } from "../components/documents/CommentsPanel";
import { VersionsPanel } from "../components/documents/VersionsPanel";
import { AuditPanel } from "../components/documents/AuditPanel";
import { SearchOverlay } from "../components/search/SearchOverlay";

// ── Toast hook ────────────────────────────────────────────

type ToastType = "success" | "error" | "info";
interface Toast { id: string; msg: string; type: ToastType; }

function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const show = useCallback((msg: string, type: ToastType = "success") => {
    const id = Math.random().toString(36).slice(2);
    setToasts((p) => [...p, { id, msg, type }]);
    setTimeout(() => setToasts((p) => p.filter((t) => t.id !== id)), 3500);
  }, []);
  return { toasts, show };
}

// ── Panel tabs ────────────────────────────────────────────

type PanelTab = "members" | "comments" | "versions" | "audit";
const PANEL_TABS: { id: PanelTab; label: string }[] = [
  { id: "members", label: "Members" },
  { id: "comments", label: "Comments" },
  { id: "versions", label: "Versions" },
  { id: "audit", label: "Audit" },
];

// ── Main component ────────────────────────────────────────

export function WorkspacePage() {
  const { token, email, username, publicKey, privateKey, userId, isAdmin, setView } = useSessionStore();
  const { docs, setDoc, removeDoc } = useDocCache();
  const { toasts, show } = useToast();

  // Workspaces ("personal" = documents that are not in any shared workspace)
  const [workspaces, setWorkspaces] = useState<DecryptedWorkspace[]>([]);
  const [scope, setScope] = useState<string>("personal");
  const [showCreateWs, setShowCreateWs] = useState(false);
  const [showWsMembers, setShowWsMembers] = useState(false);
  const [membersRefresh, setMembersRefresh] = useState(0);
  const currentWs = workspaces.find((w) => w.id === scope) ?? null;

  // Doc list
  const [docList, setDocList] = useState<DocumentListItem[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [activeId, setActiveId] = useState<string | null>(null);

  // Editor
  const [editorTitle, setEditorTitle] = useState("");
  const [editorContent, setEditorContent] = useState("");
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const saveTimer = useRef<ReturnType<typeof setTimeout>>();

  // Panels
  const [showPanel, setShowPanel] = useState(false);
  const [panelTab, setPanelTab] = useState<PanelTab>("members");

  // Modals & overlays
  const [showShare, setShowShare] = useState(false);
  const [showSearch, setShowSearch] = useState(false);

  // ── Load workspaces (names + keys are decrypted in the browser) ──

  const loadWorkspaces = useCallback(async (): Promise<DecryptedWorkspace[]> => {
    if (!token || !privateKey) return [];
    const list = await workspacesApi.list(token);
    const decrypted: DecryptedWorkspace[] = [];
    for (const w of list) {
      try {
        const key = await unwrapDocumentKey(w.wrapped_workspace_key, privateKey);
        const name = await decryptField(w.name_ciphertext, w.name_iv, key);
        decrypted.push({ id: w.id, name, role: w.role, ownerId: w.owner_id, memberCount: w.member_count, key });
      } catch { /* skip a workspace we cannot decrypt */ }
    }
    setWorkspaces(decrypted);
    return decrypted;
  }, [token, privateKey]);

  useEffect(() => {
    loadWorkspaces().catch(() => show("Failed to load workspaces", "error"));
  }, [loadWorkspaces]);

  // ── Load document list for the selected workspace ───────

  useEffect(() => {
    if (!token) return;
    setLoadingList(true);
    documentsApi.list(token, scope)
      .then(setDocList)
      .catch(() => show("Failed to load documents", "error"))
      .finally(() => setLoadingList(false));
  }, [token, scope]);

  const handleScopeChange = (next: string) => {
    if (next === scope) return;
    if (isDirty && !confirm("You have unsaved changes. Switch anyway?")) return;
    setScope(next);
    setActiveId(null);
    setEditorTitle(""); setEditorContent(""); setIsDirty(false);
    setShowPanel(false);
  };

  // ── Live sync: files shared with you appear without a refresh ──
  // Polls a tiny fingerprint endpoint (IDs only — no titles or ciphertext).
  // When something changes for this user we silently reload the lists.

  const scopeRef = useRef(scope);
  const activeIdRef = useRef(activeId);
  const selfCreated = useRef<Set<string>>(new Set());
  const known = useRef<{ docFp: string; wsFp: string; docIds: Set<string>; wsIds: Set<string> } | null>(null);
  useEffect(() => { scopeRef.current = scope; }, [scope]);
  useEffect(() => { activeIdRef.current = activeId; }, [activeId]);

  useEffect(() => {
    if (!token) return;
    let stopped = false;
    let busy = false;
    known.current = null;

    const tick = async () => {
      if (stopped || busy || document.hidden) return;
      busy = true;
      try {
        const st = await syncApi.poll(token);
        const prev = known.current;
        known.current = {
          docFp: st.documents_fp, wsFp: st.workspaces_fp,
          docIds: new Set(st.document_ids), wsIds: new Set(st.workspace_ids),
        };
        if (!prev) return;                                   // first poll = baseline

        if (prev.wsFp !== st.workspaces_fp) {
          const added = st.workspace_ids.filter((id) => !prev.wsIds.has(id));
          await loadWorkspaces().catch(() => {});
          if (added.length) show(`You were added to ${added.length === 1 ? "a new workspace" : `${added.length} new workspaces`} 👥`);
          if (scopeRef.current !== "personal" && !st.workspace_ids.includes(scopeRef.current)) {
            setScope("personal"); setActiveId(null);
            setEditorTitle(""); setEditorContent(""); setIsDirty(false); setShowPanel(false);
            show("You no longer have access to that workspace", "error");
          }
        }

        if (prev.docFp !== st.documents_fp) {
          const fresh = st.document_ids.filter((id) => !prev.docIds.has(id) && !selfCreated.current.has(id));
          const list = await documentsApi.list(token, scopeRef.current);
          if (stopped) return;
          setDocList(list);
          // keep cached permissions in sync (e.g. viewer → editor)
          const cache = useDocCache.getState();
          for (const item of list) {
            const c = cache.docs[item.id];
            if (c && c.accessLevel !== item.access_level) cache.setDoc({ ...c, accessLevel: item.access_level });
          }
          if (fresh.length) {
            const inThisView = list.filter((d) => fresh.includes(d.id)).length;
            show(fresh.length === 1
              ? "A document was shared with you 📥"
              : `${fresh.length} documents were shared with you 📥`);
            if (inThisView === 0 && fresh.length) { /* new files live in another workspace; the toast is enough */ }
          }
          const open = activeIdRef.current;
          if (open && !st.document_ids.includes(open)) {
            removeDoc(open);
            setActiveId(null); setEditorTitle(""); setEditorContent(""); setIsDirty(false); setShowPanel(false);
            show("Your access to the open document was removed", "error");
          }
        }
      } catch (err) {
        // Account deleted by an admin (or token expired): sign out cleanly
        if (err instanceof ApiError && err.status === 401) {
          stopped = true;
          alert("Your session has ended or your account was removed.");
          useSessionStore.getState().clearSession();
          useDocCache.getState().clearAll();
        }
        /* otherwise offline — try again next tick */
      }
      finally { busy = false; }
    };

    tick();
    const id = setInterval(tick, 3000);
    const wake = () => { if (!document.hidden) tick(); };
    document.addEventListener("visibilitychange", wake);
    window.addEventListener("focus", wake);
    return () => {
      stopped = true; clearInterval(id);
      document.removeEventListener("visibilitychange", wake);
      window.removeEventListener("focus", wake);
    };
  }, [token, loadWorkspaces]);

  // ── Keyboard shortcut: Cmd/Ctrl+K → search ─────────────

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setShowSearch(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // ── Saving ─────────────────────────────────────────────
  // Explicit Save button / Ctrl+S, plus an optional auto-save toggle.

  const [autoSave, setAutoSave] = useState<boolean>(() => {
    try { return localStorage.getItem("autosave") === "1"; } catch { return false; }
  });
  const toggleAutoSave = (on: boolean) => {
    setAutoSave(on);
    try { localStorage.setItem("autosave", on ? "1" : "0"); } catch { /* ignore */ }
  };

  const saveNow = useCallback(async (silent = false) => {
    if (!isDirty || !activeId || !token || isSaving) return;
    const cached = docs[activeId];
    if (!cached) return;
    if (cached.accessLevel !== "owner" && cached.accessLevel !== "editor") return;
    setIsSaving(true);
    try {
      const enc = await encryptDocument(editorTitle, editorContent, cached.documentKey);
      const searchKey = await deriveSearchKey(cached.documentKey);
      const index = await buildSearchIndex(editorContent, activeId, searchKey);
      const updated = await documentsApi.update(activeId, {
        title_ciphertext: enc.titleCiphertext,
        title_iv: enc.titleIv,
        content_ciphertext: enc.contentCiphertext,
        content_iv: enc.contentIv,
        search_index: index.map((e) => ({ keyword_token: e.keywordToken })),
      }, token);
      setDoc({
        ...cached,
        title: editorTitle,
        content: editorContent,
        currentVersion: updated.current_version,
        updatedAt: updated.updated_at,
      });
      setDocList((p) => p.map((d) => d.id === activeId
        ? { ...d, current_version: updated.current_version, updated_at: updated.updated_at }
        : d));
      setIsDirty(false);
      if (!silent) show("Saved 🔒 (encrypted in your browser)");
    } catch { show("Save failed — your changes are still in the editor", "error"); }
    finally { setIsSaving(false); }
  }, [isDirty, activeId, token, isSaving, docs, editorTitle, editorContent]);

  // Optional auto-save: 2 s after typing stops
  useEffect(() => {
    if (!autoSave || !isDirty || !activeId) return;
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => { saveNow(true); }, 2000);
    return () => clearTimeout(saveTimer.current);
  }, [autoSave, isDirty, editorTitle, editorContent, activeId, saveNow]);

  // Ctrl/Cmd+S
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        saveNow();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [saveNow]);

  // Warn before closing the tab with unsaved changes
  useEffect(() => {
    if (!isDirty) return;
    const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ""; };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [isDirty]);

  // ── Open a document ────────────────────────────────────

  const handleOpenDoc = useCallback(async (docId: string) => {
    if (activeId === docId) return;
    setActiveId(docId);

    const cached = docs[docId];
    if (cached) {
      setEditorTitle(cached.title);
      setEditorContent(cached.content);
      setIsDirty(false);
      return;
    }
    if (!token || !privateKey) return;
    try {
      const doc = await documentsApi.get(docId, token);
      const docKey = await unwrapDocumentKey(doc.wrapped_key, privateKey);
      const dec = await decryptDocument(
        { titleCiphertext: doc.title_ciphertext, titleIv: doc.title_iv, contentCiphertext: doc.content_ciphertext, contentIv: doc.content_iv },
        docKey, docId
      );
      setDoc({
        id: docId, title: dec.title, content: dec.content,
        documentKey: docKey, accessLevel: doc.access_level,
        currentVersion: doc.current_version, updatedAt: doc.updated_at,
      });
      setEditorTitle(dec.title);
      setEditorContent(dec.content);
      setIsDirty(false);
    } catch { show("Failed to open document", "error"); }
  }, [activeId, docs, token, privateKey, setDoc]);

  // ── Create document ────────────────────────────────────

  const handleNew = async () => {
    if (!token || !publicKey) return;
    try {
      const docKey = await generateDocumentKey();
      const enc = await encryptDocument("Untitled document", "", docKey);
      const wrappedKey = await wrapDocumentKey(docKey, publicKey);
      const doc = await documentsApi.create({
        title_ciphertext: enc.titleCiphertext, title_iv: enc.titleIv,
        content_ciphertext: enc.contentCiphertext, content_iv: enc.contentIv,
        wrapped_key_for_owner: wrappedKey, search_index: [],
        workspace_id: currentWs ? currentWs.id : null,
      }, token);
      const newItem: DocumentListItem = {
        id: doc.id, owner_id: doc.owner_id, workspace_id: doc.workspace_id ?? null,
        title_ciphertext: doc.title_ciphertext, title_iv: doc.title_iv,
        current_version: 1, created_at: doc.created_at,
        updated_at: doc.updated_at, wrapped_key: doc.wrapped_key,
        access_level: "owner",
      };
      selfCreated.current.add(doc.id);
      setDocList((p) => [newItem, ...p]);
      setDoc({ id: doc.id, title: "Untitled document", content: "", documentKey: docKey, accessLevel: "owner", currentVersion: 1, updatedAt: doc.updated_at });
      setActiveId(doc.id);
      setEditorTitle("Untitled document");
      setEditorContent("");
      setIsDirty(false);
      show(currentWs ? `New document created in ${currentWs.name} 🔒` : "New document created 🔒");
    } catch { show("Failed to create document", "error"); }
  };

  // ── Delete document ────────────────────────────────────

  const handleDelete = async () => {
    if (!activeId || !token || !confirm("Delete this document? This cannot be undone.")) return;
    try {
      await documentsApi.delete(activeId, token);
      removeDoc(activeId);
      setDocList((p) => p.filter((d) => d.id !== activeId));
      setActiveId(null);
      setEditorTitle("");
      setEditorContent("");
      show("Document deleted");
    } catch { show("Delete failed", "error"); }
  };

  // ── Logout ─────────────────────────────────────────────

  const handleLogout = () => {
    useSessionStore.getState().clearSession();
    useDocCache.getState().clearAll();
  };

  const activeDoc = activeId ? docs[activeId] : null;
  const isOwner = activeDoc?.accessLevel === "owner";
  const isEditable = activeDoc?.accessLevel === "editor" || isOwner;

  return (
    <div className="app-shell">

      {/* ── Top bar ────────────────────────────────────── */}
      <header className="top-bar">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <span style={{ fontWeight: 600, fontSize: 14, marginRight: 4 }}>Encrypted Workspace</span>
        <span className="enc-status">● AES-256-GCM · RSA-2048 · Zero-knowledge</span>

        {/* Search button */}
        <button
          className="btn btn-ghost btn-sm"
          style={{ marginLeft: 8 }}
          onClick={() => setShowSearch(true)}
          title="Search (Ctrl+K)"
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          Search
          <kbd style={{ fontSize: 10, color: "var(--text-muted)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 3, padding: "0 3px", marginLeft: 2 }}>⌘K</kbd>
        </button>

        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
          {activeDoc && isEditable && (
            <>
              <label style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--text-muted)", cursor: "pointer" }}
                title="Save automatically 2 seconds after you stop typing">
                <input type="checkbox" checked={autoSave} onChange={(e) => toggleAutoSave(e.target.checked)} style={{ accentColor: "var(--accent)" }} />
                Auto-save
              </label>
              <span style={{ fontSize: 12, color: isSaving ? "var(--text-muted)" : isDirty ? "var(--warn)" : "var(--encrypted)" }}>
                {isSaving ? "Encrypting & saving…" : isDirty ? "● Unsaved changes" : "✓ All changes saved"}
              </span>
              <button className="btn btn-primary btn-sm" onClick={() => saveNow()} disabled={!isDirty || isSaving}
                title="Save (Ctrl+S)">
                {isSaving ? <div className="spinner" /> : "💾"} Save
              </button>
            </>
          )}
          {isAdmin && (
            <button className="btn btn-ghost btn-sm" onClick={() => setView("admin")} title="Open the Admin Console">
              🛡 Admin Console
            </button>
          )}
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{username ? `@${username}` : email}</span>
          <button className="btn btn-ghost btn-sm" onClick={handleLogout}>Sign out</button>
        </div>
      </header>

      {/* ── Sidebar ────────────────────────────────────── */}
      <aside className="sidebar">
        <div style={{ padding: "10px 8px 0" }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: ".05em", color: "var(--text-muted)", padding: "0 4px 4px" }}>WORKSPACE</div>
          <select className="input" value={scope} onChange={(e) => handleScopeChange(e.target.value)}>
            <option value="personal">👤 Personal</option>
            {workspaces.map((w) => (
              <option key={w.id} value={w.id}>👥 {w.name}</option>
            ))}
          </select>
          <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
            <button className="btn btn-ghost btn-sm" style={{ flex: 1 }} onClick={() => setShowCreateWs(true)}>+ Workspace</button>
            {currentWs && (
              <button className="btn btn-ghost btn-sm" style={{ flex: 1 }} onClick={() => setShowWsMembers(true)}>
                👥 {currentWs.memberCount}
              </button>
            )}
            {currentWs && currentWs.role === "owner" && (
              <button className="btn btn-danger btn-sm" title="Delete this workspace and all files in it"
                onClick={async () => {
                  if (!token) return;
                  if (!confirm(`Delete workspace “${currentWs.name}” and ALL files inside it?\n\nEvery member loses access. This cannot be undone.`)) return;
                  try {
                    await workspacesApi.remove(currentWs.id, token);
                    setWorkspaces((p) => p.filter((w) => w.id !== currentWs.id));
                    setScope("personal"); setActiveId(null);
                    setEditorTitle(""); setEditorContent(""); setIsDirty(false); setShowPanel(false);
                    show("Workspace deleted");
                  } catch { show("Could not delete workspace", "error"); }
                }}>
                🗑
              </button>
            )}
          </div>
        </div>
        <div className="divider" />
        <div style={{ padding: "4px 8px 4px" }}>
          <button className="btn btn-primary" style={{ width: "100%" }} onClick={handleNew}>
            + New document
          </button>
        </div>
        <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: ".05em", color: "var(--text-muted)", padding: "6px 12px 4px" }}>
          {currentWs ? `FILES IN ${currentWs.name.toUpperCase()}` : "MY DOCUMENTS"}
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "0 8px 8px" }}>
          {loadingList ? (
            <div style={{ display: "flex", justifyContent: "center", padding: 20 }}><div className="spinner" /></div>
          ) : docList.length === 0 ? (
            <div className="empty-state" style={{ padding: "24px 12px" }}>
              <p>{currentWs
                ? "No files here that you have access to. Upload one, or ask a teammate to share theirs with you."
                : "No documents yet. Create one to get started."}</p>
            </div>
          ) : (
            docList.map((doc) => {
              const cached = docs[doc.id];
              const isActive = doc.id === activeId;
              return (
                <div
                  key={doc.id}
                  className={`doc-list-item ${isActive ? "active" : ""}`}
                  onClick={() => handleOpenDoc(doc.id)}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={isActive ? "var(--accent)" : "var(--text-muted)"} strokeWidth="1.8" style={{ flexShrink: 0, marginTop: 2 }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    {cached ? (
                      <div style={{ fontSize: 13, fontWeight: 500, color: isActive ? "var(--accent)" : "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {cached.title || "Untitled"}
                      </div>
                    ) : (
                      <>
                        <div className="cipher-preview">{doc.title_ciphertext.slice(0, 20)}…</div>
                        <div style={{ fontSize: 10, color: "var(--encrypted)", marginTop: 1 }}>🔒 encrypted</div>
                      </>
                    )}
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                      v{doc.current_version} · {new Date(doc.updated_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
        <div style={{ padding: "8px 12px", borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.8 }}>
          <div>🔒 Server sees only ciphertext</div>
          <div>🔑 Keys in browser memory only</div>
        </div>
      </aside>

      {/* ── Main area (editor + right panel) ──────────── */}
      <main className="main-area">
        {activeDoc ? (
          <>
            {/* Editor */}
            <div className="editor-wrap">
              <div className="editor-toolbar">
                <span className="enc-badge">🔒 AES-256-GCM</span>
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>v{activeDoc.currentVersion}</span>
                <span className="pill pill-blue" style={{ fontSize: 10 }}>{activeDoc.accessLevel}</span>

                <div style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center" }}>
                  {/* Share button */}
                  {isOwner && (
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => { setShowShare(true); }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.59 13.51 15.42 17.49M15.41 6.51 8.59 10.49"/></svg>
                      Share
                    </button>
                  )}

                  {/* Toggle details panel */}
                  <button
                    className={`btn btn-sm ${showPanel ? "btn-primary" : "btn-ghost"}`}
                    onClick={() => setShowPanel((v) => !v)}
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M15 3v18"/></svg>
                    {showPanel ? "Hide" : "Details"}
                  </button>

                  {isOwner && (
                    <button className="btn btn-danger btn-sm" onClick={handleDelete}>
                      Delete
                    </button>
                  )}
                </div>
              </div>

              <input
                className="editor-title-input"
                placeholder="Document title"
                value={editorTitle}
                onChange={(e) => { setEditorTitle(e.target.value); setIsDirty(true); }}
                readOnly={!isEditable}
              />

              <div className="editor-content">
                <textarea
                  className="editor-textarea"
                  placeholder={isEditable
                    ? "Start writing… content is encrypted before it leaves your browser."
                    : "You have read-only access to this document."}
                  value={editorContent}
                  onChange={(e) => { setEditorContent(e.target.value); setIsDirty(true); }}
                  readOnly={!isEditable}
                />
              </div>

              <div className="editor-footer">
                <span>Encryption: <strong style={{ color: "var(--encrypted)" }}>active</strong></span>
                <span>·</span>
                <span>Access: <strong style={{ color: "var(--text-secondary)" }}>{activeDoc.accessLevel}</strong></span>
                <span>·</span>
                <span>{editorContent.split(/\s+/).filter(Boolean).length} words</span>
                <span>·</span>
                <span>{editorContent.length} chars</span>
              </div>
            </div>

            {/* Right panel */}
            {showPanel && (
              <div className="right-panel">
                <div className="panel-tabs">
                  {PANEL_TABS.map((tab) => (
                    <button
                      key={tab.id}
                      className={`panel-tab ${panelTab === tab.id ? "active" : ""}`}
                      onClick={() => setPanelTab(tab.id)}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
                <div className="panel-body">
                  {panelTab === "members" && (
                    <MembersPanel
                      documentId={activeId!}
                      doc={activeDoc}
                      onShare={() => setShowShare(true)}
                      refreshKey={membersRefresh}
                      onRevoked={(updatedDoc) => setDoc(updatedDoc)}
                      showToast={show}
                    />
                  )}
                  {panelTab === "comments" && (
                    <CommentsPanel
                      documentId={activeId!}
                      documentKey={activeDoc.documentKey}
                      showToast={show}
                    />
                  )}
                  {panelTab === "versions" && (
                    <VersionsPanel
                      documentId={activeId!}
                      currentVersion={activeDoc.currentVersion}
                      showToast={show}
                    />
                  )}
                  {panelTab === "audit" && (
                    <AuditPanel
                      documentId={activeId!}
                      showToast={show}
                    />
                  )}
                </div>
              </div>
            )}
          </>
        ) : (
          /* Empty state */
          <div className="empty-state" style={{ flex: 1 }}>
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.4" style={{ opacity: .35 }}>
              <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: "var(--text-secondary)" }}>
              Select or create a document
            </h2>
            <p>All content is AES-256-GCM encrypted in your browser before reaching the server. Keys never leave your device.</p>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={handleNew}>+ New document</button>
              <button className="btn btn-ghost" onClick={() => setShowSearch(true)}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                Search
              </button>
            </div>
          </div>
        )}
      </main>

      {/* ── Modals & overlays ──────────────────────────── */}

      {showShare && activeDoc && activeId && (
        <ShareModal
          documentId={activeId}
          documentKey={activeDoc.documentKey}
          workspaceId={currentWs ? currentWs.id : null}
          onClose={() => setShowShare(false)}
          onShared={(summary) => {
            show(`${summary} 🔒`);
            setShowShare(false);
            setMembersRefresh((n) => n + 1);   // reload the Members tab
          }}
        />
      )}

      {showCreateWs && (
        <CreateWorkspaceModal
          onClose={() => setShowCreateWs(false)}
          onCreated={(ws) => {
            setWorkspaces((p) => [...p, ws]);
            setShowCreateWs(false);
            handleScopeChange(ws.id);
            show(`Workspace “${ws.name}” created 🔒`);
          }}
        />
      )}

      {showWsMembers && currentWs && (
        <WorkspaceMembersModal
          workspace={currentWs}
          onClose={() => setShowWsMembers(false)}
          showToast={show}
          onMembersChanged={(count) =>
            setWorkspaces((p) => p.map((w) => (w.id === currentWs.id ? { ...w, memberCount: count } : w)))}
          onLeftOrDeleted={() => {
            setShowWsMembers(false);
            setWorkspaces((p) => p.filter((w) => w.id !== currentWs.id));
            setScope("personal"); setActiveId(null);
            show("You left the workspace");
          }}
          onDeleteWorkspace={async () => {
            if (!token) return;
            try {
              await workspacesApi.remove(currentWs.id, token);
              setShowWsMembers(false);
              setWorkspaces((p) => p.filter((w) => w.id !== currentWs.id));
              setScope("personal"); setActiveId(null);
              show("Workspace deleted");
            } catch { show("Could not delete workspace", "error"); }
          }}
        />
      )}

      {showSearch && (
        <SearchOverlay
          onClose={() => setShowSearch(false)}
          onOpenDoc={(docId) => handleOpenDoc(docId)}
        />
      )}

      {/* ── Toasts ─────────────────────────────────────── */}
      <div className="toast-container">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="toast"
            style={{ borderColor: t.type === "error" ? "rgba(239,68,68,0.3)" : t.type === "info" ? "rgba(79,142,247,0.3)" : "rgba(34,197,94,0.3)" }}
          >
            <span style={{ color: t.type === "error" ? "var(--danger)" : t.type === "info" ? "var(--accent)" : "var(--encrypted)", fontWeight: 700, fontSize: 15 }}>
              {t.type === "error" ? "✕" : "✓"}
            </span>
            <span style={{ fontSize: 13 }}>{t.msg}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
