const API_BASE = (import.meta as any).env?.VITE_API_URL ?? "http://localhost:8080";

export class ApiError extends Error {
  constructor(public status: number, public detail: string) {
    super(detail);
  }
}

// FastAPI returns either a string or a list of {msg} objects (validation errors)
function formatDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (typeof d?.msg === "string" ? d.msg.replace(/^Value error,\s*/, "") : "Invalid input"))
      .join(". ");
  }
  return "Request failed";
}

async function request<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(options.headers as Record<string, string>) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}/api/v1${path}`, { ...options, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new ApiError(res.status, formatDetail(body.detail));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export interface TokenResponse {
  access_token: string; token_type: string; expires_in: number;
  user_id: string; public_key_spki: string; wrapped_private_key: string;
  wrap_iv: string; pbkdf2_salt: string; is_admin: boolean; username: string | null;
}

export interface DocumentListItem {
  id: string; owner_id: string; workspace_id: string | null;
  title_ciphertext: string; title_iv: string;
  current_version: number; created_at: string; updated_at: string;
  wrapped_key: string; access_level: string;
}

export interface DocumentResponse extends DocumentListItem {
  content_ciphertext: string; content_iv: string;
}

export interface MemberResponse {
  user_id: string; username: string; access_level: string;
  granted_at: string; public_key_spki: string;
}

export interface CommentResponse {
  id: string; document_id: string; user_id: string;
  parent_comment_id: string | null; content_ciphertext: string;
  content_iv: string; created_at: string; updated_at: string; is_deleted: boolean;
}

export interface VersionResponse {
  id: string; document_id: string; version_number: number;
  content_ciphertext: string; content_iv: string;
  created_by: string; created_at: string;
  note_ciphertext: string | null; note_iv: string | null;
}

export interface AuditEntry {
  id: string; action_type: string; actor_pseudonym: string;
  document_id: string | null; metadata: Record<string, unknown> | null;
  entry_hash: string; prev_entry_hash: string | null; created_at_hour: string;
}

export interface SearchResultItem {
  document_id: string; title_ciphertext: string; title_iv: string;
  wrapped_key: string; updated_at: string;
}

export interface UserPublicKey {
  user_id: string; username: string; public_key_spki: string;
}

export interface WorkspaceResponse {
  id: string; owner_id: string; name_ciphertext: string; name_iv: string;
  role: "owner" | "member"; wrapped_workspace_key: string;
  member_count: number; created_at: string;
}

export interface WorkspaceMemberResponse {
  user_id: string; username: string; role: string; added_at: string; public_key_spki: string;
}

// ── Admin Console types ──
export interface NetworkField {
  key: string; kind: string; ok: boolean; size: number; preview: string;
  note?: string; bytes?: number; entropy?: number;
}
export interface NetworkBody { present: boolean; fields: NetworkField[]; raw: string; bytes: number; }
export interface NetworkLogEntry {
  seq: number; ts: string; method: string; path: string; query: string;
  status: number; duration_ms: number; authenticated: boolean;
  request: NetworkBody; response: NetworkBody;
  verdict: "encrypted" | "auth" | "metadata" | "warning";
}
export interface AdminStats {
  users: number; workspaces: number; workspace_memberships: number; documents: number;
  document_keys: number; versions: number; comments: number; search_tokens: number;
  audit_entries: number; ciphertext_chars_stored: number; plaintext_columns_for_content: number;
}
export interface DbView {
  table: string; tables: string[]; columns: string[];
  rows: Record<string, { value: string; length: number }>[];
}
export interface AdminUser {
  id: string; email: string; username: string | null; created_at: string | null; last_seen_at: string | null; is_admin: boolean;
  documents_owned: number; workspaces_owned: number;
}
export interface AdminWorkspace {
  id: string; owner_id: string; owner_username: string; name_ciphertext_preview: string;
  member_count: number; document_count: number; created_at: string | null;
}
export interface AuditVerify { valid: boolean; total_entries: number; broken_at: string | null; message?: string; }

export const authApi = {
  register: (body: {
    email: string; username: string; password: string; public_key_spki: string;
    wrapped_private_key: string; wrap_iv: string; pbkdf2_salt: string;
  }) => request<TokenResponse>("/auth/register", { method: "POST", body: JSON.stringify(body) }),

  login: (email: string, password: string) =>
    request<TokenResponse>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),

  getPublicKey: (userId: string, token: string) =>
    request<UserPublicKey>(`/auth/users/${userId}/public-key`, {}, token),

  getUserByUsername: (username: string, token: string) =>
    request<UserPublicKey>(`/auth/users/by-username?username=${encodeURIComponent(username)}`, {}, token),
};

export const documentsApi = {
  /** scope: a workspace id, "personal" (no workspace), or undefined (everything) */
  list: (token: string, scope?: string) => {
    const q = scope === "personal" ? "?personal=true" : scope ? `?workspace_id=${scope}` : "";
    return request<DocumentListItem[]>(`/documents${q}`, {}, token);
  },
  get: (id: string, token: string) => request<DocumentResponse>(`/documents/${id}`, {}, token),
  create: (body: object, token: string) => request<DocumentResponse>("/documents", { method: "POST", body: JSON.stringify(body) }, token),
  update: (id: string, body: object, token: string) => request<DocumentResponse>(`/documents/${id}`, { method: "PUT", body: JSON.stringify(body) }, token),
  delete: (id: string, token: string) => request<void>(`/documents/${id}`, { method: "DELETE" }, token),
  share: (id: string, body: object, token: string) => request<{ message: string }>(`/documents/${id}/share`, { method: "POST", body: JSON.stringify(body) }, token),
  revokeAccess: (docId: string, userId: string, body: object, token: string) =>
    request<{ message: string }>(`/documents/${docId}/members/${userId}`, { method: "DELETE", body: JSON.stringify(body) }, token),
  updateAccess: (docId: string, userId: string, accessLevel: string, token: string) =>
    request<{ message: string }>(`/documents/${docId}/members/${userId}`,
      { method: "PATCH", body: JSON.stringify({ access_level: accessLevel }) }, token),
  getMembers: (id: string, token: string) => request<MemberResponse[]>(`/documents/${id}/members`, {}, token),
  getVersions: (id: string, token: string) => request<VersionResponse[]>(`/documents/${id}/versions`, {}, token),
  getComments: (id: string, token: string) => request<CommentResponse[]>(`/documents/${id}/comments`, {}, token),
  addComment: (id: string, body: object, token: string) => request<CommentResponse>(`/documents/${id}/comments`, { method: "POST", body: JSON.stringify(body) }, token),
  getAuditLog: (id: string, token: string) => request<AuditEntry[]>(`/documents/${id}/audit`, {}, token),
};

export const searchApi = {
  search: (documentTokens: Record<string, string[]>, mode: "and" | "or", token: string) =>
    request<SearchResultItem[]>("/search", { method: "POST", body: JSON.stringify({ document_tokens: documentTokens, mode }) }, token),
};

export const workspacesApi = {
  list: (token: string) => request<WorkspaceResponse[]>("/workspaces", {}, token),
  create: (body: { name_ciphertext: string; name_iv: string; wrapped_workspace_key: string }, token: string) =>
    request<WorkspaceResponse>("/workspaces", { method: "POST", body: JSON.stringify(body) }, token),
  remove: (id: string, token: string) => request<void>(`/workspaces/${id}`, { method: "DELETE" }, token),
  members: (id: string, token: string) => request<WorkspaceMemberResponse[]>(`/workspaces/${id}/members`, {}, token),
  addMember: (id: string, body: { user_id: string; wrapped_workspace_key: string }, token: string) =>
    request<{ message: string }>(`/workspaces/${id}/members`, { method: "POST", body: JSON.stringify(body) }, token),
  removeMember: (id: string, userId: string, token: string) =>
    request<void>(`/workspaces/${id}/members/${userId}`, { method: "DELETE" }, token),
};

export const adminApi = {
  networkLog: (since: number, token: string) =>
    request<{ enabled: boolean; latest_seq: number; entries: NetworkLogEntry[] }>(
      `/admin/network-log?since=${since}&limit=200`, {}, token),
  clearNetworkLog: (token: string) => request<void>("/admin/network-log", { method: "DELETE" }, token),
  stats: (token: string) => request<AdminStats>("/admin/stats", {}, token),
  dbView: (table: string, token: string) => request<DbView>(`/admin/db-view?table=${table}&limit=8`, {}, token),
  audit: (token: string) => request<AuditEntry[]>("/admin/audit?limit=100", {}, token),
  verifyAudit: (token: string) => request<AuditVerify>("/admin/audit/verify", {}, token),
  users: (token: string) => request<AdminUser[]>("/admin/users", {}, token),
  deleteUser: (id: string, token: string) => request<void>(`/admin/users/${id}`, { method: "DELETE" }, token),
  workspaces: (token: string) => request<AdminWorkspace[]>("/admin/workspaces", {}, token),
  deleteWorkspace: (id: string, token: string) => request<void>(`/admin/workspaces/${id}`, { method: "DELETE" }, token),
};

export interface SyncState {
  documents_fp: string; workspaces_fp: string;
  document_ids: string[]; document_workspaces: Record<string, string | null>;
  workspace_ids: string[];
}
export const syncApi = {
  poll: (token: string) => request<SyncState>("/sync/poll", {}, token),
};
