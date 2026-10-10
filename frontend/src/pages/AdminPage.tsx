import { useEffect, useState } from "react";
import { adminApi, type AdminStats } from "../api/client";
import { useSessionStore, useDocCache } from "../store/sessionStore";
import { NetworkLogPanel } from "../components/admin/NetworkLogPanel";
import { ServerViewPanel } from "../components/admin/ServerViewPanel";
import { AdminAuditPanel } from "../components/admin/AdminAuditPanel";
import { UsersPanel } from "../components/admin/UsersPanel";
import { WorkspacesPanel } from "../components/admin/WorkspacesPanel";

type Tab = "network" | "server" | "audit" | "users" | "workspaces";
const TABS: { id: Tab; label: string }[] = [
  { id: "network", label: "🌐 Network log" },
  { id: "server", label: "🗄 Server database view" },
  { id: "audit", label: "🧾 Audit chain" },
  { id: "users", label: "👥 Accounts" },
  { id: "workspaces", label: "🗂 Workspaces" },
];

export function AdminPage() {
  const { token, email, username, setView } = useSessionStore();
  const [tab, setTab] = useState<Tab>("network");
  const [stats, setStats] = useState<AdminStats | null>(null);

  useEffect(() => {
    if (!token) return;
    const load = () => adminApi.stats(token).then(setStats).catch(() => {});
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [token]);

  const signOut = () => {
    useSessionStore.getState().clearSession();
    useDocCache.getState().clearAll();
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: "var(--bg-app)" }}>
      <header className="top-bar">
        <span style={{ fontSize: 16 }}>🛡</span>
        <span style={{ fontWeight: 600, fontSize: 14 }}>Admin Console</span>
        <span className="enc-status">● Zero-knowledge server — no readable user content</span>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
          <button className="btn btn-ghost btn-sm" onClick={() => setView("workspace")}>← My workspace</button>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{username ? `@${username}` : email}</span>
          <button className="btn btn-ghost btn-sm" onClick={signOut}>Sign out</button>
        </div>
      </header>

      <div style={{ padding: "16px 20px 0", display: "flex", gap: 10, flexWrap: "wrap" }}>
        <StatCard label="Users" value={stats?.users} />
        <StatCard label="Workspaces" value={stats?.workspaces} />
        <StatCard label="Documents" value={stats?.documents} />
        <StatCard label="Wrapped keys" value={stats?.document_keys} />
        <StatCard label="Search tokens" value={stats?.search_tokens} />
        <StatCard label="Ciphertext stored" value={stats ? `${(stats.ciphertext_chars_stored / 1024).toFixed(1)} KB` : undefined} />
        <StatCard label="Plaintext content columns" value={stats?.plaintext_columns_for_content} color="var(--encrypted)" />
      </div>

      <div className="panel-tabs" style={{ margin: "16px 20px 0", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
        {TABS.map((t) => (
          <button key={t.id} className={`panel-tab ${tab === t.id ? "active" : ""}`} style={{ flex: "0 0 auto", padding: "9px 16px", fontSize: 13 }}
            onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 20 }}>
        {tab === "network" && <NetworkLogPanel />}
        {tab === "server" && <ServerViewPanel />}
        {tab === "audit" && <AdminAuditPanel />}
        {tab === "users" && <UsersPanel />}
        {tab === "workspaces" && <WorkspacesPanel />}
      </main>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value?: number | string; color?: string }) {
  return (
    <div className="card" style={{ flex: "1 1 120px", minWidth: 120 }}>
      <div className="muted" style={{ fontSize: 11 }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 600, color: color ?? "var(--text-primary)" }}>{value ?? "—"}</div>
    </div>
  );
}
