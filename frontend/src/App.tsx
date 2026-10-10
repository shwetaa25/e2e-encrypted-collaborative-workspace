import { useSessionStore } from "./store/sessionStore";
import { AuthPage } from "./pages/AuthPage";
import { WorkspacePage } from "./pages/WorkspacePage";
import { AdminPage } from "./pages/AdminPage";

export default function App() {
  const token = useSessionStore((s) => s.token);
  const view = useSessionStore((s) => s.view);
  const isAdmin = useSessionStore((s) => s.isAdmin);
  if (!token) return <AuthPage />;
  // The Admin Console is a completely separate screen from the workspace
  return isAdmin && view === "admin" ? <AdminPage /> : <WorkspacePage />;
}
