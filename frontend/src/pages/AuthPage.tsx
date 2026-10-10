import { useState } from "react";
import { authApi, ApiError } from "../api/client";
import { prepareRegistration, initCryptoSession } from "../crypto";
import { useSessionStore } from "../store/sessionStore";
import { evaluatePassword, isStrongPassword, strengthScore, canonicalizeEmail } from "../utils/passwordPolicy";
import { evaluateUsername, isValidUsername, normalizeUsername } from "../utils/usernamePolicy";

export function AuthPage() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);
  const { setSession, setLoading, isLoading } = useSessionStore();

  const rules = evaluatePassword(password, email, username);
  const strength = strengthScore(password, email, username);
  const strong = isStrongPassword(password, email, username);
  const nameRules = evaluateUsername(username);
  const nameOk = isValidUsername(username);
  const mismatch = confirm.length > 0 && password !== confirm;
  const canRegister = nameOk && strong && password === confirm && email.trim().length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (mode === "register") {
      if (!nameOk) { setError("Please choose a valid username — see the rules below the field."); return; }
      if (!strong) { setError("Please choose a stronger password — see the checklist below."); return; }
      if (password !== confirm) { setError("Passwords do not match"); return; }
    }
    setLoading(true);
    try {
      if (mode === "register") {
        setStatus("Deriving master key (PBKDF2)…");
        const reg = await prepareRegistration(email.trim(), password);
        setStatus("Generating RSA-2048 key pair…");
        const resp = await authApi.register({
          email: reg.email, username: normalizeUsername(username), password: reg.password,
          public_key_spki: reg.publicKeyB64,
          wrapped_private_key: reg.wrappedPrivateKeyB64,
          wrap_iv: reg.wrapIvB64, pbkdf2_salt: reg.saltB64,
        });
        setSession({ token: resp.access_token, userId: resp.user_id, email: canonicalizeEmail(email),
          username: resp.username ?? normalizeUsername(username),
          privateKey: reg.privateKey, publicKey: reg.publicKey, publicKeyBase64: reg.publicKeyB64,
          isAdmin: resp.is_admin });
      } else {
        setStatus("Re-deriving keys from password…");
        const resp = await authApi.login(email.trim(), password);
        const session = await initCryptoSession(password, {
          userId: resp.user_id, pbkdf2_salt: resp.pbkdf2_salt,
          wrapped_private_key: resp.wrapped_private_key, wrap_iv: resp.wrap_iv,
          public_key_spki: resp.public_key_spki,
        });
        setSession({ token: resp.access_token, email: canonicalizeEmail(email), ...session,
          username: resp.username, isAdmin: resp.is_admin });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Something went wrong");
      setStatus("");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-app)", padding: 16 }}>
      <div style={{ width: "100%", maxWidth: 400 }}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 48, height: 48, borderRadius: 12, background: "var(--accent-dim)", border: "1px solid rgba(79,142,247,0.3)", marginBottom: 14 }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4F8EF7" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <h1 style={{ fontSize: 20, fontWeight: 600 }}>Encrypted Workspace</h1>
          <p style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 4 }}>End-to-end encrypted document collaboration</p>
        </div>

        <div style={{ padding: "10px 14px", borderRadius: 8, background: "var(--encrypted-dim)", border: "1px solid rgba(34,197,94,0.2)", marginBottom: 20, display: "flex", gap: 10 }}>
          <span style={{ color: "var(--encrypted)" }}>🔒</span>
          <p style={{ fontSize: 12, color: "var(--encrypted)", lineHeight: 1.6 }}>Keys are generated in your browser. The server stores only encrypted blobs.</p>
        </div>

        <div style={{ display: "flex", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8, padding: 3, marginBottom: 20, gap: 3 }}>
          {(["login", "register"] as const).map((m) => (
            <button key={m} onClick={() => { setMode(m); setError(null); setStatus(""); }}
              style={{ flex: 1, padding: 7, border: "none", borderRadius: 4, fontSize: 13, fontWeight: 500, cursor: "pointer", background: mode === m ? "var(--bg-surface)" : "transparent", color: mode === m ? "var(--text-primary)" : "var(--text-secondary)" }}>
              {m === "login" ? "Sign in" : "Create account"}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {mode === "register" && (
            <div className="form-group">
              <label className="input-label">Username</label>
              <input className="input" placeholder="e.g. alice_dev" value={username} maxLength={20}
                onChange={(e) => setUsername(e.target.value)} required autoComplete="username" />
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                This is how others find and add you — your email is never shown to anyone.
              </span>
              {username.length > 0 && (
                <ul style={{ listStyle: "none", padding: 0, margin: "4px 0 0", display: "flex", flexWrap: "wrap", gap: "2px 12px" }}>
                  {nameRules.map((r) => (
                    <li key={r.id} style={{ fontSize: 11, color: r.passed ? "var(--encrypted)" : "var(--danger)" }}>
                      {r.passed ? "✓" : "✕"} {r.label}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          <div className="form-group">
            <label className="input-label">{mode === "register" ? "Email (private, used to sign in)" : "Email or username"}</label>
            <input className="input" type={mode === "register" ? "email" : "text"}
              placeholder={mode === "register" ? "you@example.com" : "you@example.com or alice_dev"}
              value={email} onChange={(e) => setEmail(e.target.value)} required
              autoComplete={mode === "register" ? "email" : "username"} />
            {mode === "register" && (
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>One account per email — upper/lower case and “+tags” count as the same address.</span>
            )}
          </div>
          <div className="form-group">
            <label className="input-label">Password</label>
            <input className="input" type="password" placeholder={mode === "register" ? "Create a strong password" : "Your password"} value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete={mode === "register" ? "new-password" : "current-password"} />
          </div>

          {mode === "register" && (
            <div style={{ padding: "10px 12px", borderRadius: 8, background: "var(--bg-elevated)", border: "1px solid var(--border)", marginTop: -4 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 6 }}>
                Your password must have:
              </div>
              <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 3 }}>
                {rules.map((r) => (
                  <li key={r.id} style={{ fontSize: 12, display: "flex", gap: 8, alignItems: "center", color: !password ? "var(--text-muted)" : r.passed ? "var(--encrypted)" : "var(--danger)" }}>
                    <span style={{ width: 12, textAlign: "center", fontWeight: 700 }}>{!password ? "○" : r.passed ? "✓" : "✕"}</span>
                    {r.label}
                  </li>
                ))}
              </ul>
              <div style={{ display: "flex", gap: 4, marginTop: 10 }}>
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} style={{ flex: 1, height: 4, borderRadius: 2, background: i <= strength.score ? strength.color : "var(--border-mid)" }} />
                ))}
              </div>
              <div style={{ fontSize: 11, color: strength.color, marginTop: 4, minHeight: 14 }}>{strength.label}</div>
              <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6, lineHeight: 1.5 }}>
                Tip: a long passphrase such as <span style={{ fontFamily: "var(--font-mono)" }}>Blue-Tiger#Rides9Trains</span> is easy to remember and hard to crack.
                Your password also protects your encryption keys — if you forget it, your documents cannot be recovered.
              </p>
            </div>
          )}
          {mode === "register" && (
            <div className="form-group">
              <label className="input-label">Confirm password</label>
              <input className="input" type="password" placeholder="Re-enter password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password" />
              {mismatch && <span style={{ fontSize: 11, color: "var(--danger)" }}>Passwords do not match</span>}
            </div>
          )}
          {error && <div style={{ padding: "8px 12px", borderRadius: 4, background: "var(--danger-dim)", color: "var(--danger)", fontSize: 13 }}>{error}</div>}
          {status && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderRadius: 4, background: "var(--accent-dim)", border: "1px solid rgba(79,142,247,0.2)" }}>
              <div className="spinner" />
              <span style={{ fontSize: 12, color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{status}</span>
            </div>
          )}
          <button type="submit" className="btn btn-primary" disabled={isLoading || (mode === "register" && !canRegister)} style={{ width: "100%", padding: 10, fontSize: 14 }}>
            {isLoading ? <><div className="spinner" style={{ borderTopColor: "white" }} />{mode === "login" ? "Signing in…" : "Generating keys…"}</> : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
