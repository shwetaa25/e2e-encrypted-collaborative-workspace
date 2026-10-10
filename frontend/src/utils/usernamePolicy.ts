// Mirror of backend/app/security/username_policy.py — the server re-checks everything.

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 20;

const RESERVED = new Set([
  "admin", "administrator", "root", "system", "support", "security", "staff",
  "moderator", "mod", "help", "info", "null", "undefined", "anonymous",
  "everyone", "owner", "api", "www", "me", "you", "user", "test",
]);

export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

export interface UsernameRule { id: string; label: string; passed: boolean }

export function evaluateUsername(raw: string): UsernameRule[] {
  const v = normalizeUsername(raw);
  return [
    { id: "len", label: `${USERNAME_MIN}-${USERNAME_MAX} characters`, passed: v.length >= USERNAME_MIN && v.length <= USERNAME_MAX },
    { id: "start", label: "Starts with a letter", passed: /^[a-z]/.test(v) },
    { id: "chars", label: "Only letters, numbers and underscores", passed: v.length > 0 && /^[a-z0-9_]+$/.test(v) },
    { id: "us", label: "No double or trailing underscore", passed: v.length > 0 && !v.includes("__") && !v.endsWith("_") },
    { id: "reserved", label: "Not a reserved name", passed: v.length > 0 && !RESERVED.has(v) },
  ];
}

export function isValidUsername(raw: string): boolean {
  return evaluateUsername(raw).every((r) => r.passed);
}
