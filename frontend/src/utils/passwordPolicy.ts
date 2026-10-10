// Mirror of backend/app/security/password_policy.py — keep the two in sync.
// The server re-checks everything; this file only gives instant feedback.

export const MIN_LENGTH = 12;
export const MAX_LENGTH = 128;

const COMMON_PASSWORDS = new Set([
  "password", "passw0rd", "p@ssword", "p@ssw0rd", "password1", "password12",
  "password123", "password1234", "123456", "1234567", "12345678", "123456789",
  "1234567890", "12345678910", "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl",
  "zxcvbnm", "abc123", "abcd1234", "iloveyou", "admin", "admin123", "administrator",
  "welcome", "welcome1", "welcome123", "letmein", "monkey", "dragon", "football",
  "baseball", "master", "sunshine", "princess", "login", "starwars", "whatever",
  "trustno1", "111111", "000000", "123123", "654321", "superman", "batman",
  "changeme", "secret", "testpass", "testpassword", "test1234", "hello123",
  "freedom", "shadow", "michael", "jennifer", "computer", "internet", "cricket",
  "india123", "mumbai", "krishna", "ganesh", "lovely", "pass1234", "guest",
]);

export function canonicalizeEmail(raw: string): string {
  const value = raw.trim().toLowerCase();
  const at = value.lastIndexOf("@");
  if (at < 0) return value;
  const local = value.slice(0, at).split("+")[0];
  return `${local}@${value.slice(at + 1)}`;
}

export interface PasswordRule {
  id: string;
  label: string;
  passed: boolean;
}

export function evaluatePassword(password: string, email = "", username = ""): PasswordRule[] {
  const lowered = password.toLowerCase();
  const lettersOnly = lowered.replace(/[^a-z]/g, "");
  const local = email.includes("@") ? canonicalizeEmail(email).split("@")[0] : "";
  const isCommon = COMMON_PASSWORDS.has(lowered) || (lettersOnly.length >= 4 && COMMON_PASSWORDS.has(lettersOnly));
  const hasPassword = password.length > 0;
  const uname = username.trim().toLowerCase();

  return [
    { id: "length", label: `At least ${MIN_LENGTH} characters`, passed: password.length >= MIN_LENGTH && password.length <= MAX_LENGTH },
    { id: "lower", label: "One lowercase letter (a-z)", passed: /[a-z]/.test(password) },
    { id: "upper", label: "One uppercase letter (A-Z)", passed: /[A-Z]/.test(password) },
    { id: "digit", label: "One number (0-9)", passed: /[0-9]/.test(password) },
    { id: "special", label: "One special character (! @ # $ % …)", passed: /[^A-Za-z0-9]/.test(password) },
    { id: "repeat", label: "No character repeated 3+ times in a row", passed: hasPassword && !/(.)\1\1/.test(password) },
    { id: "space", label: "No spaces", passed: hasPassword && !/\s/.test(password) },
    { id: "common", label: "Not a common password (e.g. “Password123!”)", passed: hasPassword && !isCommon },
    { id: "email", label: "Does not contain your email name", passed: hasPassword && !(local.length >= 3 && lowered.includes(local)) },
    { id: "username", label: "Does not contain your username", passed: hasPassword && !(uname.length >= 3 && lowered.includes(uname)) },
  ];
}

export function isStrongPassword(password: string, email = "", username = ""): boolean {
  return evaluatePassword(password, email, username).every((r) => r.passed);
}

/** 0-4 score for the strength bar. */
export function strengthScore(password: string, email = "", username = ""): { score: number; label: string; color: string } {
  if (!password) return { score: 0, label: "", color: "var(--text-muted)" };
  const rules = evaluatePassword(password, email, username);
  const passed = rules.filter((r) => r.passed).length;
  if (passed === rules.length) {
    const bonus = password.length >= 16 ? 4 : 3;
    return bonus === 4
      ? { score: 4, label: "Very strong", color: "var(--encrypted)" }
      : { score: 3, label: "Strong", color: "var(--encrypted)" };
  }
  const ratio = passed / rules.length;
  if (ratio < 0.5) return { score: 1, label: "Weak", color: "var(--danger)" };
  return { score: 2, label: "Almost there", color: "var(--warn)" };
}
