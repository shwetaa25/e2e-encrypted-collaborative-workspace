import { create } from "zustand";

interface SessionState {
  token: string | null;
  userId: string | null;
  email: string | null;
  username: string | null;
  privateKey: CryptoKey | null;
  publicKey: CryptoKey | null;
  publicKeyBase64: string | null;
  isAdmin: boolean;
  /** Which top-level screen is showing. Admins can switch between them. */
  view: "workspace" | "admin";
  isLoading: boolean;
  error: string | null;
  setSession: (params: {
    token: string; userId: string; email: string; username?: string | null;
    privateKey: CryptoKey; publicKey: CryptoKey; publicKeyBase64: string;
    isAdmin?: boolean;
  }) => void;
  setView: (v: "workspace" | "admin") => void;
  clearSession: () => void;
  setLoading: (v: boolean) => void;
  setError: (msg: string | null) => void;
}

export const useSessionStore = create<SessionState>((set) => ({
  token: null, userId: null, email: null, username: null,
  privateKey: null, publicKey: null, publicKeyBase64: null,
  isAdmin: false, view: "workspace",
  isLoading: false, error: null,
  // Admins land on the Admin Console; everyone else on their workspace
  setSession: (p) => set({ ...p, username: p.username ?? null, isAdmin: !!p.isAdmin, view: p.isAdmin ? "admin" : "workspace", error: null }),
  setView: (view) => set({ view }),
  clearSession: () => set({
    token: null, userId: null, email: null, username: null,
    privateKey: null, publicKey: null, publicKeyBase64: null,
    isAdmin: false, view: "workspace",
  }),
  setLoading: (isLoading) => set({ isLoading }),
  setError: (error) => set({ error }),
}));

export interface DecryptedDoc {
  id: string;
  title: string;
  content: string;
  documentKey: CryptoKey;
  accessLevel: string;
  currentVersion: number;
  updatedAt: string;
}

interface DocCacheState {
  docs: Record<string, DecryptedDoc>;
  setDoc: (doc: DecryptedDoc) => void;
  removeDoc: (id: string) => void;
  clearAll: () => void;
}

export const useDocCache = create<DocCacheState>((set) => ({
  docs: {},
  setDoc: (doc) => set((s) => ({ docs: { ...s.docs, [doc.id]: doc } })),
  removeDoc: (id) => set((s) => {
    const next = { ...s.docs };
    delete next[id];
    return { docs: next };
  }),
  clearAll: () => set({ docs: {} }),
}));
