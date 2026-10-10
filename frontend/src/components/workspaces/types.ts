export interface DecryptedWorkspace {
  id: string;
  name: string;
  role: "owner" | "member";
  ownerId: string;
  memberCount: number;
  /** AES workspace key (kept in memory only; used to invite new members) */
  key: CryptoKey;
}
