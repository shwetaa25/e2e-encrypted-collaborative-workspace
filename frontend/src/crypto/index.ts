// WebCrypto operations — all encryption happens here in the browser

const AES_GCM = "AES-GCM";
const RSA_OAEP = "RSA-OAEP";
const PBKDF2 = "PBKDF2";
const SHA256 = "SHA-256";
const IV_LENGTH = 12;
const SALT_LENGTH = 16;

// ── Encoding helpers ──────────────────────────────────────

export function bufToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

export function strToBuf(s: string): ArrayBuffer {
  return new TextEncoder().encode(s).buffer as ArrayBuffer;
}

export function bufToStr(buf: ArrayBuffer): string {
  return new TextDecoder().decode(buf);
}

export function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Master key derivation (PBKDF2) ───────────────────────

export async function deriveMasterKey(password: string, saltB64?: string): Promise<{ key: CryptoKey; saltB64: string }> {
  const salt = saltB64 ? new Uint8Array(b64ToBuf(saltB64)) : crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const pwKey = await crypto.subtle.importKey("raw", strToBuf(password), { name: PBKDF2 }, false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: PBKDF2, salt, iterations: 600_000, hash: SHA256 },
    pwKey,
    { name: AES_GCM, length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );
  return { key, saltB64: bufToB64(salt.buffer as ArrayBuffer) };
}

// ── RSA key pair ──────────────────────────────────────────

export async function generateUserKeyPair(masterKey: CryptoKey): Promise<{
  publicKey: CryptoKey; privateKey: CryptoKey;
  publicKeyB64: string; wrappedPrivateKeyB64: string; wrapIvB64: string;
}> {
  const kp = await crypto.subtle.generateKey(
    { name: RSA_OAEP, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: SHA256 },
    true,
    ["wrapKey", "unwrapKey"]
  );
  const publicKeySpki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const wrapIv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const wrappedPrivate = await crypto.subtle.wrapKey("pkcs8", kp.privateKey, masterKey, { name: AES_GCM, iv: wrapIv });
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    publicKeyB64: bufToB64(publicKeySpki),
    wrappedPrivateKeyB64: bufToB64(wrappedPrivate),
    wrapIvB64: bufToB64(wrapIv.buffer as ArrayBuffer),
  };
}

export async function unwrapPrivateKey(wrappedB64: string, wrapIvB64: string, masterKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "pkcs8", b64ToBuf(wrappedB64), masterKey,
    { name: AES_GCM, iv: new Uint8Array(b64ToBuf(wrapIvB64)) },
    { name: RSA_OAEP, hash: SHA256 },
    false, ["unwrapKey"]
  );
}

export async function importPublicKey(spkiB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", b64ToBuf(spkiB64), { name: RSA_OAEP, hash: SHA256 }, false, ["wrapKey"]);
}

// ── Document key ──────────────────────────────────────────

export async function generateDocumentKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: AES_GCM, length: 256 }, true, ["encrypt", "decrypt"]);
}

export async function wrapDocumentKey(docKey: CryptoKey, recipientPublicKey: CryptoKey): Promise<string> {
  const wrapped = await crypto.subtle.wrapKey("raw", docKey, recipientPublicKey, { name: RSA_OAEP });
  return bufToB64(wrapped);
}

export async function unwrapDocumentKey(wrappedB64: string, privateKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw", b64ToBuf(wrappedB64), privateKey,
    { name: RSA_OAEP },
    { name: AES_GCM },
    true, ["encrypt", "decrypt"]
  );
}

// ── Encrypt / Decrypt ─────────────────────────────────────

export async function encryptField(plaintext: string, key: CryptoKey): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const buf = await crypto.subtle.encrypt({ name: AES_GCM, iv }, key, strToBuf(plaintext));
  return { ciphertext: bufToB64(buf), iv: bufToB64(iv.buffer as ArrayBuffer) };
}

export async function decryptField(ciphertextB64: string, ivB64: string, key: CryptoKey): Promise<string> {
  try {
    const buf = await crypto.subtle.decrypt(
      { name: AES_GCM, iv: new Uint8Array(b64ToBuf(ivB64)) },
      key,
      b64ToBuf(ciphertextB64)
    );
    return bufToStr(buf);
  } catch {
    throw new Error("Decryption failed — wrong key or tampered data");
  }
}

export async function encryptDocument(title: string, content: string, key: CryptoKey) {
  const [t, c] = await Promise.all([encryptField(title, key), encryptField(content, key)]);
  return { titleCiphertext: t.ciphertext, titleIv: t.iv, contentCiphertext: c.ciphertext, contentIv: c.iv };
}

export async function decryptDocument(enc: {
  titleCiphertext: string; titleIv: string;
  contentCiphertext: string; contentIv: string;
}, key: CryptoKey, id: string) {
  const [title, content] = await Promise.all([
    decryptField(enc.titleCiphertext, enc.titleIv, key),
    decryptField(enc.contentCiphertext, enc.contentIv, key),
  ]);
  return { id, title, content, documentKey: key };
}

export const encryptComment = encryptField;
export const decryptComment = decryptField;

// ── SSE Search ────────────────────────────────────────────

export async function deriveSearchKey(docKey: CryptoKey): Promise<CryptoKey> {
  const raw = await crypto.subtle.exportKey("raw", docKey);
  const hkdf = await crypto.subtle.importKey("raw", raw, { name: "HKDF" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: SHA256, salt: new Uint8Array(32), info: strToBuf("search-index-v1") },
    hkdf,
    { name: "HMAC", hash: SHA256 },
    false, ["sign"]
  );
}

export async function keywordToToken(word: string, searchKey: CryptoKey): Promise<string> {
  const normalized = word.toLowerCase().replace(/[^a-z0-9]/g, "");
  const buf = await crypto.subtle.sign({ name: "HMAC" }, searchKey, strToBuf(normalized));
  return bufToHex(buf);
}

export async function buildSearchIndex(content: string, docId: string, searchKey: CryptoKey) {
  const stopwords = new Set(["the","and","or","in","on","at","to","for","of","a","an","is","it"]);
  const words = [...new Set(
    content.toLowerCase().split(/[\s.,;:!?'"()\[\]{}\-/\\]+/)
      .map((w) => w.replace(/[^a-z0-9]/g, ""))
      .filter((w) => w.length >= 3 && !stopwords.has(w))
  )];
  return Promise.all(words.map(async (w) => ({ keywordToken: await keywordToToken(w, searchKey), documentId: docId })));
}

export async function buildSearchTokens(query: string, searchKey: CryptoKey): Promise<string[]> {
  const stopwords = new Set(["the","and","or","in","on","at","to","for","of","a","an","is","it"]);
  const words = [...new Set(
    query.toLowerCase().split(/[\s.,;:!?\'"()\[\]{}\-/\\]+/)
      .map((w) => w.replace(/[^a-z0-9]/g, ""))
      .filter((w) => w.length >= 3 && !stopwords.has(w))
  )];
  return Promise.all(words.map((w) => keywordToToken(w, searchKey)));
}

// ── High-level flows ──────────────────────────────────────

export async function prepareRegistration(email: string, password: string) {
  const { key: masterKey, saltB64 } = await deriveMasterKey(password);
  const { publicKeyB64, wrappedPrivateKeyB64, wrapIvB64, publicKey, privateKey } = await generateUserKeyPair(masterKey);
  return { email, password, publicKeyB64, wrappedPrivateKeyB64, wrapIvB64, saltB64, publicKey, privateKey };
}

export async function initCryptoSession(password: string, serverData: {
  userId: string; pbkdf2_salt: string; wrapped_private_key: string;
  wrap_iv: string; public_key_spki: string;
}) {
  const { key: masterKey } = await deriveMasterKey(password, serverData.pbkdf2_salt);
  const privateKey = await unwrapPrivateKey(serverData.wrapped_private_key, serverData.wrap_iv, masterKey);
  const publicKey = await importPublicKey(serverData.public_key_spki);
  return { userId: serverData.userId, privateKey, publicKey, publicKeyBase64: serverData.public_key_spki };
}
