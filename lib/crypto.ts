export const FILE_SIZE_LIMIT = 64 * 1024 * 1024;
export const PBKDF2_ITERATIONS = 600_000;
const MAGIC = new TextEncoder().encode("SVAULT01");
const HEADER_LIMIT = 16 * 1024;
const ITERATION_MIN = 100_000;
const ITERATION_MAX = 2_000_000;

export type VaultHeader = {
  version: 1;
  algorithm: "AES-256-GCM";
  kdf: "PBKDF2-SHA-256";
  iterations: number;
  salt: string;
  nonce: string;
  filename: string;
  mimeType: string;
  createdAt: string;
};

export class VaultError extends Error {
  constructor(message: string) { super(message); this.name = "VaultError"; }
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: unknown, length: number, label: string): Uint8Array {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new VaultError(`The encrypted file has an invalid ${label}.`);
  }
  const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  if (bytes.length !== length) throw new VaultError(`The encrypted file has an invalid ${label}.`);
  return bytes;
}

export function sanitizeFilename(input: string): string {
  const name = input.split(/[\\/]/).pop() ?? "";
  const cleaned = name.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "_").replace(/[. ]+$/g, "").trim();
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned.slice(0, 180) : "decrypted-file";
}

async function deriveKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(password);
  let material: CryptoKey;
  try {
    material = await crypto.subtle.importKey("raw", passwordBytes as BufferSource, "PBKDF2", false, ["deriveKey"]);
  } finally {
    passwordBytes.fill(0);
  }
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function authenticatedHeader(headerBytes: Uint8Array): Uint8Array {
  const prefix = new Uint8Array(MAGIC.length + 4 + headerBytes.length);
  prefix.set(MAGIC, 0);
  new DataView(prefix.buffer).setUint32(MAGIC.length, headerBytes.length, false);
  prefix.set(headerBytes, MAGIC.length + 4);
  return prefix;
}

export async function encryptBytes(data: Uint8Array, filename: string, mimeType: string, password: string): Promise<Uint8Array> {
  if (!password) throw new VaultError("Enter a password before encrypting.");
  if (data.byteLength > FILE_SIZE_LIMIT) throw new VaultError("This file is larger than the 64 MiB limit.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const header: VaultHeader = {
    version: 1, algorithm: "AES-256-GCM", kdf: "PBKDF2-SHA-256", iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt), nonce: toBase64(nonce), filename: sanitizeFilename(filename),
    mimeType: /^[\w.+-]+\/[\w.+-]+$/.test(mimeType) ? mimeType : "application/octet-stream",
    createdAt: new Date().toISOString(),
  };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const aad = authenticatedHeader(headerBytes);
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  let cipher: Uint8Array | null = null;
  try {
    cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 }, key, data as BufferSource));
    const out = new Uint8Array(aad.length + cipher.length);
    out.set(aad); out.set(cipher, aad.length);
    return out;
  } finally {
    salt.fill(0); nonce.fill(0); headerBytes.fill(0); aad.fill(0); cipher?.fill(0);
  }
}

export async function decryptBytes(file: Uint8Array, password: string): Promise<{ data: Uint8Array; filename: string; mimeType: string }> {
  if (!password) throw new VaultError("Enter the password used to encrypt this file.");
  if (file.byteLength < MAGIC.length + 4 + 16) throw new VaultError("This file is too short to be a valid SecureVault file.");
  if (!MAGIC.every((byte, index) => file[index] === byte)) throw new VaultError("This is not a valid SecureVault file (header marker not found).");
  const headerLength = new DataView(file.buffer, file.byteOffset, file.byteLength).getUint32(MAGIC.length, false);
  const headerStart = MAGIC.length + 4;
  const cipherStart = headerStart + headerLength;
  if (headerLength < 2 || headerLength > HEADER_LIMIT || cipherStart > file.byteLength - 16) throw new VaultError("The encrypted file header is invalid or corrupted.");
  const headerBytes = file.slice(headerStart, cipherStart);
  let header: Partial<VaultHeader>;
  try { header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(headerBytes)) as Partial<VaultHeader>; }
  catch { throw new VaultError("The encrypted file header is not valid JSON."); }
  if (header.version !== 1 || header.algorithm !== "AES-256-GCM" || header.kdf !== "PBKDF2-SHA-256") throw new VaultError("This SecureVault version or algorithm is not supported.");
  if (!Number.isSafeInteger(header.iterations) || header.iterations! < ITERATION_MIN || header.iterations! > ITERATION_MAX) throw new VaultError("The encrypted file has unsafe key-derivation settings.");
  const salt = fromBase64(header.salt, 16, "salt");
  const nonce = fromBase64(header.nonce, 12, "nonce");
  if (typeof header.filename !== "string" || typeof header.mimeType !== "string") throw new VaultError("The encrypted file is missing required metadata.");
  const aad = file.slice(0, cipherStart);
  const ciphertext = file.slice(cipherStart);
  const key = await deriveKey(password, salt, header.iterations!);
  try {
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 }, key, ciphertext as BufferSource));
    if (plain.byteLength > FILE_SIZE_LIMIT) { plain.fill(0); throw new VaultError("The decrypted file is larger than the 64 MiB limit."); }
    return { data: plain, filename: sanitizeFilename(header.filename), mimeType: /^[\w.+-]+\/[\w.+-]+$/.test(header.mimeType) ? header.mimeType : "application/octet-stream" };
  } catch (error) {
    if (error instanceof VaultError) throw error;
    throw new VaultError("Decryption failed. The password may be wrong, or the file may have been modified or corrupted.");
  } finally {
    salt.fill(0); nonce.fill(0); headerBytes.fill(0); aad.fill(0); ciphertext.fill(0);
  }
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
