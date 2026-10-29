import { beforeAll, describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import { decryptBytes, encryptBytes, FILE_SIZE_LIMIT, generateEncryptionKey, sanitizeFilename, VaultError } from "./crypto";

beforeAll(() => { Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true }); });

describe("SecureVault file format", () => {
  it("encrypts and decrypts binary bytes with a Unicode filename", async () => {
    const input = Uint8Array.from([0, 255, 12, 128, 65, 0, 9]);
    const key = generateEncryptionKey();
    const encrypted = await encryptBytes(input, "résumé 安全.bin", "application/octet-stream", key);
    const result = await decryptBytes(encrypted, key);
    expect([...result.data]).toEqual([...input]);
    expect(result.filename).toBe("résumé 安全.bin");
  }, 30_000);

  it("generates a fresh 256-bit key for each encryption", () => {
    const first = generateEncryptionKey();
    const second = generateEncryptionKey();
    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(second).toMatch(/^[a-f0-9]{64}$/);
    expect(second).not.toBe(first);
  });

  it("rejects a wrong key", async () => {
    const encrypted = await encryptBytes(new Uint8Array([1]), "a.txt", "text/plain", generateEncryptionKey());
    await expect(decryptBytes(encrypted, generateEncryptionKey())).rejects.toThrow(/key may be wrong/);
  }, 30_000);

  it("rejects modified ciphertext", async () => {
    const key = generateEncryptionKey();
    const encrypted = await encryptBytes(new Uint8Array([1, 2, 3]), "a.txt", "text/plain", key);
    encrypted[encrypted.length - 1] ^= 1;
    await expect(decryptBytes(encrypted, key)).rejects.toThrow(/modified or corrupted/);
  }, 30_000);

  it("rejects invalid markers and malformed headers", async () => {
    await expect(decryptBytes(new Uint8Array(50), "password")).rejects.toThrow(/marker/);
    const malformed = new Uint8Array(32); malformed.set(new TextEncoder().encode("SVAULT01"));
    new DataView(malformed.buffer).setUint32(8, 99, false);
    await expect(decryptBytes(malformed, "password")).rejects.toThrow(/header/);
  });

  it("supports an empty plaintext file", async () => {
    const key = generateEncryptionKey();
    const encrypted = await encryptBytes(new Uint8Array(), "empty.txt", "text/plain", key);
    const result = await decryptBytes(encrypted, key);
    expect(result.data).toHaveLength(0);
  }, 30_000);

  it("sanitizes unsafe filename characters and path components", () => {
    expect(sanitizeFilename("../../private:<report>?.txt")).toBe("private__report__.txt");
    expect(sanitizeFilename("../résumé.txt")).toBe("résumé.txt");
    expect(sanitizeFilename("..")).toBe("decrypted-file");
  });

  it("rejects files above the configured size limit", async () => {
    await expect(encryptBytes(new Uint8Array(FILE_SIZE_LIMIT + 1), "large.bin", "", generateEncryptionKey()))
      .rejects.toBeInstanceOf(VaultError);
  });
});
