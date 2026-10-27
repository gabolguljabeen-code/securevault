import { beforeAll, describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";
import { decryptBytes, encryptBytes, FILE_SIZE_LIMIT, sanitizeFilename, VaultError } from "./crypto";

beforeAll(() => { Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true }); });

describe("SecureVault file format", () => {
  it("encrypts and decrypts binary bytes with a Unicode filename", async () => {
    const input = Uint8Array.from([0, 255, 12, 128, 65, 0, 9]);
    const encrypted = await encryptBytes(input, "résumé 安全.bin", "application/octet-stream", "correct horse battery staple 2026");
    const result = await decryptBytes(encrypted, "correct horse battery staple 2026");
    expect([...result.data]).toEqual([...input]);
    expect(result.filename).toBe("résumé 安全.bin");
  }, 30_000);

  it("rejects a wrong password", async () => {
    const encrypted = await encryptBytes(new Uint8Array([1]), "a.txt", "text/plain", "correct horse battery staple");
    await expect(decryptBytes(encrypted, "wrong password entirely")).rejects.toThrow(/password may be wrong/);
  }, 30_000);

  it("rejects modified ciphertext", async () => {
    const encrypted = await encryptBytes(new Uint8Array([1, 2, 3]), "a.txt", "text/plain", "correct horse battery staple");
    encrypted[encrypted.length - 1] ^= 1;
    await expect(decryptBytes(encrypted, "correct horse battery staple")).rejects.toThrow(/modified or corrupted/);
  }, 30_000);

  it("rejects invalid markers and malformed headers", async () => {
    await expect(decryptBytes(new Uint8Array(50), "password")).rejects.toThrow(/marker/);
    const malformed = new Uint8Array(32); malformed.set(new TextEncoder().encode("SVAULT01"));
    new DataView(malformed.buffer).setUint32(8, 99, false);
    await expect(decryptBytes(malformed, "password")).rejects.toThrow(/header/);
  });

  it("supports an empty plaintext file", async () => {
    const encrypted = await encryptBytes(new Uint8Array(), "empty.txt", "text/plain", "correct horse battery staple");
    const result = await decryptBytes(encrypted, "correct horse battery staple");
    expect(result.data).toHaveLength(0);
  }, 30_000);

  it("sanitizes unsafe filename characters and path components", () => {
    expect(sanitizeFilename("../../private:<report>?.txt")).toBe("private__report__.txt");
    expect(sanitizeFilename("../résumé.txt")).toBe("résumé.txt");
    expect(sanitizeFilename("..")).toBe("decrypted-file");
  });

  it("rejects files above the configured size limit", async () => {
    await expect(encryptBytes(new Uint8Array(FILE_SIZE_LIMIT + 1), "large.bin", "", "password"))
      .rejects.toBeInstanceOf(VaultError);
  });
});
