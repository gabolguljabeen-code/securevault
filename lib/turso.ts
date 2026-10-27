import { createClient, type Client } from "@libsql/client";

const globalForTurso = globalThis as typeof globalThis & { secureVaultTurso?: Client };

export function getTursoClient(): Client {
  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;
  if (!url || !authToken) throw new Error("Turso is not configured.");
  if (!globalForTurso.secureVaultTurso) {
    globalForTurso.secureVaultTurso = createClient({ url, authToken });
  }
  return globalForTurso.secureVaultTurso;
}

export async function ensureHistoryTable() {
  await getTursoClient().execute(`
    CREATE TABLE IF NOT EXISTS operation_history (
      id TEXT PRIMARY KEY,
      browser_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      operation TEXT NOT NULL CHECK (operation IN ('encrypt', 'decrypt')),
      file_size INTEGER NOT NULL CHECK (file_size >= 0 AND file_size <= 67108864),
      algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )
  `);
  await getTursoClient().execute("CREATE INDEX IF NOT EXISTS operation_history_browser_time ON operation_history (browser_id, created_at DESC)");
}
