import { NextRequest, NextResponse } from "next/server";
import { ensureHistoryTable, getTursoClient } from "@/lib/turso";
import { FILE_SIZE_LIMIT, sanitizeFilename } from "@/lib/crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COOKIE = "svault_browser";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type HistoryItem = { id: string; filename: string; mode: "encrypt" | "decrypt"; at: string; size: number };

function getBrowserId(request: NextRequest) {
  const current = request.cookies.get(COOKIE)?.value;
  return current && UUID_PATTERN.test(current) ? { id: current, isNew: false } : { id: crypto.randomUUID(), isNew: true };
}

function json(data: unknown, status = 200, browserId?: string, isNew = false) {
  const response = NextResponse.json(data, { status, headers: { "Cache-Control": "no-store, max-age=0" } });
  if (browserId && isNew) response.cookies.set(COOKIE, browserId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  return response;
}

function originIsSame(request: NextRequest) {
  const origin = request.headers.get("origin");
  return !!origin && origin === new URL(request.url).origin;
}

export async function GET(request: NextRequest) {
  try {
    await ensureHistoryTable();
    const browser = getBrowserId(request);
    const result = await getTursoClient().execute({
      sql: "SELECT id, filename, operation, file_size, created_at FROM operation_history WHERE browser_id = ? ORDER BY created_at DESC LIMIT 50",
      args: [browser.id],
    });
    const history: HistoryItem[] = result.rows.map((row) => ({
      id: String(row.id), filename: String(row.filename), mode: row.operation === "decrypt" ? "decrypt" : "encrypt",
      at: String(row.created_at), size: Number(row.file_size),
    }));
    return json({ history, storage: "turso" }, 200, browser.id, browser.isNew);
  } catch {
    return json({ error: "Turso history is unavailable. Check the server database configuration." }, 503);
  }
}

export async function POST(request: NextRequest) {
  if (!originIsSame(request)) return json({ error: "Request origin was not accepted." }, 403);
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > 2048) return json({ error: "History request is too large." }, 413);
  let body: unknown;
  try { body = await request.json(); }
  catch { return json({ error: "Invalid request body." }, 400); }
  if (!body || typeof body !== "object") return json({ error: "Invalid history entry." }, 400);
  const value = body as Record<string, unknown>;
  if ((value.mode !== "encrypt" && value.mode !== "decrypt") || typeof value.filename !== "string" || !Number.isSafeInteger(value.size) || (value.size as number) < 0 || (value.size as number) > FILE_SIZE_LIMIT) {
    return json({ error: "Invalid history entry." }, 400);
  }
  const filename = sanitizeFilename(value.filename);
  if (!filename || filename.length > 180) return json({ error: "Invalid filename." }, 400);
  try {
    await ensureHistoryTable();
    const browser = getBrowserId(request);
    const id = crypto.randomUUID();
    await getTursoClient().execute({
      sql: "INSERT INTO operation_history (id, browser_id, filename, operation, file_size) VALUES (?, ?, ?, ?, ?)",
      args: [id, browser.id, filename, value.mode, value.size as number],
    });
    await getTursoClient().execute({
      sql: "DELETE FROM operation_history WHERE browser_id = ? AND id NOT IN (SELECT id FROM operation_history WHERE browser_id = ? ORDER BY created_at DESC, id DESC LIMIT 50)",
      args: [browser.id, browser.id],
    });
    const result = await getTursoClient().execute({
      sql: "SELECT id, filename, operation, file_size, created_at FROM operation_history WHERE browser_id = ? ORDER BY created_at DESC LIMIT 50",
      args: [browser.id],
    });
    const history: HistoryItem[] = result.rows.map((row) => ({
      id: String(row.id), filename: String(row.filename), mode: row.operation === "decrypt" ? "decrypt" : "encrypt",
      at: String(row.created_at), size: Number(row.file_size),
    }));
    return json({ history, storage: "turso" }, 201, browser.id, browser.isNew);
  } catch {
    return json({ error: "Could not save operation history to Turso." }, 503);
  }
}

export async function DELETE(request: NextRequest) {
  if (!originIsSame(request)) return json({ error: "Request origin was not accepted." }, 403);
  try {
    await ensureHistoryTable();
    const browser = getBrowserId(request);
    await getTursoClient().execute({ sql: "DELETE FROM operation_history WHERE browser_id = ?", args: [browser.id] });
    return json({ cleared: true }, 200, browser.id, browser.isNew);
  } catch {
    return json({ error: "Could not clear operation history from Turso." }, 503);
  }
}
