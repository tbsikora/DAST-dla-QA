import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import path from "path";
import { mkdir } from "fs/promises";
import { fileURLToPath } from "url";

export type StoredScan = {
  id: string;
  createdAt: string;
  status: "queued" | "running" | "finished";
  endpoints?: { method: string; path: string }[];
  totalTests?: number;
  totalErrors?: number;
  totalSuspicious?: number;
  testResults: any[];
  seedResults?: { method: string; path: string; resourceKey: string; id?: string; status: "ok" | "error" | "no_id"; message?: string }[];
  config?: any;
};

type DbData = { scans: StoredScan[] };

const thisFile = fileURLToPath(import.meta.url);
const thisDir = path.dirname(thisFile);
const defaultDbFile = path.resolve(thisDir, "..", "data", "scans.json");
const dbFile = process.env.DAST_DB_FILE ? path.resolve(process.env.DAST_DB_FILE) : defaultDbFile;

export const db = new Low<DbData>(new JSONFile<DbData>(dbFile), { scans: [] });

export async function loadScans() {
  await mkdir(path.dirname(dbFile), { recursive: true });
  await db.read();
  db.data ||= { scans: [] };
  return db.data.scans;
}

let flushTimer: NodeJS.Timeout | null = null;

export function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(async () => {
    flushTimer = null;
    await db.write();
  }, 500);
}

export function upsertScan(scan: StoredScan) {
  const idx = db.data!.scans.findIndex((s) => s.id === scan.id);
  if (idx === -1) db.data!.scans.push(scan);
  else db.data!.scans[idx] = scan;
  scheduleFlush();
}
