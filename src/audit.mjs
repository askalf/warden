// Tamper-evident audit log. Each entry's hash chains the previous one, so any
// silent edit to a past verdict breaks verify().
import crypto from 'node:crypto';
import fs from 'node:fs';

export const GENESIS = '0'.repeat(64);
export const hashOf = (prev, rec) => crypto.createHash('sha256').update(prev + JSON.stringify(rec)).digest('hex');

export class AuditLog {
  constructor() { this.entries = []; this.prev = GENESIS; }

  record(rec) {
    const hash = hashOf(this.prev, rec);
    const entry = { ...rec, prev: this.prev, hash };
    this.entries.push(entry);
    this.prev = hash;
    return entry;
  }

  /** Returns true iff the hash chain is intact (no entry has been altered). */
  verify() {
    let prev = GENESIS;
    for (const e of this.entries) {
      const { prev: _p, hash, ...rec } = e;
      if (e.prev !== prev || hashOf(prev, rec) !== hash) return false;
      prev = hash;
    }
    return true;
  }

  /** Append entries to a JSONL file (durable audit trail). */
  flush(path) {
    fs.appendFileSync(path, this.entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
  }
}

// Read the last chained hash from an audit file so a streaming appender can
// CONTINUE the chain across process restarts. Reads only the tail (8 KB) — O(1)
// regardless of how large the log has grown.
export function lastHashOf(path) {
  try {
    const fd = fs.openSync(path, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      if (!size) return GENESIS;
      const len = Math.min(size, 8192);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, size - len);
      const lines = buf.toString('utf8').split('\n').filter((l) => l.trim());
      for (let i = lines.length - 1; i >= 0; i--) {
        try { const o = JSON.parse(lines[i]); if (o && o.hash) return o.hash; } catch {}
      }
    } finally { fs.closeSync(fd); }
  } catch {}
  return GENESIS;
}

// Streaming, tamper-evident audit. Each record is hash-chained to the previous
// and appended to disk IMMEDIATELY — so the durable log (not just an in-memory
// copy) is verifiable, and there is no unbounded buffer to leak in a long-lived
// daemon. Seeds from the file's last hash so the chain survives restarts.
export class ChainedFileAudit {
  constructor(path) { this.path = path; this.prev = lastHashOf(path); }
  record(rec) {
    const hash = hashOf(this.prev, rec);
    const entry = { ...rec, prev: this.prev, hash };
    try { fs.appendFileSync(this.path, JSON.stringify(entry) + '\n'); this.prev = hash; } catch {}
    return entry;
  }
}

// Verify an on-disk audit chain. { ok:true, entries:N } or { ok:false, at:i }.
// Leading legacy lines written before chaining existed (no `hash` field) are
// unprotected history and skipped; verification covers the chain from where it
// begins (its first entry must root at GENESIS, so the suffix can't be forged).
export function verifyAuditFile(path) {
  let prev = GENESIS, n = 0, started = false, data;
  try { data = fs.readFileSync(path, 'utf8'); } catch { return { ok: true, entries: 0 }; }
  for (const line of data.split('\n')) {
    if (!line.trim()) continue;
    let e; try { e = JSON.parse(line); } catch { return { ok: false, at: n }; }
    if (!started) { if (typeof e.hash !== 'string') continue; started = true; } // skip pre-chain legacy lines
    const { prev: p, hash, ...rec } = e;
    if (p !== prev || hashOf(prev, rec) !== hash) return { ok: false, at: n };
    prev = hash; n++;
  }
  return { ok: true, entries: n };
}
