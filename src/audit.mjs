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
// CONTINUE the chain across process restarts. Reads the tail and GROWS the window
// until it contains a complete final record — a fixed 8 KB window silently
// returned GENESIS (re-rooting the chain on the next restart, a false tamper
// alarm) whenever the last record was larger than the window. Starts at 8 KB so
// the common case (small records) stays a single O(1) tail read.
export function lastHashOf(path) {
  try {
    const fd = fs.openSync(path, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      if (!size) return GENESIS;
      for (let chunk = 8192; ; chunk *= 8) {
        const len = Math.min(size, chunk);
        const off = size - len;
        const buf = Buffer.alloc(len);
        fs.readSync(fd, buf, 0, len, off);
        const segs = buf.toString('utf8').split('\n');
        // When the window starts mid-file, its first segment is a partial line
        // (and may begin mid-UTF8). Drop it so we never parse a fragment; keep it
        // only when the window covers the whole file (off === 0).
        if (off > 0) segs.shift();
        for (let i = segs.length - 1; i >= 0; i--) {
          if (!segs[i].trim()) continue;
          try { const o = JSON.parse(segs[i]); if (o && o.hash) return o.hash; } catch {}
        }
        if (off === 0) break; // whole file scanned, nothing usable → GENESIS
      }
    } finally { fs.closeSync(fd); }
  } catch {}
  return GENESIS;
}

// A chain HEAD checkpoint: the running hash plus the count of chained records.
// A plain hash chain proves no PAST record was edited or removed from the MIDDLE
// (that breaks a link), but it cannot detect TAIL-TRUNCATION — a valid prefix of
// the chain still verifies clean, so an attacker who can write the log can delete
// the most-recent entries (the ones recording their own action) undetected, and a
// restart re-seeds happily from the truncated tail. The fix is an out-of-band
// anchor: persist {count, head} and require the log to still end there.
//
// The sidecar (`<path>.chk`, mode 0600) raises the bar — accidental truncation
// and any attacker who rewrites the log but not the checkpoint are caught. It is
// NOT a same-attacker defense: someone who can write the directory can rewrite
// both. For that, persist the checkpoint on separate-trust storage and pass it to
// verifyAuditFile() as `expected` (the sidecar is just the convenient default).
const checkpointPath = (p) => p + '.chk';
export function writeCheckpoint(path, state) {
  try { fs.writeFileSync(checkpointPath(path), JSON.stringify({ count: state.count, head: state.head }), { mode: 0o600 }); } catch {}
}
export function readCheckpoint(path) {
  try {
    const o = JSON.parse(fs.readFileSync(checkpointPath(path), 'utf8'));
    if (o && typeof o.head === 'string' && Number.isInteger(o.count)) return { head: o.head, count: o.count };
  } catch {}
  return null;
}

// Full scan of a chained log → its current { head, count }. Unlike lastHashOf
// (a fast tail read for the head only) this also counts chained records, so a
// checkpoint writer can seed an accurate count across restarts.
export function chainStateOf(path) {
  let head = GENESIS, count = 0, data;
  try { data = fs.readFileSync(path, 'utf8'); } catch { return { head, count }; }
  for (const line of data.split('\n')) {
    if (!line.trim()) continue;
    let e; try { e = JSON.parse(line); } catch { continue; }
    if (typeof e.prev !== 'string' || typeof e.hash !== 'string') continue; // skip unchained/foreign lines
    head = e.hash; count++;
  }
  return { head, count };
}

// Streaming, tamper-evident audit. Each record is hash-chained to the previous
// and appended to disk IMMEDIATELY — so the durable log (not just an in-memory
// copy) is verifiable, and there is no unbounded buffer to leak in a long-lived
// daemon. Seeds from the file's last hash so the chain survives restarts.
//
// With { checkpoint: true } it also maintains a 0600 `<path>.chk` head anchor
// after every record, which verifyAuditFile() consults to catch tail-truncation
// (see the checkpoint note above). Default off = byte-identical to before.
export class ChainedFileAudit {
  constructor(path, { checkpoint = false } = {}) {
    this.path = path;
    this.checkpoint = checkpoint;
    if (checkpoint) { const s = chainStateOf(path); this.prev = s.head; this.count = s.count; }
    else { this.prev = lastHashOf(path); this.count = 0; }
  }
  get head() { return this.prev; }
  record(rec) {
    const hash = hashOf(this.prev, rec);
    const entry = { ...rec, prev: this.prev, hash };
    try {
      fs.appendFileSync(this.path, JSON.stringify(entry) + '\n');
      this.prev = hash; this.count++;
      if (this.checkpoint) writeCheckpoint(this.path, { count: this.count, head: hash });
    } catch {}
    return entry;
  }
}

// Verify an on-disk audit chain. { ok:true, entries:N } (plus `unchained:K` when
// K>0 unprotected lines were skipped) or { ok:false, at:i }.
//
// Only records the chained audit wrote — a string `prev` AND `hash` — are part of
// the chain. Any other line is UNPROTECTED history, not part of the chain, and is
// skipped WITHOUT counting as a break: a legacy pre-chain record, or a record
// appended by a different, non-chained writer that happens to share this file
// (e.g. an in-process hook fallback logging raw tool calls). Such a line appearing
// mid-file must not read as tampering when the chain around it is intact — and it
// must not let an attacker defeat verification by appending one junk line.
//
// This still catches every tamper of a CHAINED record: editing one breaks its
// hash; deleting one breaks the next record's `prev` link; and stripping a
// record's `prev`/`hash` to disguise an edit as "un-chained" leaves the NEXT
// chained record's `prev` pointing at a hash that is no longer in the running
// chain — a break. The first chained record must still root at GENESIS, so the
// verified suffix can't be forged.
//
// TAIL-TRUNCATION (deleting the most-recent records) leaves a valid prefix that
// the chain alone CANNOT flag. Pass `expected` = { head, count } — an out-of-band
// checkpoint — to catch it: the log must still end at that head with that many
// chained records, else it was truncated (or rolled back). When omitted, the
// sidecar `<path>.chk` (if a checkpoint writer left one) is used automatically.
export function verifyAuditFile(path, expected = readCheckpoint(path)) {
  const wantCount = expected && Number.isInteger(expected.count) && expected.count > 0 ? expected.count : null;
  const wantHead = expected && typeof expected.head === 'string' ? expected.head : null;
  let prev = GENESIS, n = 0, unchained = 0, data, headAtCount = null;
  try {
    data = fs.readFileSync(path, 'utf8');
  } catch {
    // A checkpoint that expected records but the file is gone = truncated-to-nothing.
    if (wantCount) return { ok: false, at: 0, reason: 'truncated' };
    return { ok: true, entries: 0 };
  }
  for (const line of data.split('\n')) {
    if (!line.trim()) continue;
    let e; try { e = JSON.parse(line); } catch { return { ok: false, at: n }; }
    if (typeof e.prev !== 'string' || typeof e.hash !== 'string') { unchained++; continue; } // unprotected, not chained
    const { prev: p, hash, ...rec } = e;
    if (p !== prev || hashOf(prev, rec) !== hash) return { ok: false, at: n };
    prev = hash; n++;
    if (wantCount != null && n === wantCount) headAtCount = prev; // the checkpointed head's expected position
  }
  // Truncation / rollback against a trusted checkpoint. The checkpointed PREFIX
  // must still be present and unchanged: fewer records than promised = truncated;
  // the count-th record's hash not matching the checkpoint head = the prefix was
  // rewritten (rollback, or truncate-and-regrow to the same length). A log that
  // legitimately grew PAST the checkpoint (n > count) still verifies — only the
  // checkpointed prefix is pinned, so a stale checkpoint never false-alarms.
  if (wantCount != null) {
    if (n < wantCount) return { ok: false, at: n, reason: 'truncated' };
    if (wantHead != null && headAtCount !== wantHead) return { ok: false, at: wantCount, reason: 'rollback' };
  } else if (wantHead != null && prev !== wantHead) {
    return { ok: false, at: n, reason: 'rollback' };
  }
  return unchained ? { ok: true, entries: n, unchained } : { ok: true, entries: n };
}
