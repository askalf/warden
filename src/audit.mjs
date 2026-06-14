// Tamper-evident audit log. Each entry's hash chains the previous one, so any
// silent edit to a past verdict breaks verify().
import crypto from 'node:crypto';
import fs from 'node:fs';

const GENESIS = '0'.repeat(64);
const hashOf = (prev, rec) => crypto.createHash('sha256').update(prev + JSON.stringify(rec)).digest('hex');

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
