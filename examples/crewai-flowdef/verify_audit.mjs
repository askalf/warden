// Verify warden's audit chain over the governed CrewAI Flow run, then prove it
// is tamper-EVIDENT: flip one byte in a verdict and the chain fails to verify.
//
//   node verify_audit.mjs <path-to-flow_audit.jsonl>
//
// Resolves warden's audit module relative to this example's location in the
// warden repo (examples/crewai-flowdef/ -> ../../src/audit.mjs).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const auditMod = process.env.WARDEN_AUDIT_MODULE || path.resolve(here, '../../src/audit.mjs');
const { verifyAuditFile } = await import(auditMod);

const src = process.argv[2];
if (!src) { console.error('usage: node verify_audit.mjs <audit.jsonl>'); process.exit(2); }

// 1) the real run verifies
const clean = verifyAuditFile(src);
console.log('1) intact chain  ->', JSON.stringify(clean));
if (!clean.ok) { console.error('UNEXPECTED: clean chain did not verify'); process.exit(1); }

// 2) tamper: rewrite a blocked verdict to "allow" in a COPY, re-verify -> fails.
// Use a per-run unique temp dir (mkdtempSync) instead of a fixed name in the
// shared temp dir — a predictable path in os.tmpdir() is a symlink/race surface
// (CodeQL js/insecure-temporary-file).
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-audit-'));
const tampered = path.join(tmpDir, 'tampered_audit.jsonl');
const lines = fs.readFileSync(src, 'utf8').trimEnd().split('\n');
const i = lines.findIndex((l) => l.includes('"decision":"block"'));
lines[i] = lines[i].replace('"decision":"block"', '"decision":"allow"');
fs.writeFileSync(tampered, lines.join('\n') + '\n');
const bad = verifyAuditFile(tampered);
console.log(`2) after flipping the blocked verdict (entry ${i}) to "allow" -> ${JSON.stringify(bad)}`);
fs.rmSync(tmpDir, { recursive: true, force: true });

const passed = clean.ok && !bad.ok;
console.log('\n' + (passed ? 'AUDIT_TAMPER_EVIDENT_PASS' : 'AUDIT_TAMPER_EVIDENT_FAIL'));
process.exit(passed ? 0 : 1);
