// Detection benchmark — run the corpus through warden, report catch-rate and
// false-positive rate overall AND per family, then list every miss / false
// positive / under-gate so the gaps are an actionable backlog.
import { check } from '../src/index.mjs';
import { SAMPLES } from './corpus.mjs';

const policy = { egressAllow: ['api.example.com'], writeRoots: ['src/', 'docs/'] };
const C = { r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m', d: '\x1b[2m', x: '\x1b[0m', b: '\x1b[1m' };

const miss = [];  // malicious not blocked
const fp = [];    // benign flagged (over-blocking)
const soft = [];  // risky not gated (slipped to allow)
const fam = new Map(); // family -> { malTot, malHit, benTot, benOk, riskTot, riskOk }

const F = (k) => { if (!fam.has(k)) fam.set(k, { malTot: 0, malHit: 0, benTot: 0, benOk: 0, riskTot: 0, riskOk: 0 }); return fam.get(k); };

for (const s of SAMPLES) {
  const v = check(s.action, policy, { skillText: s.skill || '' });
  const f = F(s.family || 'misc');
  if (s.expect === 'block') {
    f.malTot++;
    if (v.decision === 'block') f.malHit++; else miss.push(`[${s.family}] ${s.label} → ${v.decision} (${v.tier})`);
  } else if (s.expect === 'allow') {
    f.benTot++;
    if (v.decision === 'allow') f.benOk++; else fp.push(`[${s.family}] ${s.label} → ${v.decision} (${v.tier}) :: ${v.why.join(', ')}`);
  } else if (s.expect === 'approve') {
    f.riskTot++;
    if (v.decision !== 'allow') f.riskOk++; else soft.push(`[${s.family}] ${s.label} → allow (${v.tier})`);
  }
}

const mal = SAMPLES.filter((s) => s.expect === 'block');
const ben = SAMPLES.filter((s) => s.expect === 'allow');
const risk = SAMPLES.filter((s) => s.expect === 'approve');
const pct = (n, d) => (d ? (100 * n / d).toFixed(0) : '—');

console.log(`\n${C.b}warden detection bench${C.x}  (${SAMPLES.length} samples · ${fam.size} families)\n`);
console.log(`${C.g}detection${C.x}:      ${mal.length - miss.length}/${mal.length} malicious blocked   (${pct(mal.length - miss.length, mal.length)}% recall)`);
console.log(`${C.r}false-positive${C.x}: ${fp.length}/${ben.length} benign over-flagged   (${pct(ben.length - fp.length, ben.length)}% precision)`);
console.log(`${C.y}under-gated${C.x}:    ${soft.length}/${risk.length} risky slipped to allow`);

console.log(`\n${C.b}per family${C.x}  ${C.d}(malicious blocked · benign clean · risky gated)${C.x}`);
for (const [k, s] of [...fam.entries()].sort()) {
  const seg = [];
  if (s.malTot) seg.push(`${s.malHit === s.malTot ? C.g : C.r}block ${s.malHit}/${s.malTot}${C.x}`);
  if (s.benTot) seg.push(`${s.benOk === s.benTot ? C.g : C.r}clean ${s.benOk}/${s.benTot}${C.x}`);
  if (s.riskTot) seg.push(`${s.riskOk === s.riskTot ? C.g : C.y}gate ${s.riskOk}/${s.riskTot}${C.x}`);
  console.log(`  ${k.padEnd(18)} ${seg.join('  ')}`);
}

if (miss.length) console.log(`\n${C.r}${C.b}MISSES (malicious not blocked) — hardening backlog:${C.x}\n  ${miss.join('\n  ')}`);
if (fp.length) console.log(`\n${C.r}${C.b}FALSE POSITIVES (benign flagged):${C.x}\n  ${fp.join('\n  ')}`);
if (soft.length) console.log(`\n${C.y}${C.b}UNDER-GATED (risky → allow):${C.x}\n  ${soft.join('\n  ')}`);
if (!miss.length && !fp.length && !soft.length) console.log(`\n${C.g}${C.b}clean — every sample classified as expected.${C.x}`);
console.log();
