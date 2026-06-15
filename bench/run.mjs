// Detection benchmark — run the corpus through warden, report catch-rate and
// false-positive rate, and list every miss / false positive to fix.
import { check } from '../src/index.mjs';
import { SAMPLES } from './corpus.mjs';

const policy = { egressAllow: ['api.example.com'], writeRoots: ['src/', 'docs/'] };
const C = { r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m', d: '\x1b[2m', x: '\x1b[0m', b: '\x1b[1m' };

const miss = [];  // malicious not blocked
const fp = [];    // benign flagged (over-blocking)
const soft = [];  // risky not gated

for (const s of SAMPLES) {
  const v = check(s.action, policy, { skillText: s.skill || '' });
  if (s.expect === 'block' && v.decision !== 'block') miss.push(`${s.label} → ${v.decision} (${v.tier})`);
  else if (s.expect === 'allow' && v.decision !== 'allow') fp.push(`${s.label} → ${v.decision} (${v.tier}) :: ${v.why.join(', ')}`);
  else if (s.expect === 'approve' && v.decision === 'allow') soft.push(`${s.label} → allow (${v.tier})`);
}

const mal = SAMPLES.filter((s) => s.expect === 'block');
const ben = SAMPLES.filter((s) => s.expect === 'allow');
console.log(`\n${C.b}warden detection bench${C.x}  (${SAMPLES.length} samples)\n`);
console.log(`${C.g}detection${C.x}:      ${mal.length - miss.length}/${mal.length} malicious blocked`);
console.log(`${C.r}false-positive${C.x}: ${fp.length}/${ben.length} benign over-flagged`);
console.log(`${C.y}under-gated${C.x}:    ${soft.length} risky actions slipped to allow`);
if (miss.length) console.log(`\n${C.r}MISSES (malicious not blocked):${C.x}\n  ${miss.join('\n  ')}`);
if (fp.length) console.log(`\n${C.r}FALSE POSITIVES (benign flagged):${C.x}\n  ${fp.join('\n  ')}`);
if (soft.length) console.log(`\n${C.y}UNDER-GATED (risky → allow):${C.x}\n  ${soft.join('\n  ')}`);
if (!miss.length && !fp.length && !soft.length) console.log(`\n${C.g}${C.b}clean — every sample classified as expected.${C.x}`);
console.log();
