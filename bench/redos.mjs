// ReDoS guard — time every classifier/scanner regex against adversarial inputs
// at the 16KB input cap. Flags any pattern that exceeds a per-pattern budget.
// Run: node bench/redos.mjs
import { BLACK_SHELL, RED_SHELL, YELLOW_SHELL } from '../src/classify.mjs';
import { SECRET_RE, INJECTION_RE, OBFUSCATION_RE, METADATA_RE, SENSITIVE_PATH_RE, PERSISTENCE_PATH_RE, SECRET_ENV_RE, URL_RE } from '../src/scan.mjs';

const N = 16384;                       // the classifier's input cap
const evilStrings = [
  'a'.repeat(N),
  ('a'.repeat(N / 2)) + '!',
  'rm -' + 'r'.repeat(N),
  'curl ' + 'a'.repeat(N),
  'scp ' + '-a '.repeat(N / 4),
  ('/' + 'a'.repeat(50)).repeat(N / 51),
  ('\\x41').repeat(N / 4),
  ('$a').repeat(N / 2),
  'base64 ' + 'a'.repeat(N) + ' | ',
  ('http://' + 'a'.repeat(40) + '/ ').repeat(N / 50),
  ('a=b;'.repeat(N / 4)),
  ('rm --recursive --force ' + 'a'.repeat(N)),
  ('git ' + 'a'.repeat(N)),
  ('tar ' + 'a'.repeat(N)),
];

const all = [
  ...BLACK_SHELL.map((p, i) => ['BLACK[' + i + ']', p.re, p.why]),
  ...RED_SHELL.map((p, i) => ['RED[' + i + ']', p.re, p.why]),
  ...YELLOW_SHELL.map((p, i) => ['YELLOW[' + i + ']', p.re, p.why]),
  ...SECRET_RE.map((p, i) => ['SECRET[' + i + ']', p.re, p.why]),
  ...INJECTION_RE.map((p, i) => ['INJ[' + i + ']', p.re, p.why]),
  ...OBFUSCATION_RE.map((p, i) => ['OBF[' + i + ']', p.re, p.why]),
  ['METADATA', METADATA_RE, ''], ['SENSITIVE_PATH', SENSITIVE_PATH_RE, ''],
  ['PERSISTENCE', PERSISTENCE_PATH_RE, ''], ['SECRET_ENV', SECRET_ENV_RE, ''], ['URL', URL_RE, ''],
];

const BUDGET = 25; // ms per (pattern × worst input)
let worstMs = 0, worstName = '', flagged = 0;
for (const [name, re, why] of all) {
  for (const s of evilStrings) {
    const r = new RegExp(re.source, re.flags.replace('g', '')); // avoid lastIndex statefulness
    const t = process.hrtime.bigint();
    r.test(s);
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    if (ms > worstMs) { worstMs = ms; worstName = name + ' :: ' + why; }
    if (ms > BUDGET) { flagged++; console.log(`⚠ ${ms.toFixed(1)}ms  ${name}  ${why}  (input ${s.slice(0, 14)}…)`); }
  }
}
console.log(`\n${all.length} patterns × ${evilStrings.length} adversarial inputs @ ${N}B`);
console.log(`worst: ${worstMs.toFixed(2)}ms (${worstName})`);
console.log(flagged ? `❌ ${flagged} pattern×input over ${BUDGET}ms budget` : `✅ all under ${BUDGET}ms — no catastrophic backtracking`);
