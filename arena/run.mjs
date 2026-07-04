// Arena runner — score every registered agent-firewall over the same labeled
// corpus, with the same metrics, through the same stdin/stdout pipe
// (see protocol.md). Emits a markdown table (RESULTS.md) + full JSON
// (results.json), and prints a summary.
//
//   node arena/run.mjs                # all available adapters, default corpus
//   node arena/run.mjs --adapter warden,deny-list
//   node arena/run.mjs --runs 1       # skip the determinism double-run
//   node arena/run.mjs --corpus external-corpus.json  # score an alternate corpus
//       (results write to <basename>-results.json + <BASENAME>-RESULTS.md so the
//        default RESULTS.md/results.json are never clobbered)
//
// The adapter sees only the action, never the label: `expect`/`family`/`label`
// are stripped before feeding, so nothing can read the answer key.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, '..');

const arg = (name, d) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : d; };
const corpusFile = arg('--corpus', 'corpus.json');
const isDefault = corpusFile === 'corpus.json';
const mdOut = isDefault ? 'RESULTS.md' : path.basename(corpusFile).replace(/\.json$/, '').toUpperCase() + '-RESULTS.md';
const jsonOut = isDefault ? 'results.json' : path.basename(corpusFile).replace(/\.json$/, '') + '-results.json';

const corpus = JSON.parse(fs.readFileSync(path.join(here, corpusFile), 'utf8'));
const registry = JSON.parse(fs.readFileSync(path.join(here, 'adapters.json'), 'utf8'));

const only = (arg('--adapter', '') || '').split(',').map((s) => s.trim()).filter(Boolean);
const RUNS = Number(arg('--runs', '2')) === 1 ? 1 : 2;

// What the adapter is allowed to see — the action, never the ground truth.
const feed = corpus.samples.map((s) => ({ id: s.id, tool: s.tool, command: s.command, action: s.action, ...(s.skill ? { skill: s.skill } : {}) }));
const jsonl = feed.map((s) => JSON.stringify(s)).join('\n') + '\n';

// Spawn an adapter, feed the corpus on stdin, collect verdicts keyed by id.
// Resolves { ok:false, reason } if the command can't be spawned.
function runAdapter(a) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(a.cmd[0], a.cmd.slice(1), { cwd: repoRoot, stdio: ['pipe', 'pipe', 'inherit'] });
    } catch (e) {
      return resolve({ ok: false, reason: String((e && e.message) || e) });
    }
    let out = '';
    let spawnErr = null;
    child.on('error', (e) => { spawnErr = e; });
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', () => {
      if (spawnErr) return resolve({ ok: false, reason: String(spawnErr.message || spawnErr) });
      const verdicts = new Map();
      for (const line of out.split('\n')) {
        const t = line.trim();
        if (!t) continue;
        try { const v = JSON.parse(t); if (v && v.id) verdicts.set(v.id, v); } catch { /* ignore noise */ }
      }
      resolve({ ok: true, verdicts });
    });
    child.stdin.on('error', () => {}); // adapter may exit early; don't crash the runner
    child.stdin.write(jsonl);
    child.stdin.end();
  });
}

const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const pctlist = (xs, p) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};

function score(verdicts) {
  const mal = [], ben = [], risk = [];
  let errored = 0;
  const famBlock = new Map(); // family -> {tot, hit}
  const lat = [];
  for (const s of corpus.samples) {
    const v = verdicts.get(s.id);
    if (!v || v.error) { errored++; }
    const blocked = !!(v && v.blocked && !v.error);
    const gated = !!(v && v.gated && !v.error);
    const prevented = blocked || gated;
    if (v && typeof v.ms === 'number') lat.push(v.ms);
    if (s.expect === 'block') {
      mal.push(s);
      const f = famBlock.get(s.family) || { tot: 0, hit: 0 };
      f.tot++; if (prevented) f.hit++;
      famBlock.set(s.family, f);
      s._blocked = blocked; s._prevented = prevented;
    } else if (s.expect === 'allow') {
      ben.push(s); s._blocked = blocked; s._gated = gated;
    } else if (s.expect === 'approve') {
      risk.push(s); s._prevented = prevented;
    }
  }
  const malBlocked = mal.filter((s) => s._blocked).length;
  const malPrevented = mal.filter((s) => s._prevented).length;
  const fp = ben.filter((s) => s._blocked).length;
  const benGated = ben.filter((s) => s._gated).length;
  const underGate = risk.filter((s) => !s._prevented).length;
  return {
    malicious: mal.length, benign: ben.length, risky: risk.length,
    recallBlock: malBlocked / mal.length,
    recallPrevent: malPrevented / mal.length,
    precision: (ben.length - fp) / ben.length,
    falsePositives: fp,
    benignFriction: benGated,
    underGate,
    underGateRate: risk.length ? underGate / risk.length : 0,
    errored,
    latencyMedianMs: median(lat),
    latencyP99Ms: pctlist(lat, 99),
    perFamilyBlockRecall: Object.fromEntries([...famBlock].sort().map(([k, f]) => [k, f.hit / f.tot])),
  };
}

// Two verdict maps are "identical" if every sample's (blocked,gated,tier) matches.
function sameVerdicts(a, b) {
  if (a.size !== b.size) return false;
  for (const [id, v] of a) {
    const w = b.get(id);
    if (!w) return false;
    if (!!v.blocked !== !!w.blocked || !!v.gated !== !!w.gated || (v.tier || '') !== (w.tier || '')) return false;
  }
  return true;
}

const chosen = registry.adapters.filter((a) => !only.length || only.includes(a.id));
const results = [];
for (const a of chosen) {
  const r1 = await runAdapter(a);
  if (!r1.ok) { results.push({ ...a, available: false, reason: r1.reason }); console.error(`- ${a.id}: unavailable (${r1.reason})`); continue; }
  // Spawned but emitted no verdicts = the tool isn't installed/configured (its
  // adapter exited early). Mark unavailable rather than scoring a misleading 0%.
  if (r1.verdicts.size === 0) { results.push({ ...a, available: false, reason: 'no verdicts — tool not installed/configured' }); console.error(`- ${a.id}: unavailable (no verdicts)`); continue; }
  let observedDeterministic = null;
  if (RUNS === 2) {
    const r2 = await runAdapter(a);
    observedDeterministic = r2.ok ? sameVerdicts(r1.verdicts, r2.verdicts) : null;
  }
  results.push({ ...a, available: true, observedDeterministic, ...score(r1.verdicts) });
}

// ---- emit ----
const pf = (x) => (x == null ? '—' : (100 * x).toFixed(1) + '%');
const yn = (b) => (b == null ? '—' : b ? 'yes' : 'no');
const det = (a) => {
  if (a.observedDeterministic == null) return a.deterministic ? 'yes*' : 'no*';
  return a.observedDeterministic ? 'yes' : (a.deterministic ? '**NO (declared yes!)**' : 'no');
};

const avail = results.filter((r) => r.available);
const head = [
  '| firewall | offline | deterministic | recall (block) | recall (+gate) | precision | under-gate | median µs |',
  '|---|---|---|---|---|---|---|---|',
];
const rows = avail.map((r) =>
  `| ${r.name} | ${yn(r.offline)} | ${det(r)} | ${pf(r.recallBlock)} | ${pf(r.recallPrevent)} | ${r.precision === 1 ? '**100%**' : pf(r.precision)} | ${r.underGate}/${r.risky} | ${r.latencyMedianMs == null ? '—' : (r.latencyMedianMs * 1000).toFixed(0)} |`
);

const md = [
  '# Arena results',
  '',
  `Corpus: **${corpus.total} samples** · ${corpus.families.length} families · ${corpus.counts.block} malicious / ${corpus.counts.approve} risky / ${corpus.counts.allow} benign.`,
  corpus.provenance ? `> ${corpus.provenance}` : '',
  `Scored ${avail.length} firewall(s) through the same stdin/stdout pipe (see [protocol.md](protocol.md)). Regenerate: \`node arena/run.mjs${isDefault ? '' : ' --corpus ' + corpusFile}\`.`,
  '',
  ...head,
  ...rows,
  '',
  '- **recall (block)** — malicious actions hard-blocked. **recall (+gate)** — blocked *or* escalated to a human.',
  '- **precision** — benign actions NOT blocked (100% = zero false positives). **under-gate** — risky actions silently allowed.',
  '- **deterministic** — identical verdicts across two scoring passes (`*` = not re-run this pass; declared value shown).',
  '- **median µs** — self-reported decision latency; comparable only among offline, same-host tools (a cloud tool includes network RTT).',
  '',
  '_The `allow-all` and `block-all` rows are sanity anchors: allow-all pins 0% recall, block-all pins 100% recall at 0% precision — which is why recall is meaningless without precision beside it._',
  '',
].join('\n');

fs.writeFileSync(path.join(here, mdOut), md);
fs.writeFileSync(path.join(here, jsonOut), JSON.stringify({ corpus: { total: corpus.total, families: corpus.families, counts: corpus.counts }, results }, null, 2) + '\n');

// console summary
console.log(`\narena (${corpusFile}) — ${corpus.total} samples, ${avail.length} firewall(s)\n`);
for (const r of avail) {
  console.log(`  ${r.name.padEnd(28)} recall ${pf(r.recallBlock).padStart(6)} (+gate ${pf(r.recallPrevent).padStart(6)})  precision ${pf(r.precision).padStart(6)}  under-gate ${r.underGate}/${r.risky}  determ ${det(r)}`);
}
const unavail = results.filter((r) => !r.available);
if (unavail.length) console.log(`\n  unavailable: ${unavail.map((r) => r.id).join(', ')} (not installed / no key — expected for roadmap tools)`);
console.log(`\nwrote ${mdOut} + ${jsonOut}\n`);
