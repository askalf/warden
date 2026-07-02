// Extract warden's labeled detection corpus into a tool-AGNOSTIC JSON file that
// any agent-firewall can be scored against — not just warden. The ground truth
// (an agent action + the verdict a firewall SHOULD reach) is universal; only the
// `action` field uses warden's `{tool, input}` shape, which is a reasonable
// neutral representation of "an agent tool call" that any adapter can read.
//
// Run: node arena/build-corpus.mjs   → writes arena/corpus.json
//
// The corpus lives in ONE place (bench/corpus.mjs, warden's own bench). This
// generator is the single source of truth for the arena copy, so the two never
// drift: re-run it whenever the corpus changes (CI checks it is up to date).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SAMPLES } from '../bench/corpus.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);

// Deterministic builder — pure function of SAMPLES, so the committed corpus.json
// can be regenerated identically and a test can assert it hasn't drifted.
export function buildCorpus() {
  const seen = new Map();
  const corpus = SAMPLES.map((s) => {
    const family = s.family || 'misc';
    const n = (seen.get(family) || 0) + 1;
    seen.set(family, n);
    const input = s.action?.input || {};
    // A convenience text field for adapters that classify a single string
    // (most firewalls take a shell command or a URL). Full `action` is kept for
    // adapters that want the structured tool call (warden does).
    const command = input.command ?? input.url ?? input.path ?? null;
    return {
      // stable, human-readable id: family + zero-padded per-family index.
      id: `${family}/${String(n).padStart(2, '0')}-${slug(s.label)}`,
      family,
      label: s.label,
      // expect: what a correct firewall SHOULD do.
      //   block   → malicious; a firewall must NOT allow it (block, or at least gate).
      //   approve → risky/dual-use; should be gated for human approval, not silently allowed.
      //   allow   → benign; blocking it is a false positive.
      expect: s.expect,
      tool: s.action?.tool ?? null,
      command,
      action: s.action,
      ...(s.skill ? { skill: s.skill } : {}),
    };
  });

  // Integrity: ids must be unique, expect must be one of the three labels.
  const ids = new Set();
  for (const c of corpus) {
    if (ids.has(c.id)) throw new Error(`duplicate id: ${c.id}`);
    ids.add(c.id);
    if (!['block', 'approve', 'allow'].includes(c.expect)) throw new Error(`bad expect on ${c.id}: ${c.expect}`);
  }

  const families = [...new Set(corpus.map((c) => c.family))].sort();
  const counts = { block: 0, approve: 0, allow: 0 };
  for (const c of corpus) counts[c.expect]++;

  return {
    $schema: 'https://github.com/askalf/warden/arena — agent-firewall benchmark corpus',
    version: 1,
    generatedFrom: 'bench/corpus.mjs',
    total: corpus.length,
    families,
    counts,
    samples: corpus,
  };
}

export const CORPUS_PATH = path.join(here, 'corpus.json');
/** The exact bytes the committed corpus.json must contain. */
export const serialize = (obj) => JSON.stringify(obj, null, 2) + '\n';

// Write when run directly (not when imported by the drift-guard test).
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const out = buildCorpus();
  fs.writeFileSync(CORPUS_PATH, serialize(out));
  console.log(`wrote ${CORPUS_PATH}`);
  console.log(`  ${out.total} samples · ${out.families.length} families`);
  console.log(`  block ${out.counts.block} · approve ${out.counts.approve} · allow ${out.counts.allow}`);
}
