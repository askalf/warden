import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildCorpus, CORPUS_PATH, serialize } from '../arena/build-corpus.mjs';
import { buildExternalCorpus, EXTERNAL_CORPUS_PATH } from '../arena/build-external-corpus.mjs';

// The committed arena/corpus.json is generated from bench/corpus.mjs. This guards
// against drift: if the source corpus changes and corpus.json isn't regenerated,
// the benchmark would score stale data. Regenerate with `node arena/build-corpus.mjs`.
// Compare EOL-normalized content, not raw bytes — the guard is about corpus drift
// (samples added/changed), not line endings, and Windows autocrlf checks the file
// out as CRLF while the generator emits LF. (.gitattributes also pins it to LF.)
const normEol = (s) => s.replace(/\r\n/g, '\n');
test('arena/corpus.json is in sync with the source corpus', () => {
  const onDisk = normEol(fs.readFileSync(CORPUS_PATH, 'utf8'));
  const fresh = normEol(serialize(buildCorpus()));
  assert.equal(onDisk, fresh, 'arena/corpus.json is stale — run `node arena/build-corpus.mjs`');
});

test('arena/external-corpus.json is in sync with its generator', () => {
  const onDisk = normEol(fs.readFileSync(EXTERNAL_CORPUS_PATH, 'utf8'));
  const fresh = normEol(serialize(buildExternalCorpus()));
  assert.equal(onDisk, fresh, 'arena/external-corpus.json is stale — run `node arena/build-external-corpus.mjs`');
});

for (const [name, build] of [['default', buildCorpus], ['external', buildExternalCorpus]]) {
  test(`arena ${name} corpus has unique ids and valid labels`, () => {
    const c = build();
    const ids = new Set();
    for (const s of c.samples) {
      assert.ok(!ids.has(s.id), `duplicate id ${s.id}`);
      ids.add(s.id);
      assert.ok(['block', 'approve', 'allow'].includes(s.expect), `bad expect ${s.expect}`);
      assert.ok(s.action && typeof s.action === 'object', `missing action on ${s.id}`);
    }
    assert.equal(c.total, c.samples.length);
    assert.equal(c.counts.block + c.counts.approve + c.counts.allow, c.total);
  });
}
