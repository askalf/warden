#!/bin/bash -eu
# Build the Jazzer.js fuzz targets for ClusterFuzzLite / OSS-Fuzz.
# Each target is an ESM module exporting `fuzz(data)`; the invariant is
# redstamp's headline guarantee — the classifier/scanner sits in the host
# agent's hot path on every tool call and must NEVER throw into the agent on
# arbitrary bytes, and must always return a well-formed verdict.
#
# redstamp's runtime is zero-dependency, so Jazzer is installed --no-save here
# (fuzz-only, never added to package.json or the published tarball).
cd "$SRC/redstamp"
npm install --no-save --no-audit --no-fund @jazzer.js/core@^4

for target in classify scan_mcp inject; do
  compile_javascript_fuzzer redstamp "fuzz/${target}.fuzz.js" --sync
done
