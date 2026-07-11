#!/bin/bash -eu
# Build the Jazzer.js fuzz targets for ClusterFuzzLite / OSS-Fuzz.
# Each target is an ESM module exporting `fuzz(data)`; the invariant is
# redstamp's headline guarantee — the classifier/scanner sits in the host
# agent's hot path on every tool call and must NEVER throw into the agent on
# arbitrary bytes, and must always return a well-formed verdict.
#
# redstamp's runtime is zero-dependency, so Jazzer lives in a fuzz-only
# manifest under .clusterfuzzlite/ — hash-pinned by its committed lockfile
# (`npm ci` verifies every integrity hash; Scorecard Pinned-Dependencies) and
# never added to the project's own package.json or the published tarball.
cd "$SRC/redstamp"
(cd .clusterfuzzlite && npm ci --no-audit --no-fund)
# compile_javascript_fuzzer executes node_modules/@jazzer.js/core/dist/cli.js
# relative to the project root, so move the fuzz-only install there.
mv .clusterfuzzlite/node_modules node_modules

for target in classify scan_mcp inject; do
  compile_javascript_fuzzer redstamp "fuzz/${target}.fuzz.js" --sync
done
