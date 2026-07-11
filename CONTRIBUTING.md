# Contributing to redstamp

Thanks for your interest in improving **redstamp** — a deterministic, offline
firewall for AI-agent tool calls: green/yellow/red/black risk tiers, secret-exfil
and prompt-injection blocking, and a tamper-evident audit trail, plus **arena**,
an open agent-firewall benchmark. It runs as a Claude Code hook or an MCP proxy.
Part of [Own Your Agent Security](https://sprayberrylabs.com).

## Ground rules

- Be respectful. This project follows our [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a security issue? **Do not open a public issue** — follow
  [SECURITY.md](SECURITY.md) to report it privately.

## Development setup

redstamp is a Node.js package. You need Node.js **20 or 22** (the versions CI
tests against).

```bash
git clone https://github.com/askalf/redstamp.git
cd redstamp
npm ci        # install from the frozen lockfile
npm test      # run the full test suite (node --test)
```

## Making a change

1. Branch off `master`.
2. Keep the change focused — one concern per PR.
3. Add or update tests for any behavior change. redstamp guards a trust
   boundary, so changes to the risk classifier, the policy engine, the
   secret-exfil / prompt-injection defenses, or the MCP middleware must be
   covered by tests.
4. Run `npm test` locally before pushing.
5. Open a pull request against `master`.

## What CI requires

Every PR must pass these checks to merge:

- `test` on **ubuntu-latest** and **windows-latest** × Node **20** and **22**
  (the `test (<os>, <node>)` matrix)
- **CodeQL** static analysis (`analyze (javascript-typescript)`)

OpenSSF Scorecard and ClusterFuzzLite fuzzing also run on the repo; a discovered
crash or a new high-severity finding will block the change.

## Conventions

- GitHub Actions are **pinned to a commit SHA**, never a mutable tag. New or
  updated workflow steps must keep this.
- Commit messages: short imperative subject, with a wrapped body explaining the
  *why* when it isn't obvious.
- PRs are squash-merged, so your PR title becomes the commit subject on `master`.

## Releases

Releases are automated: bump `version` in `package.json` on `master` and
`auto-release.yml` tags it, cuts a GitHub release from `CHANGELOG.md`, and
publishes to npm via OIDC trusted publishing (no tokens). A normal PR needs no
release steps.
