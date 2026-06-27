# Changelog

All notable changes to **@askalf/warden** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-06-27

### Fixed
- **Secret scanner — GitHub App / Actions tokens.** `scanSecrets` recognized
  `ghp_` / `gho_` / `github_pat_` but missed the GitHub App token family:
  `ghs_` (server-to-server — the `GITHUB_TOKEN` minted into **every** GitHub
  Actions run and the output of `actions/create-github-app-token`), `ghu_`
  (user-to-server), and `ghr_` (refresh). An agent exfiltrating a `ghs_` token
  to an external host therefore slipped the secret-exfil gate. This is the
  credential class stolen in the tj-actions/changed-files supply-chain attack
  (CVE-2025-30066). Now matched (`gh[sur]_[A-Za-z0-9]{30,}`) and blocked on
  egress; pinned by a regression test.

## [0.2.0] - 2026-06-15

First public release — own your agent security.

### Added
- **Deterministic risk classification** — `check()` / `decide()` sort any agent
  action into one of four tiers (green / yellow / red / black) from a fixed,
  offline rule set. No model call in the hot path, so the verdict is the same
  every run.
- **Policy** — `loadPolicy()` reads `~/.warden/config.json`; allow / approve /
  block decisions are policy-driven and overridable per tier.
- **Threat coverage** — secret-exfiltration and prompt-injection detection,
  catastrophic-filesystem and credential-theft patterns, with ReDoS-hardened
  matchers (bounded quantifiers; benchmarked under `npm run bench:redos`).
- **Tamper-evident audit** (`@askalf/warden/audit`) — every decision is
  hash-chained to disk; `verifyAuditFile()` detects any edit or deletion of a
  past entry.
- **MCP middleware** (`@askalf/warden/mcp`, `warden-mcp`) — wrap an MCP server
  to firewall tool calls, strip poisoned tools from `tools/list`, and neutralize
  prompt-injection returned in tool *results* (indirect injection). Tool/arg
  mapping is exfil-aware: a URL-bearing call is risk-checked as a fetch even when
  the tool is named like a reader, so SSRF / cloud-metadata access can't be
  hidden behind a benign name. The stdio proxy bounds its line buffer against a
  hostile peer (`npm run bench:mcp` red-teams all of this).
- **Claude Code hook** (`warden-hook`) — drop-in pre-tool-use guard.
- **Daemon + native fast client** (`warden-serve`, `@askalf/warden/client`) —
  a local decision server with a low-latency client for hot paths.
- **Optional LLM judge tier** (`@askalf/warden/judge`) — escalates only genuine
  gray-zone actions; the deterministic core decides everything else.
- **Fail-safe contract** — every entrypoint returns a verdict, never throws into
  the host: a null/non-object action, a non-string `tool`/`method`, a circular
  input, or a Symbol buried in a command/path/url array all classify safely
  instead of raising. The scanned text is bounded (64KB) so a giant input field
  can't turn a call into a heavy scan. Fuzzed at 2M malformed inputs with zero
  throws / zero invalid verdicts (`npm run bench:max`), worst-case regex timing
  under 50ms at 300KB, ~60k verdicts/sec (p99 ~60µs).

[0.2.0]: https://github.com/askalf/warden/releases/tag/v0.2.0
