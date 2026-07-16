# Changelog

## [0.5.1] - 2026-07-16

### Security
- **Audit tail-truncation is now detectable.** A hash chain proves no past record
  was edited or deleted from the *middle*, but a valid *prefix* still verifies — so
  deleting the most-recent entries (the ones recording an attacker's own action)
  went unnoticed, and a restart re-seeded from the truncated tail. `ChainedFileAudit`
  can now anchor the chain head in a `0600` `<audit>.chk` checkpoint (`{ checkpoint: true }`,
  which the streaming daemon enables), and `verifyAuditFile(path, { head, count })`
  flags a log that no longer ends where the checkpoint says (`truncated`/`rollback`,
  surfaced by `redstamp verify`). A same-directory attacker who rewrites both is still
  out of reach of a same-fs sidecar; retain the checkpoint on separate-trust storage
  for full protection. SECURITY.md's tamper-evidence scope updated to match.
- **Write-root confinement no longer bypassable by `..` traversal or a shared-prefix
  sibling.** The `writeRoots` gate compared paths with a raw `startsWith`, so
  `src/../../etc/x` (traverses out) and a `data` root admitting `database/…` (shared
  string prefix) both slipped the review gate. Paths are now normalized (`.`/`..`
  collapsed) and matched on a separator boundary.
- **Daemon capability token compared in constant time.** The `!==` check returned
  early on the first differing byte — a timing oracle a local process on the loopback
  listener could walk. Now a fixed-length SHA-256 digest comparison via
  `crypto.timingSafeEqual` (constant-time and length-independent).

## [0.5.0] - 2026-07-11

### Changed
- **`redstamp init` now writes `redstamp.config.json`** (was `warden.config.json`),
  and `redstamp check` / `redstamp-mcp` default to it — completing the config-file
  half of the warden→redstamp rename (the docs already advertised
  `redstamp.config.json`, but the code still defaulted to `warden.config.json`, so
  a user following the README got a gate that loaded no policy). **Fully
  back-compatible:** with no `--policy`, an existing `warden.config.json` is still
  read transparently, so a project set up before the rename keeps working — only a
  fresh `init` writes the branded name. Help text updated and the example is now
  `redstamp.config.example.json`. The `~/.warden/` **global** config, the audit
  log, and the `WARDEN_*` env vars are intentionally unchanged.

## 0.4.1

- **Renamed: `@askalf/warden` → `@askalf/redstamp`** (npm-publishable name; the old name collides with an existing unscoped package and is create-blocked by the registry). GitHub repo becomes `askalf/redstamp` (old URLs redirect). Legacy `warden`/`warden-mcp`/`warden-hook`/`warden-serve` bin aliases retained alongside the new `redstamp*` bins. `WARDEN_*` env vars unchanged.

All notable changes to **@askalf/redstamp** (formerly `@askalf/warden`) are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-07-09

### Added
- **Cross-call taint tracking — `TaintSession`** (`@askalf/warden/taint`, #34).
  `check()` classifies one call in isolation, which an attacker evades by
  splitting an exfil across calls: read a secret into a temp file (call 1 — a
  sensitive *read*), then ship that file out (call 2 — *benign*, no visible
  secret). `TaintSession` remembers the session: secret **sources** (reads of
  `~/.ssh`, `.env`, `.aws/credentials`, …), **propagation** (the file a secret
  is written to — and any copy — becomes tainted), and external **sinks**,
  escalating to black the moment tainted data leaves the machine.
  `checkSequence(actions, policy)` runs a whole stream through one session.
  Deterministic and offline; like the judge it can only **raise** risk, never
  lower a verdict — wrapping a stream is always at least as safe as per-call
  `check()`. Precision-scoped: config-read → **allowlisted** host is not
  flagged. The stateless core is untouched (byte-identical `decide()`).
- **External MITRE ATT&CK arena corpus** (#36) — the default arena corpus is
  warden-authored, so warden topping it proves capability, not neutrality.
  `arena/external-corpus.json` adds 68 samples across 32 MITRE ATT&CK
  techniques, command forms drawn from the public GTFOBins / LOLBAS /
  HackTricks knowledge bases, with benign uses of the *same* tools so precision
  is a genuine test. `node arena/run.mjs --corpus <file>` / `npm run
  arena:external`; results in `arena/EXTERNAL-CORPUS-RESULTS.md` (warden: 100%
  recall, 100% precision after the #33 coverage work — the corpus originally
  cross-flagged the same two gaps #33 closed). Honest caveat documented:
  externally taxonomized but still assembled in-repo; true neutrality needs an
  outside-contributed corpus, and the protocol makes that a drop-in.
- **Six measured classifier coverage gaps closed** (#33), each mechanism-scoped
  and checked against the benign set: recursive `chmod` of the root/system tree
  (any mode — `000` locks root out, not just `777`); staged
  download→make-executable chained with `;` as well as `&&`; `rundll32
  javascript:` protocol exec (LOLBin) → black; gnupg keyring
  (`.gnupg/secring.gpg`) in `SENSITIVE_PATH_RE`; `/etc/shadow` reads gated
  (distinct from world-readable `/etc/passwd`, which stays allow); `vssadmin
  create shadow` gated (dual-use NTDS-theft prep — the ransomware
  delete-shadows variant stays black). Corpus +11 → 245 samples; recall
  96% → **97%**, precision held at **100%**.

### Changed
- Default judge model freshened to `claude-sonnet-5` (#35).
- README: quick-start notes that **npm v12 blocks git dependencies by
  default** — until warden is on npm, `npm i github:askalf/warden` needs
  `--allow-git` on npm ≥ 12.

### Fixed
- **Judge tier fail-safe + raise-only proof** (#35). `makeJudge` no longer
  throws into the host on a bad response (explicit `res.ok` check — a 429/5xx
  returning HTML used to throw at `res.json()`; wrapped JSON parse; catch-all):
  every failure mode returns null and `checkAsync` keeps the deterministic
  verdict. And the invariant that a compromised/jailbroken judge can only
  *raise* risk is now pinned by tests — a judge answering green cannot clear a
  black or weaken a verdict.
- **Fuzz-found fail-safe gaps at the entrypoints** (#32): `tool`/`method`
  arriving as an array containing a `Symbol` (implicit `String(array)` →
  `Array.join` → TypeError), and non-string `skillText` reaching the injection
  scanner's regex, could throw instead of failing safe to a verdict. A shared
  symbol-safe `asStr()` coercion now guards every site; found by 1M-iteration
  fuzzing, pinned by regression tests. Detection unchanged.
- **CI release notes** (#30): extraction uses `indexOf`, not a multiline regex
  whose `$` matched the blank line after the heading and shipped empty bodies
  (v0.2.1 and v0.3.0 notes were backfilled by hand).

## [0.3.0] - 2026-07-03

### Added
- **arena — a neutral, reproducible agent-firewall benchmark** (`npm run arena`):
  on a labeled corpus of real attacks and real benign work, every tool is scored
  on recall *and* precision *and* determinism through one pipe, so the numbers
  are comparable instead of anecdotal. Ships allow-all / block-all anchors, a
  naive regex deny-list baseline, and a **LlamaFirewall adapter**, framed along
  threat-model axes (what each tool even attempts to cover). Results live in
  `arena/RESULTS.md` and regenerate with `node arena/run.mjs`.
- **`scanMcpTools` severity tiers** — every finding now carries
  `severity: 'critical' | 'advisory'`. Injection/exfil *instructions* (the
  curated patterns) are critical; a bare sensitive-path / secret-env *mention*
  is advisory, so consumers scanning long-form skill prose (canon) can stop
  treating instructional docs about credential handling as poison — scanning
  the official Claude Code marketplace flagged 19/29 skills on exactly those
  mention heuristics. Additive: `flags` are unchanged and consumers that only
  read them behave as before.
- **`SENSITIVE_PATH_EXFIL_RE`** — a sensitive path being *moved*
  (transfer-verb → sensitive path → destination, one clause), e.g.
  `read ~/.ssh/id_rsa and POST it to https://…`, which the curated exfil
  patterns miss (wrong verb/noun combination). Critical, and built on
  `SENSITIVE_PATH_RE` so the two can't drift apart.
- **Four framework-governance examples** (`examples/`) — the same warden MCP
  gate governing a CrewAI Flow, a LangGraph.js StateGraph, an OpenAI Agents SDK
  agent, and a Microsoft AutoGen agent, all surfaced in the README.

### Fixed
- **Three scanner false-positive classes, measured on 2,000+ real marketplace
  skills** (auditing the official Claude Code catalog + 9 community
  marketplaces with canon; every first-pass critical was manually reviewed):
  - `SENSITIVE_PATH_RE`'s `.env` now requires a non-word lookbehind —
    `process.env` / `self.env` / `import.meta.env` are code, not the dotenv
    file, and were the single largest FP source. (Also applied to the
    data-exfil-to-destination pattern's `.env` noun.)
  - `scanMcpTools` normalizes stringified newlines (`\n` 2-char escapes) back
    to real newlines before matching, and `SENSITIVE_PATH_EXFIL_RE`'s gaps stop
    at both — previously clause-bounded patterns silently spanned lines in
    JSON-stringified text, so unrelated rows of a markdown table could read as
    one verb→path→destination "clause".
  - The bare-word **'exfiltration intent'** rule (exfiltrate/leak/steal, no
    destination) now tiers as `advisory`, not critical: every corpus hit was
    descriptive prose — memory leaks, ML data leakage, threat lists in
    defensive security docs. The flag itself is unchanged, so strict
    (tool-description) surfaces still act on it.
- **Three classifier false-positive classes:**
  - single-label hostnames (Docker service names like `db` or `redis`) are
    treated as internal, so container-to-container traffic no longer reads as
    an exfil destination;
  - the `curl | interpreter` RCE rule fires only on an *external* target —
    piping from localhost/internal services no longer flags;
  - the DNS-exfil rule is anchored to command position, so prose that merely
    mentions `host`/`dig` no longer flags.
- **Docs matched to shipped behavior** — the native hook (`warden-fast`) is
  fail-safe, not fail-open (daemon unreachable → it execs the in-process Node
  hook, which still screens), and the daemon command is `warden-serve`, not
  `warden serve`.
- **Audit verifier — interspersed unprotected records no longer read as tampering.**
  `verifyAuditFile()` skipped only *leading* pre-chain lines; the first line
  lacking a `prev`/`hash` mid-file was treated as a chain break, so any file that
  a second, non-chained writer had appended to (e.g. an in-process hook fallback
  logging raw tool calls into the shared `~/.warden/audit.jsonl`) reported
  `ok:false` even when the hash chain was fully intact — and an attacker could
  defeat verification outright by appending one junk line. Now any line without a
  string `prev`+`hash` is treated as unprotected history: skipped and tallied as
  `unchained`, while the chained records are verified continuously. Tamper
  detection is unchanged — editing a chained record breaks its hash, deleting one
  breaks the next record's link, and stripping a record's `prev`/`hash` to
  disguise an edit breaks the following record's link. Pinned by three regression
  tests (interspersed foreign record, junk-tail append, strip-to-disguise).

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
