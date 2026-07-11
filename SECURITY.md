# Security Policy

redstamp is a deterministic firewall between an autonomous agent and its tools. A
vulnerability here — a bypass, a crash in the host's hot path, or a tampered audit
— has outsized blast radius, so reports get priority attention.

## Reporting a vulnerability

Please **do not open a public issue** for security reports.

- **Preferred:** [GitHub private vulnerability reporting](https://github.com/askalf/redstamp/security/advisories/new) — creates a private advisory visible only to maintainers.
- **Email:** support@askalf.org with `redstamp security` in the subject.

You'll get an acknowledgement within 72 hours. Please include a minimal reproduction (an `action` JSON that is mis-classified, or an input that throws) where possible.

## Supported versions

redstamp is pre-1.0: only the latest release receives security fixes; there are no maintenance branches.

## In scope

Anything that breaks the core promise — every tool call gets a deterministic, reproducible verdict, and a black/red action never slips through as `allow`:

- **Bypass** — a catastrophic/destructive/exfil action (RCE, `rm -rf /`, secret + external destination, cloud-metadata SSRF, poisoned skill/MCP tool) that redstamp classifies as `allow`.
- **Crash / DoS** — any input that makes `check()`/`decide()` **throw into the host agent** or stall it (e.g. catastrophic regex backtracking) instead of returning a verdict.
- **Audit tampering** — an edit or deletion of a past audit entry that `verifyAuditFile()` fails to detect.
- **Scanner gap** — the secret/injection scanner failing to flag a pattern it documents as covered.

Out of scope: novel obfuscation that evades pattern detection is a *known limitation* (see "What it does NOT claim" below), not a vulnerability — the fix path is a corpus PR, not an advisory. Model behavior of the optional LLM judge is out of scope.

---

# Threat model

redstamp is a guard between an autonomous agent and its tools. It is **defense-in-depth, not a sandbox**: it shrinks blast radius and creates an audit trail; it does not replace OS-level isolation.

## What it defends against
Deterministically, per tool call:

- **Remote code execution** — `curl|sh` (incl. multi-hop pipelines through `tee`/`gunzip`/`xxd`), `base64 -d|sh`, `eval $(curl)`, PowerShell download-cradles / encoded commands, interpreter (python/perl) reverse shells, `/dev/tcp` & `nc -e` shells, git transport RCE (`ext::`, `core.sshCommand`, `--upload-pack`), exec-via-flag (`tar --checkpoint-action`, `find -exec`).
- **Destruction** — `rm -rf /`, `mkfs`, `dd` to a disk, fork bombs, `vssadmin delete shadows`, `DROP TABLE`, `terraform destroy`, `kubectl delete`, `docker rm -f`.
- **Secret exfiltration** — a secret/credential + an external destination in the same shell/network call; sensitive files piped to `nc`/`curl` or scp'd off-box; DNS exfil; **cloud-metadata SSRF** (`169.254.169.254` incl. decimal/hex/octal/IPv4-mapped-IPv6 encodings, `metadata.google.internal`); link-local & RFC1918 SSRF.
- **Persistence / backdoors** — `authorized_keys`, cron, systemd units, registry Run keys, backdoor admin accounts — caught in shell commands *and* when written via the file-write tool (shell-rc, `sudoers`, `ld.so.preload`, `profile.d`, Startup).
- **Security-disabling** — firewall flush, SELinux `setenforce 0`, Defender disable.
- **Container escape** — host-root mounts, `nsenter --target 1`, privileged containers.
- **Prompt injection / poisoned skills & MCP tools** — instruction-override / exfil instructions in skill text, tool inputs, an MCP server's advertised tool descriptions, or content an MCP server returns (`tools/call` results, `resources/read` bodies, `prompts/get` templates — the indirect-injection vectors).

## Tiers
`green` (read-only) → allow · `yellow` (reversible) → allow · `red` (destructive/outward) → approval · `black` (catastrophic/malicious) → block.

## What it does NOT claim
- **Not a sandbox.** An attacker with arbitrary code execution can evade pattern-based detection. redstamp raises the bar and records what happened; it is not a containment boundary — pair it with OS isolation for high-trust workloads.
- **Pattern + policy based** (plus an optional LLM judge for gray-zone calls). Novel obfuscation can slip through — which is exactly why the corpus + bench exist: every new evasion becomes a pattern. Coverage is *measured*, not assumed (`npm run bench`).
- It **classifies**; the integration (hook / wrapper / MCP proxy) **enforces**.

## Posture
- **Fail-safe in the Claude Code hook** — a redstamp error never blocks your tooling, and never silently stops screening: it falls back to the in-process check. A security tool that bricks the workflow gets ripped out; one that's quietly always-on stays. Tighten per-action with `strict` mode + `deny` rules.
- **Data at rest ≠ execution** — a secret or injection phrase in file *content* is flagged (red), not blocked; only execution or transmission escalates to black.
- **Tamper-evident audit at rest** — every decision is streamed hash-chained to disk; `verifyAuditFile()` detects any edited entry. Queryable via `redstamp audit`.
- **Authenticated daemon** — the shared daemon is reachable only with a capability token published into a `0600` file, so a local process can't abuse the judge tier (LLM calls) or pollute the audit. An unauthenticated caller is rejected and the hook falls back to its own in-process check (fail-safe).
- **No ReDoS** — every detection pattern is bounded; `bench/redos.mjs` times them all against adversarial input at the 16 KB cap (worst case <1ms), so a crafted input can't stall the hook into a fail-open timeout. Continuously re-checked by fuzzing (`fuzz/`, ClusterFuzzLite).

Coverage today: **245-sample labeled corpus across 19 attack families — 97% deterministic recall, 100% precision (0 false positives)** (`npm run bench`). The remaining ~3% is the evasion bucket (variable-indirection, `${IFS}`, encoded payloads) which redstamp routes to the optional LLM judge rather than guess. Three adversarial batteries (`bench/edgecases.mjs`, `bench/stress.mjs`, `bench/stress2.mjs`) exercise the boundaries.
