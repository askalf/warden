# warden — threat model

warden is a guard between an autonomous agent and its tools. It is **defense-in-depth, not a sandbox**: it shrinks blast radius and creates an audit trail; it does not replace OS-level isolation.

## What it defends against
Deterministically, per tool call:

- **Remote code execution** — `curl|sh` (incl. multi-hop pipelines through `tee`/`gunzip`/`xxd`), `base64 -d|sh`, `eval $(curl)`, PowerShell download-cradles / encoded commands, interpreter (python/perl) reverse shells, `/dev/tcp` & `nc -e` shells, git transport RCE (`ext::`, `core.sshCommand`, `--upload-pack`), exec-via-flag (`tar --checkpoint-action`, `find -exec`).
- **Destruction** — `rm -rf /`, `mkfs`, `dd` to a disk, fork bombs, `vssadmin delete shadows`, `DROP TABLE`, `terraform destroy`, `kubectl delete`, `docker rm -f`.
- **Secret exfiltration** — a secret/credential + an external destination in the same shell/network call; sensitive files piped to `nc`/`curl` or scp'd off-box; DNS exfil; **cloud-metadata SSRF** (`169.254.169.254` incl. decimal/hex/octal/IPv4-mapped-IPv6 encodings, `metadata.google.internal`); link-local & RFC1918 SSRF.
- **Persistence / backdoors** — `authorized_keys`, cron, systemd units, registry Run keys, backdoor admin accounts — caught in shell commands *and* when written via the file-write tool (shell-rc, `sudoers`, `ld.so.preload`, `profile.d`, Startup).
- **Security-disabling** — firewall flush, SELinux `setenforce 0`, Defender disable.
- **Container escape** — host-root mounts, `nsenter --target 1`, privileged containers.
- **Prompt injection / poisoned skills & MCP tools** — instruction-override / exfil instructions in skill text, tool inputs, or an MCP server's advertised tool descriptions.

## Tiers
`green` (read-only) → allow · `yellow` (reversible) → allow · `red` (destructive/outward) → approval · `black` (catastrophic/malicious) → block.

## What it does NOT claim
- **Not a sandbox.** An attacker with arbitrary code execution can evade pattern-based detection. warden raises the bar and records what happened; it is not a containment boundary — pair it with OS isolation for high-trust workloads.
- **Pattern + policy based** (plus an optional LLM judge for gray-zone calls). Novel obfuscation can slip through — which is exactly why the corpus + bench exist: every new evasion becomes a pattern. Coverage is *measured*, not assumed (`npm run bench`).
- It **classifies**; the integration (hook / wrapper / MCP proxy) **enforces**.

## Posture
- **Fail-open in the Claude Code hook** — a warden error never blocks your tooling. A security tool that bricks the workflow gets ripped out; one that's quietly always-on stays. Tighten per-action with `strict` mode + `deny` rules.
- **Data at rest ≠ execution** — a secret or injection phrase in file *content* is flagged (red), not blocked; only execution or transmission escalates to black.
- **Tamper-evident audit at rest** — every decision is streamed hash-chained to disk; `verifyAuditFile()` detects any edited entry. Queryable via `warden audit`.
- **Authenticated daemon** — the shared daemon is reachable only with a capability token published into a `0600` file, so a local process can't abuse the judge tier (LLM calls) or pollute the audit. An unauthenticated caller is rejected and the hook falls back to its own in-process check (fail-safe).
- **No ReDoS** — every detection pattern is bounded; `bench/redos.mjs` times them all against adversarial input at the 16 KB cap (worst case <1ms), so a crafted input can't stall the hook into a fail-open timeout.

Coverage today: **234-sample labeled corpus across 19 attack families — 96% deterministic recall, 100% precision (0 false positives)** (`npm run bench`). The ~4% gap is the evasion bucket (variable-indirection, `${IFS}`, encoded payloads) which warden routes to the optional LLM judge rather than guess. Three adversarial batteries (`bench/edgecases.mjs`, `bench/stress.mjs`, `bench/stress2.mjs`) exercise the boundaries.
