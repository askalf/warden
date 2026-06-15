# warden — threat model

warden is a guard between an autonomous agent and its tools. It is **defense-in-depth, not a sandbox**: it shrinks blast radius and creates an audit trail; it does not replace OS-level isolation.

## What it defends against
Deterministically, per tool call:

- **Remote code execution** — `curl|sh`, `base64 -d|sh`, `eval $(curl)`, PowerShell download-cradles / encoded commands, interpreter (python/perl) reverse shells, `/dev/tcp` & `nc -e` shells.
- **Destruction** — `rm -rf /`, `mkfs`, `dd` to a disk, fork bombs, `vssadmin delete shadows`, `DROP TABLE`, `terraform destroy`, `kubectl delete`, `docker rm -f`.
- **Secret exfiltration** — a secret/credential + an external destination in the same shell/network call; sensitive files piped to `nc`/`curl` or scp'd off-box; DNS exfil; **cloud-metadata SSRF** (`169.254.169.254`, `metadata.google.internal`).
- **Persistence / backdoors** — `authorized_keys`, cron, systemd units, registry Run keys, backdoor admin accounts.
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
- Every decision is written to a queryable audit log (`warden audit`).

Coverage today: **80-sample labeled corpus across 8 attack families — 100% catch, 0% false positives** (`npm run bench`).
