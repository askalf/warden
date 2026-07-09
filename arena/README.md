# arena — an agent-firewall benchmark

> A neutral, reproducible way to measure the thing "agent security" tools all
> claim and almost none quantify: **on a labeled corpus of real attacks and real
> benign work, what do you catch, what do you break, and do you answer the same
> way twice?**

Every agent firewall demos a curated win — "look, it blocked `rm -rf /`." Almost
none publish **recall _and_ precision _and_ determinism** on an open, labeled
corpus. Recall alone is meaningless (a firewall that blocks everything scores
100%); precision alone is meaningless (one that blocks nothing scores 100%). The
arena scores every tool on all of it, through one pipe, so the numbers are
comparable instead of anecdotal.

## Results

See **[RESULTS.md](RESULTS.md)** (regenerate any time with `node arena/run.mjs`,
or re-run the [Arena workflow](../.github/workflows/arena.yml) — the committed
tables are CI-generated, all rows scored on the same neutral host).

| firewall | recall (block) | precision | under-gate | deterministic |
|---|---|---|---|---|
| **warden** (default, offline) | **96.5%** | **100%** | 1/35 | yes |
| regex deny-list (naive baseline) | 15.4% | 98.5% | 35/35 | yes |
| **Pipelock** v3.0.0 (scan API, out-of-box) | 7.0% | 95.5% | 29/35 | yes |
| allow-all (null) | 0% | 100% | 35/35 | yes |
| block-all (paranoid) | 100% | 0% | 0/35 | yes |

The two anchors are the point: **block-all** gets perfect recall by blocking all
your real work; **allow-all** gets perfect precision by catching nothing. A
useful firewall is the one that keeps recall high *and* precision at 100% — which
is why both columns are always shown together.

Read the Pipelock row through the axes map below, not as a head-to-head loss:
its per-family results are exactly its declared shape — it catches **exfil**
(40%) and **poisoned-skill injection** (80%), the families where a credential or
injection string is present in the call, and scores zero on shell-*semantics*
families (`rm -rf /` carries no credential or URL — Pipelock's primary
enforcement for those lives at its egress wire, and an operator-written
`mcp_tool_policy` would move its number substantially). The row answers one
narrow, honest question: *out of the box, what does each tool's per-call verdict
surface catch on this corpus?*

## What's measured, and why each matters

The corpus (`corpus.json`, 245 samples, 19 attack families) labels every sample
by what a correct firewall **should** do — `block` (malicious), `approve`
(risky / dual-use, escalate to a human), or `allow` (benign). Then, per tool:

- **Recall (block)** — of the malicious actions, how many were hard-blocked. The
  headline "does it catch attacks" number.
- **Recall (block + gate)** — blocked *or* escalated to a human. A tool that
  escalates rather than hard-blocks still stopped silent execution, so it isn't
  scored as a miss.
- **Precision** — of the benign actions, how many it did **not** block. `100%` =
  zero false positives. This is the number that decides whether anyone leaves the
  firewall turned on; a noisy firewall gets disabled, and a disabled firewall has
  0% real-world recall.
- **Under-gate** — risky/dual-use actions silently allowed (neither blocked nor
  escalated).
- **Determinism** — the runner scores each tool **twice** and checks the verdicts
  are identical. A deterministic firewall is reproducible and auditable; an
  LLM-in-the-loop guard that answers differently across runs cannot make either
  claim, and this column exposes it (a tool that *declares* determinism but fails
  the double-run is flagged loudly).
- **Latency** — self-reported decision time (comparable only among offline,
  same-host tools; a cloud tool's number includes network RTT).

## How it works

One corpus, one pipe, one scorer. An **adapter** is any executable that reads
samples as JSONL on stdin and writes verdicts as JSONL on stdout — so a JS
firewall and a Python firewall are scored identically, with no shared SDK. Full
contract in **[protocol.md](protocol.md)**.

```
corpus.json ──▶ run.mjs ──stdin(JSONL)──▶ your-adapter ──stdout(JSONL)──▶ scorer ──▶ RESULTS.md
 (labels the                (strips the        (your firewall)   (blocked?          (recall /
  runner keeps)              answer key)                          gated?)            precision / …)
```

Add a firewall in three steps: write an adapter (a few lines — see
`adapters/warden.mjs`), register it in `adapters.json`, run `node arena/run.mjs`.
If a tool isn't installed (or a cloud key is absent), the runner marks it
unavailable and skips it — it never crashes the run.

```bash
node arena/build-corpus.mjs      # regenerate corpus.json from the source corpus
node arena/run.mjs               # score all available adapters → RESULTS.md + results.json
node arena/run.mjs --adapter warden,deny-list
```

## Threat-model axes — what actually competes

"Agent security" is not one problem, and these tools do not sit on the same axis.
Scoring them all on one corpus without saying so would be a strawman — so here is
the honest map. **This corpus is agent _tool-call actions_** (shell/exec, fetch,
write). A tool is a *same-axis* competitor only if it classifies a tool call.

| tool | axis | fair on this corpus? |
|---|---|---|
| **warden** | tool-call firewall — classifies each action | **yes** — this is its axis |
| regex deny-list | tool-call firewall (naive) | yes — the floor |
| **AEGIS** | **tool-call firewall** — pre-execution `/check` classifies each action into allow / block / **pending** (human review) | **yes — same axis.** The first competitor with a real three-tier verdict; scored in blocking mode so risky calls escalate to `pending` (→ gated). Read its **+gate** column: hard recall(block) is low *by design* because it escalates rather than hard-blocks. Its behavioral-anomaly layer needs a per-agent baseline a one-shot corpus can't build, so the scored surface is its static policy + classifier + DSL. Screens the *action*, not poisoned-skill *text*. |
| **Meta LlamaFirewall** | LLM-I/O guardrail — PromptGuard (injection text), CodeShield (insecure generated code), AgentAlignment (trace goal-hijack) | **partial** — fair on the **injection** family; expected to *allow* shell RCE (not what it screens) |
| **Pipelock** | **egress-DLP gateway** — proxy that scans wire traffic (HTTP/MCP/WebSocket) for credential exfil, SSRF, injection; plus an on-demand **Scan API** for per-call verdicts | **partial** — scored via its documented Scan API (`tool_call` + `dlp` + `prompt_injection`, deny-from-any). Expected strong on credential-exfil / exfil-URL / injection families; its default install has no shell-*semantics* classifier (`rm -rf /` carries no credential or URL), so destruction/RCE families land at its wire layer only when the payload actually egresses. An operator-written `mcp_tool_policy` would change that — the arena runs the out-of-box posture. |
| **NeMo Guardrails** (NVIDIA) | LLM-backed dialog/rail checks | partial + non-deterministic; needs a model endpoint |
| **Lakera Guard** | LLM-I/O guardrail (cloud) — prompt-injection | partial; paid key |
| **Claw Patrol** (Deno) | **network-wire gateway** — gates SQL verbs / K8s verb+resource / HTTP path via HCL rules + credential injection | **no — different layer.** It gates protocol traffic on the wire, not tool-call strings, so this corpus can't score it. warden + Claw Patrol are *complementary layers*, not competitors. |

So the deliverable isn't a leaderboard where warden wins — it's a **map**. warden,
the deny-list, and **AEGIS** are the same-axis rows (AEGIS being the one that
answers "escalate to a human" where warden answers "approve" — the +gate column
is where you read both fairly). LlamaFirewall competes only on the injection
slice, and its per-family numbers are meant to show it catching injection while
passing shell RCE — honestly, not as a "loss." Pipelock is an egress-DLP gateway
scored on its per-call API surface. Claw Patrol is a different layer and is
deliberately **not** a row (forcing it onto this corpus would be the strawman
this section exists to avoid).

## Roadmap — adapters

Committed: `warden`, the `deny-list` baseline, the `allow-all` / `block-all`
anchors, a faithful **LlamaFirewall** adapter (`adapters/llamafirewall_adapter.py`)
that scores the injection slice — registered but **unavailable** until
`pip install llamafirewall` + a configured gated Meta PromptGuard model (HF
license + token), at which point the runner picks it up automatically (every
useful LlamaFirewall scanner needs a gated model or a paid Together key, so a
real run is one operator green-light away, not a code gap) — and a
**Pipelock** adapter (`adapters/pipelock.mjs`) that drives its Scan API with
every applicable kind per sample, and an **AEGIS** adapter (`adapters/aegis.mjs`)
that drives its pre-execution `/check` in blocking mode (the first three-tier
competitor). Both run live in CI: the [Arena workflow](../.github/workflows/arena.yml)
pins each competitor (Pipelock by sha256-verified release, AEGIS by git commit
built into its gateway container), starts it, scores the full arena on every PR
that touches it, and asserts each competitor actually scored — so the numbers
regenerate on a neutral host, on demand.

Still open (`adapters.json` → `roadmap`): **NeMo Guardrails** (needs a model
endpoint; the non-deterministic contrast case), **Lakera Guard** (paid key),
and **mcp-firewall** (OSS MCP gateway — same-axis candidate). **Claw Patrol**
is intentionally not on the roadmap as a row — it's a different layer (above).

## External corpus (MITRE ATT&CK)

The default corpus is warden-authored — so a second corpus, organized by an
**outside taxonomy**, exists to blunt that: [`external-corpus.json`](external-corpus.json)
groups its samples by **MITRE ATT&CK technique** (T1059 command execution, T1003
credential dumping, T1048/T1567 exfiltration, T1053 scheduled tasks, T1490
inhibit-recovery, T1611 container escape, …), with canonical command forms drawn
from the public **GTFOBins / LOLBAS / HackTricks** knowledge bases. The threat
*definitions and grouping* come from an external authority warden didn't write.
Crucially, every attack technique ships **benign uses of the same tools** (curl to
a real API, `certutil -hashfile`, `vssadmin list`, `docker run … npm test`,
`iptables -L`) so precision is a genuine test, not a giveaway.

```bash
npm run arena:external                 # node arena/run.mjs --corpus external-corpus.json
node arena/build-external-corpus.mjs   # regenerate the corpus
```

Results ([EXTERNAL-CORPUS-RESULTS.md](EXTERNAL-CORPUS-RESULTS.md)) — 68 samples,
32 ATT&CK techniques, scored through the same pipe:

| firewall | recall (block) | precision | under-gate |
|---|---|---|---|
| **warden** (default, offline) | **100%** | **100%** | 1/8 |
| regex deny-list (baseline) | 30.6% | 95.8% | 8/8 |
| Pipelock v3.0.0 (scan API, out-of-box) | 8.3% | 95.8% | 5/8 |

warden catches **every** ATT&CK-technique attack (36/36) at **100% precision** —
**zero benign commands blocked** despite the shared-tool benign set. The single
remaining under-gate is `grep -R API_KEY ~/.config` (a search, not an egress —
defensibly allowed). This corpus **earns its keep as a cross-check**: an early
run flagged two techniques warden missed — `rundll32 javascript:` (a LOLBAS
entry) and gnupg-keyring exfil — plus two dual-use reads it under-gated
(`/etc/shadow`, `vssadmin create shadow`); those became detection work in
warden's own corpus, and the numbers above are post-fix. An outside taxonomy
independently pointing at real gaps is exactly what an external corpus is for.

**Honest limit:** this is *externally taxonomized*, not a third-party dataset —
the strings are still assembled in this repo. True neutrality needs an
outside-contributed corpus, and the [protocol](protocol.md) makes that a drop-in:
any labeled JSONL with `{id, action, expect}` scores here unchanged, no warden
code involved. This corpus is the reference that invites those contributions.

## Honest caveats

- **The corpus is warden-authored.** warden topping a corpus warden wrote is the
  *expected* result, not a proof of superiority — so read this as "here is an
  open, reproducible harness and an honest scoreboard," not "warden wins." What
  keeps it meaningful: the labels are assigned by security principle (what a
  correct firewall *should* do), not by what warden happens to do; misses and
  under-gates are reported, not hidden (warden's own 5 misses and 1 under-gate
  are right there in the table); and the corpus + adapters are open to PRs.
- **It earns neutrality by growing.** Two things make the scoreboard trustworthy:
  more firewalls (so it's not a solo run), and corpus samples contributed by
  people who don't own warden. Both are wide-open contribution paths.
- **Latency is indicative, not a leaderboard.** Self-reported, single-host,
  no warm-up controls. Treat it as an order-of-magnitude signal.
- **A blocked-vs-gated boundary is a judgment call.** Binary tools can't express
  "approve"; the `+gate` recall column and the separate under-gate metric exist
  so they're scored fairly rather than penalized for lacking a tier.

## Provenance

Corpus generated from this repo's detection corpus (`bench/corpus.mjs`) by
`build-corpus.mjs` — one source of truth, regenerated, never hand-edited. MIT,
same as warden. Part of **[warden](../README.md)** · own your agent security.
