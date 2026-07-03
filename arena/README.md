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

See **[RESULTS.md](RESULTS.md)** (regenerate any time with `node arena/run.mjs`).

| firewall | recall (block) | precision | under-gate | deterministic |
|---|---|---|---|---|
| **warden** (default, offline) | **96.4%** | **100%** | 1/33 | yes |
| regex deny-list (naive baseline) | 15.8% | 98.4% | 33/33 | yes |
| allow-all (null) | 0% | 100% | 33/33 | yes |
| block-all (paranoid) | 100% | 0% | 0/33 | yes |

The two anchors are the point: **block-all** gets perfect recall by blocking all
your real work; **allow-all** gets perfect precision by catching nothing. A
useful firewall is the one that keeps recall high *and* precision at 100% — which
is why both columns are always shown together.

## What's measured, and why each matters

The corpus (`corpus.json`, 234 samples, 19 attack families) labels every sample
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
| **Meta LlamaFirewall** | LLM-I/O guardrail — PromptGuard (injection text), CodeShield (insecure generated code), AgentAlignment (trace goal-hijack) | **partial** — fair on the **injection** family; expected to *allow* shell RCE (not what it screens) |
| **NeMo Guardrails** (NVIDIA) | LLM-backed dialog/rail checks | partial + non-deterministic; needs a model endpoint |
| **Lakera Guard** | LLM-I/O guardrail (cloud) — prompt-injection | partial; paid key |
| **Claw Patrol** (Deno) | **network-wire gateway** — gates SQL verbs / K8s verb+resource / HTTP path via HCL rules + credential injection | **no — different layer.** It gates protocol traffic on the wire, not tool-call strings, so this corpus can't score it. warden + Claw Patrol are *complementary layers*, not competitors. |

So the deliverable isn't a leaderboard where warden wins — it's a **map**. warden
and the deny-list are the same-axis rows. LlamaFirewall competes only on the
injection slice, and its per-family numbers are meant to show it catching
injection while passing shell RCE — honestly, not as a "loss." Claw Patrol is a
different layer and is deliberately **not** a row (forcing it onto this corpus
would be the strawman this section exists to avoid).

## Roadmap — adapters

Committed: `warden`, the `deny-list` baseline, the `allow-all` / `block-all`
anchors, and a faithful **LlamaFirewall** adapter (`adapters/llamafirewall_adapter.py`)
that scores the injection slice — it's registered but **unavailable** until
`pip install llamafirewall` + a configured gated Meta PromptGuard model (HF
license + token), at which point the runner picks it up automatically. Every
useful LlamaFirewall scanner needs a gated model (PromptGuard/CodeShield) or a
paid Together key (AgentAlignment), so a real run is one operator green-light
away (heavy `torch` install + HF token), not a code gap.

Still open (`adapters.json` → `roadmap`): **NeMo Guardrails** (needs a model
endpoint; the non-deterministic contrast case) and **Lakera Guard** (paid key).
**Claw Patrol** is intentionally not on the roadmap as a row — it's a different
layer (above).

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
