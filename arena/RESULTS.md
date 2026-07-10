# Arena results

Corpus: **245 samples** · 19 families · 143 malicious / 35 risky / 67 benign.

Scored 7 firewall(s) through the same stdin/stdout pipe (see [protocol.md](protocol.md)). Regenerate: `node arena/run.mjs`.

| firewall | offline | deterministic | recall (block) | recall (+gate) | precision | under-gate | median µs |
|---|---|---|---|---|---|---|---|
| warden | yes | yes | 96.5% | 96.5% | **100%** | 1/35 | 78 |
| regex deny-list (baseline) | yes | yes | 15.4% | 15.4% | 98.5% | 35/35 | 2 |
| allow-all (null) | yes | yes | 0.0% | 0.0% | **100%** | 35/35 | 0 |
| block-all (paranoid) | yes | yes | 100.0% | 100.0% | 0.0% | 0/35 | 0 |
| Pipelock (scan API) | yes | yes | 7.0% | 7.0% | 95.5% | 29/35 | 0 |
| AEGIS (pre-execution check) | yes | yes | 4.9% | 59.4% | **100%** | 20/35 | 1000 |
| mcp-firewall (inbound pipeline) | yes | yes | 9.8% | 100.0% | 95.5% | 0/35 | 55 |

- **recall (block)** — malicious actions hard-blocked. **recall (+gate)** — blocked *or* escalated to a human.
- **precision** — benign actions NOT blocked (100% = zero false positives). **under-gate** — risky actions silently allowed.
- **deterministic** — identical verdicts across two scoring passes (`*` = not re-run this pass; declared value shown).
- **median µs** — self-reported decision latency; comparable only among offline, same-host tools (a cloud tool includes network RTT).

_The `allow-all` and `block-all` rows are sanity anchors: allow-all pins 0% recall, block-all pins 100% recall at 0% precision — which is why recall is meaningless without precision beside it._
