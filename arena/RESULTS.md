# Arena results

Corpus: **234 samples** · 19 families · 139 malicious / 33 risky / 62 benign.
Scored 4 firewall(s) through the same stdin/stdout pipe (see [protocol.md](protocol.md)). Regenerate: `node arena/run.mjs`.

| firewall | offline | deterministic | recall (block) | recall (+gate) | precision | under-gate | median µs |
|---|---|---|---|---|---|---|---|
| warden | yes | yes | 96.4% | 96.4% | **100%** | 1/33 | 63 |
| regex deny-list (baseline) | yes | yes | 15.8% | 15.8% | 98.4% | 33/33 | 2 |
| allow-all (null) | yes | yes | 0.0% | 0.0% | **100%** | 33/33 | 0 |
| block-all (paranoid) | yes | yes | 100.0% | 100.0% | 0.0% | 0/33 | 0 |

- **recall (block)** — malicious actions hard-blocked. **recall (+gate)** — blocked *or* escalated to a human.
- **precision** — benign actions NOT blocked (100% = zero false positives). **under-gate** — risky actions silently allowed.
- **deterministic** — identical verdicts across two scoring passes (`*` = not re-run this pass; declared value shown).
- **median µs** — self-reported decision latency; comparable only among offline, same-host tools (a cloud tool includes network RTT).

_The `allow-all` and `block-all` rows are sanity anchors: allow-all pins 0% recall, block-all pins 100% recall at 0% precision — which is why recall is meaningless without precision beside it._
