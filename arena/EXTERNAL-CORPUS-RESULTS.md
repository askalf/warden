# Arena results

Corpus: **68 samples** · 32 families · 36 malicious / 8 risky / 24 benign.
> Organized by the MITRE ATT&CK technique taxonomy; command forms are canonical techniques from the public GTFOBins / LOLBAS / HackTricks knowledge bases. Externally taxonomized, still assembled in-repo — see the arena README ("External corpus") for the honest caveat and how to contribute a true third-party corpus.
Scored 4 firewall(s) through the same stdin/stdout pipe (see [protocol.md](protocol.md)). Regenerate: `node arena/run.mjs --corpus external-corpus.json`.

| firewall | offline | deterministic | recall (block) | recall (+gate) | precision | under-gate | median µs |
|---|---|---|---|---|---|---|---|
| warden | yes | yes | 100.0% | 100.0% | **100%** | 1/8 | 73 |
| regex deny-list (baseline) | yes | yes | 30.6% | 30.6% | 95.8% | 8/8 | 5 |
| allow-all (null) | yes | yes | 0.0% | 0.0% | **100%** | 8/8 | 0 |
| block-all (paranoid) | yes | yes | 100.0% | 100.0% | 0.0% | 0/8 | 0 |

- **recall (block)** — malicious actions hard-blocked. **recall (+gate)** — blocked *or* escalated to a human.
- **precision** — benign actions NOT blocked (100% = zero false positives). **under-gate** — risky actions silently allowed.
- **deterministic** — identical verdicts across two scoring passes (`*` = not re-run this pass; declared value shown).
- **median µs** — self-reported decision latency; comparable only among offline, same-host tools (a cloud tool includes network RTT).

_The `allow-all` and `block-all` rows are sanity anchors: allow-all pins 0% recall, block-all pins 100% recall at 0% precision — which is why recall is meaningless without precision beside it._
