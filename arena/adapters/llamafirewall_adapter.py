#!/usr/bin/env python3
# Arena adapter: Meta LlamaFirewall (PurpleLlama). See ../protocol.md.
#
# THREAT-MODEL NOTE (read before reading its numbers): LlamaFirewall is an
# LLM-I/O guardrail, not a shell/tool-call firewall. Its PromptGuard scanner is a
# BERT classifier for prompt-injection / jailbreak *text*. So on this corpus it is
# EXPECTED to flag the injection-skill family and to ALLOW shell RCE like
# `rm -rf /` — screening that is not what PromptGuard does. The arena's per-family
# breakdown (results.json) shows exactly this split. That is a fair cross-layer
# comparison, not a claim that either tool loses on the other's turf. warden
# classifies tool-call actions; LlamaFirewall screens model I/O; they overlap only
# on injection.
#
# Requires `pip install llamafirewall` AND a configured PromptGuard model — a
# GATED Meta HuggingFace model (accept its license + set HF_TOKEN, or run
# `llamafirewall configure`). If the package or model isn't available, this prints
# a diagnostic to stderr and exits 0 with NO stdout, so the arena runner marks the
# adapter "unavailable" and skips it (never a fake 0% row).
#
# Decision mapping (protocol.md): BLOCK -> blocked; HUMAN_IN_THE_LOOP_REQUIRED ->
# gated; ALLOW -> neither.
import sys
import json
import time


def unavailable(msg: str) -> None:
    print(f"[llamafirewall adapter] unavailable: {msg}", file=sys.stderr)
    sys.exit(0)  # no stdout => runner marks this adapter unavailable and skips it


try:
    from llamafirewall import LlamaFirewall, UserMessage, Role, ScannerType
except Exception as e:  # noqa: BLE001 - any import failure means "not installed"
    unavailable(f"import failed ({e}); `pip install llamafirewall`")

# PromptGuard is the scanner whose axis overlaps warden (injection). CodeShield
# and AgentAlignment need more setup (a model / a paid Together key) and screen a
# different slice; override with LLAMAFIREWALL_SCANNERS=PROMPT_GUARD,CODE_SHIELD.
import os

wanted = [s.strip() for s in os.environ.get("LLAMAFIREWALL_SCANNERS", "PROMPT_GUARD").split(",") if s.strip()]
try:
    scanners = [getattr(ScannerType, s) for s in wanted]
    fw = LlamaFirewall(scanners={Role.USER: scanners})
except Exception as e:  # noqa: BLE001
    unavailable(f"init failed ({e}); run `llamafirewall configure` and provide the gated PromptGuard model")


def scan_one(sample: dict) -> dict:
    # Feed the injection payload when present (injection-skill family), else the
    # command string — the action the agent wants to take, as a user turn.
    text = sample.get("skill") or sample.get("command")
    if not text:
        text = json.dumps((sample.get("action") or {}).get("input") or {})
    t0 = time.perf_counter()
    r = fw.scan(UserMessage(content=text))
    ms = (time.perf_counter() - t0) * 1000.0
    name = getattr(getattr(r, "decision", None), "name", str(getattr(r, "decision", "")))
    return {
        "id": sample["id"],
        "blocked": name == "BLOCK",
        "gated": name in ("HUMAN_IN_THE_LOOP_REQUIRED", "HUMAN_IN_THE_LOOP"),
        "tier": getattr(r, "reason", name) or name,
        "ms": round(ms, 3),
    }


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        sample = json.loads(line)
    except Exception:  # noqa: BLE001
        continue
    try:
        print(json.dumps(scan_one(sample)), flush=True)
    except Exception as e:  # noqa: BLE001 - a per-sample failure is an error verdict, not an allow
        print(json.dumps({"id": sample.get("id"), "blocked": False, "error": str(e)}), flush=True)
