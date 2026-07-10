#!/usr/bin/env python3
# Arena adapter: mcp-firewall (github.com/ressl/mcp-firewall, AGPL-3.0) — an
# MCP security gateway that runs the same policy pipeline warden's corpus
# targets: a per-call tool-call firewall. Scored through its own inbound
# pipeline (kill-switch → rate-limit → injection → egress → policy → chain),
# in the documented starter posture (`mcp-firewall init`), rate-limit disabled.
#
# Filename is *_adapter.py on purpose: a file named mcp_firewall.py would shadow
# the installed `mcp_firewall` package and self-import.
#
# THREE-tier, read fairly:
#   mcp-firewall's inbound stages return allow / deny / PROMPT (escalate to a
#   human). Its SDK (`Gateway.check`) auto-approves prompts to allow when no TTY
#   is present — which would erase its human-approval tier on a batch run. So
#   this adapter reads the RAW stage verdict and maps it the way the arena maps
#   every gating tool:
#       deny   -> blocked
#       prompt -> gated   (escalate-to-human; counts toward +gate recall)
#       allow  -> allowed
#   This is the same credit warden gets for `approve` and AEGIS for `pending`.
#
# Out-of-box posture note: the starter config's defaultAction is `prompt`, so
# anything not matched by injection / egress / a rule escalates to a human.
# Expect a HIGH +gate recall AND high friction (benign actions also escalate) —
# mcp-firewall is the most escalate-by-default tool on the board. Read its
# +gate recall and its friction together.
#
# If the package isn't importable (not installed), this prints nothing and exits
# 0, so the runner marks it unavailable instead of scoring a bogus 0%.
import sys
import json
import time
import os

try:
    from mcp_firewall.config import load_config
    from mcp_firewall.models import Action, ToolCallRequest
    from mcp_firewall.pipeline.inbound.kill_switch import KillSwitch
    from mcp_firewall.pipeline.inbound.rate_limiter import RateLimiter
    from mcp_firewall.pipeline.inbound.injection import InjectionDetector
    from mcp_firewall.pipeline.inbound.egress import EgressControl
    from mcp_firewall.pipeline.inbound.policy import PolicyEngine
    from mcp_firewall.pipeline.inbound.chain_detector import ChainDetector
except Exception:
    sys.exit(0)

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("MCP_FIREWALL_CONFIG", os.path.join(HERE, "mcp-firewall.arena.yaml"))

try:
    config = load_config(CONFIG_PATH)
except Exception:
    sys.exit(0)

# Stages in the pipeline runner's documented order.
STAGES = [KillSwitch(), RateLimiter(), InjectionDetector(), EgressControl(), PolicyEngine(), ChainDetector()]


def verdict_for(sample):
    action = (sample.get("action") or {})
    args = action.get("input")
    if not isinstance(args, dict):
        args = {}
    req = ToolCallRequest(
        tool_name=sample.get("tool") or "tool",
        arguments=args,
        agent_id="arena-%s" % sample.get("id", ""),  # fresh agent per sample -> independent, deterministic
    )
    t0 = time.perf_counter()
    gated = False
    tier = "allow"
    for stage in STAGES:
        d = stage.evaluate(req, config)
        if d is None:
            continue
        if d.action == Action.DENY:
            tier = "deny"
            break
        if d.action == Action.PROMPT:
            gated = True  # human approval would run here; auto-continue like the runner
            continue
        if d.action == Action.ALLOW:
            tier = "allow"  # explicit allow short-circuits
            break
        # ALERT / REDACT: allow-but-note; keep going
    if tier != "deny" and gated:
        tier = "prompt"
    ms = (time.perf_counter() - t0) * 1000.0
    return {
        "id": sample.get("id"),
        "blocked": tier == "deny",
        "gated": tier == "prompt",
        "tier": tier,
        "ms": round(ms, 3),
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            sample = json.loads(line)
        except Exception:
            continue
        try:
            out = verdict_for(sample)
        except Exception as e:
            # A firewall that errors is not a firewall that allowed.
            out = {"id": sample.get("id"), "blocked": False, "error": str(e)}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
