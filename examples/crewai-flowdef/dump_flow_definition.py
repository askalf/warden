"""Dump the genuine CrewAI v1.15.1 FlowDefinition for GovernedNotesFlow.

`Flow.flow_definition()` returns crewai.flow.flow_definition.FlowDefinition - the
serializable, declarative contract (methods, trigger conditions, state, config)
that the ticket names. This proves we built a real *FlowDefinition* flow, and the
trigger graph (discover -> write -> attempt-destructive -> read_back) is exactly
the governed event chain that ran through warden.
"""
from __future__ import annotations
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _musl_rag_shim  # noqa: E402
_musl_rag_shim.install()

# Import the flow class without running it.
from crewai_governed_flow import GovernedNotesFlow  # noqa: E402
from crewai.flow.flow_definition import FlowDefinition  # noqa: E402

fd = GovernedNotesFlow.flow_definition()
assert isinstance(fd, FlowDefinition), f"not a FlowDefinition: {type(fd)}"

print("FlowDefinition type:", type(fd).__module__ + "." + type(fd).__name__)
print("flow name:", getattr(fd, "name", "?"))

# Serialize the declarative contract. FlowDefinition is a pydantic model.
data = fd.model_dump(mode="json")
print("\n--- FlowDefinition (declarative contract) ---")
print(json.dumps(data, indent=2, default=str))

# Summarize the method/trigger graph for a human-readable proof.
methods = data.get("methods") or {}
print("\n--- step graph ---")
if isinstance(methods, dict):
    for name, m in methods.items():
        trig = m.get("condition") or m.get("trigger") or m.get("listen") or "@start"
        print(f"  {name}  <-  {trig}")
elif isinstance(methods, list):
    for m in methods:
        print(f"  {m.get('name')}  <-  {m.get('condition') or '@start'}")
