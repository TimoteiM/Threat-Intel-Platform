"""
Analyst package.

Deliberately re-exports nothing. Import submodules directly.

This package used to eagerly import the orchestrator, prompt builder and response
parser, which meant `from app.analyst.attack_mapping import ...` — done by
app/api/attack.py and the three attack_* services, none of which want a model — pulled in
the openai and anthropic SDKs as a side effect. Keeping this file empty stops the ATT&CK
technique database from dragging in the LangChain agent stack.
"""
