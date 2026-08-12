"""
Containment: no agent in the analyst graph can write or execute.

The analyst's entire input is attacker-controlled — page bodies, JavaScript, WHOIS
strings, certificate subjects, sandbox reports. deepagents' `FilesystemMiddleware`
creates every tool it knows by default, including `execute`, which runs commands in the
*host* shell, so this is the single assertion that matters in this package.

Two library behaviours make it non-obvious, and both are checked here rather than
assumed:

1. The auto-injected `general-purpose` subagent inherits the main agent's `tools`
   verbatim, which is why the main agent is built with `tools=[]`.
2. A declarative subagent does NOT inherit the parent's `FilesystemMiddleware` — it gets
   a fresh default one, with `execute`. Every subagent needs its own explicit middleware.

Offline: `build_agent()` only *constructs* `ChatOpenAI`, it makes no network call.
"""

import pytest

from app.analyst.agent import ANALYST_FS_TOOLS, build_agent

DANGEROUS = {"execute", "write_file", "edit_file", "delete"}

# ls / read_file / glob / grep from the pinned FilesystemMiddleware, `task` from the
# subagent middleware, `write_todos` from the explicitly-added TodoListMiddleware.
EXPECTED_MAIN_TOOLS = {*ANALYST_FS_TOOLS, "task", "write_todos"}


@pytest.fixture(autouse=True)
def _hosted_openai(monkeypatch):
    """A configured provider, so build_model() succeeds without touching the network."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-used")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _tools_of(graph) -> set[str]:
    return set(graph.nodes["tools"].bound.tools_by_name)


def _subagents_of(graph) -> dict:
    """Dig the compiled subagents out of the `task` tool's closure."""
    task_tool = graph.nodes["tools"].bound.tools_by_name.get("task")
    if task_tool is None:
        return {}
    for cell in getattr(task_tool, "func", None).__closure__ or ():
        contents = cell.cell_contents
        if isinstance(contents, dict) and contents and all(
            hasattr(v, "nodes") for v in contents.values()
        ):
            return contents
    return {}


def test_no_agent_anywhere_can_write_or_execute():
    """The single assertion that matters."""
    agent = build_agent()
    reachable = _tools_of(agent)
    subagents = _subagents_of(agent)

    # If this fails the test is inspecting nothing — the closure shape changed.
    assert subagents, "could not recover compiled subagents from the task tool"

    for subagent in subagents.values():
        reachable |= _tools_of(subagent)

    assert reachable & DANGEROUS == set(), (
        f"shell/write tools reachable: {sorted(reachable & DANGEROUS)}"
    )


def test_main_agent_tool_surface_is_exactly_the_allowlist():
    """The positive half: no tool creeps in, and the read-only four are all present."""
    assert _tools_of(build_agent()) == EXPECTED_MAIN_TOOLS


def test_every_subagent_is_contained_individually():
    """
    Named per-subagent assertions, so a failure says which one regressed.

    The enrichment subagent is the one that needs its own explicit middleware; without it
    deepagents gives it a default filesystem stack including `execute`.
    """
    subagents = _subagents_of(build_agent())
    assert "general-purpose" in subagents
    assert "enrichment" in subagents

    for name, subagent in subagents.items():
        tools = _tools_of(subagent)
        assert tools & DANGEROUS == set(), f"subagent {name!r} exposes {sorted(tools & DANGEROUS)}"

    # The enrichment specialist owns the outbound lookups, and only it.
    enrichment_tools = _tools_of(subagents["enrichment"])
    assert {"resolve_hostname", "lookup_ip_reputation", "reverse_dns"} <= enrichment_tools
    assert "read_file" in enrichment_tools, "FilesystemMiddleware requires read_file"


def test_enrichment_tools_are_not_reachable_from_the_main_agent():
    """
    They must have exactly one invocation path.

    deepagents hands the main agent's `tools` to the general-purpose subagent verbatim, so
    a tool mounted on the main agent would be callable two ways.
    """
    agent = build_agent()
    outbound = {"resolve_hostname", "lookup_ip_reputation", "reverse_dns"}

    assert _tools_of(agent) & outbound == set()
    assert _tools_of(_subagents_of(agent)["general-purpose"]) & outbound == set()


def test_enrichment_can_be_disabled_entirely():
    """`enrichment=False` leaves an analyst that makes no outbound requests at all."""
    subagents = _subagents_of(build_agent(enrichment=False))

    assert "enrichment" not in subagents
    for subagent in subagents.values():
        assert _tools_of(subagent) & DANGEROUS == set()
