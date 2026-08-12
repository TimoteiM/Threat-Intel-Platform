"""
The deep agent — an analyst, not an orchestrator.

Replaces `orchestrator.py` + `prompt_builder.py` + `response_parser.py`.

Collector scheduling stays deterministic Python. Letting the model choose which sources
to run would cost a round-trip per collector and make two runs over the same domain
disagree, which is the opposite of what this platform promises. What the model owns is
reading the evidence and writing the report.

`create_deep_agent` supplies filesystem tools, summarization and prompt caching. Two
things are overridden here:

- **Read-only filesystem.** By default `FilesystemMiddleware` creates every tool it
  knows, including `execute`, which runs commands in the *host* shell. This agent's
  entire input is attacker-controlled — page bodies, JavaScript, WHOIS strings,
  certificate subjects, sandbox reports — so a shell tool is a prompt-injection target
  with nothing to gain. It gets `ls`/`read_file`/`glob`/`grep` and nothing that writes or
  executes; the report leaves via `response_format`.
- **Explicit planning middleware.** deepagents adds none by default, so `write_todos`
  only exists because `TodoListMiddleware` is passed here.

The enrichment tools live on a dedicated `enrichment` subagent rather than on the main
agent. That is containment, not tidiness: deepagents passes the main agent's `tools`
straight through to the auto-injected `general-purpose` subagent, so a tool mounted on
the main agent has two invocation paths. These tools make outbound requests and spend
third-party API quota, and there should be exactly one way to reach them.

The `general-purpose` subagent stays enabled. It inherits the read-only filesystem
middleware above, and it is a cheap way for the model to isolate a bulky evidence read
out of the main context.
"""

from __future__ import annotations

import logging
from typing import Any

from deepagents import FilesystemMiddleware, create_deep_agent
from deepagents.backends import StateBackend
from deepagents.backends.utils import create_file_data
from langchain.agents.middleware import ModelFallbackMiddleware, TodoListMiddleware

from app.analyst.enrichment_tools import build_enrichment_subagent
from app.analyst.models import build_fallback_model, build_model
from app.analyst.report import report_from_state
from app.analyst.system_prompt import ANALYST_SYSTEM_PROMPT, build_task_message
from app.models.schemas import AnalystReport

logger = logging.getLogger(__name__)

# Read-only. No write_file / edit_file / delete / execute.
ANALYST_FS_TOOLS = ["ls", "read_file", "glob", "grep"]


def build_agent(
    *,
    model_override: str | None = None,
    tools: list[Any] | None = None,
    enrichment: bool = True,
):
    """
    Compile the analyst graph.

    `enrichment=False` drops the enrichment subagent, leaving an analyst that can only
    read the evidence it was given — no outbound requests at all.
    """
    model = build_model(model_override)

    # One backend instance shared by create_deep_agent and the middleware that replaces
    # its default filesystem stack entry (matched by middleware name). Two instances
    # would point at different stores.
    backend = StateBackend()
    middleware: list[Any] = [
        FilesystemMiddleware(backend=backend, tools=ANALYST_FS_TOOLS),
        TodoListMiddleware(),
    ]
    subagents = [build_enrichment_subagent(model, backend)] if enrichment else None
    # With a single local model there is nothing to fail over to, so the fallback
    # middleware is only installed when a second model is configured.
    if (fallback := build_fallback_model()) is not None:
        middleware.append(ModelFallbackMiddleware(fallback))

    return create_deep_agent(
        model=model,
        # Deliberately empty: anything here is also handed to the auto-injected
        # general-purpose subagent. Action tools go on a specialist instead.
        tools=tools or [],
        system_prompt=ANALYST_SYSTEM_PROMPT,
        backend=backend,
        middleware=middleware,
        subagents=subagents,
        response_format=AnalystReport,
        name="threat-analyst",
    )


def to_file_data(files: dict[str, str]) -> dict[str, Any]:
    """
    Wrap plain file contents in the `FileData` shape the backend stores.

    deepagents' `StateBackend` keeps `{path: {"content": ..., "encoding": ...}}` and
    calls `file_data_to_string` on every entry — so handing it `{path: str}` makes the
    agent's first `ls` raise `TypeError: string indices must be integers`. The whole
    analyst leg then degrades to an error path and every investigation returns the
    deterministic report only, with a green test suite, because a stub agent in tests
    accepts any dict.

    Built through the library's own constructor rather than by hand: the shape is theirs,
    and it has changed once already.
    """
    return {path: create_file_data(content) for path, content in files.items()}


async def run_analyst(
    agent,
    *,
    domain: str,
    investigation_id: str,
    files: dict[str, str],
    observable_type: str = "domain",
    digest_markdown: str = "",
    client_domain: str | None = None,
    context: str | None = None,
) -> tuple[AnalystReport, str, dict[str, Any]]:
    """
    Run one analyst turn over a prepared evidence bundle.

    Returns `(report, source, final_state)`. A report always comes back: `source` is
    "structured", "salvaged" or "fallback", so a model that cannot hold the schema
    degrades visibly instead of losing the whole run.
    """
    message = build_task_message(
        domain=domain,
        investigation_id=investigation_id,
        observable_type=observable_type,
        digest_markdown=digest_markdown,
        client_domain=client_domain,
        context=context,
    )
    # thread_id is harmless without a checkpointer (none is configured — InMemorySaver is
    # process-local and useless across Celery tasks, and langgraph-checkpoint-postgres
    # would add a second Postgres driver alongside psycopg2-binary). It is what a
    # follow-up-turn feature would need later.
    state = await agent.ainvoke(
        {
            "messages": [{"role": "user", "content": message}],
            "files": to_file_data(files),
        },
        config={"configurable": {"thread_id": investigation_id}},
    )
    report, source = report_from_state(state)
    if source != "structured":
        logger.warning("[%s] Analyst report obtained via %s path", investigation_id, source)
    return report, source, state
