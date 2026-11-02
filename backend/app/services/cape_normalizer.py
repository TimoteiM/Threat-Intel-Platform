"""Turn a CAPE report into the platform's own shape.

CAPE reports are large, deeply nested, and differ between versions and between
report formats. Every access here is defensive: a missing or oddly-typed branch
produces an empty list, never an exception, because a partially-parseable report
from a sample that really did execute is still evidence worth showing.

Two rules this file exists to enforce:

* **A missing malscore is not zero.** `tasks/view` frequently omits it, and a
  sample whose score is unknown must never be presented as clean. `malscore`
  stays None and `verdict` stays "unknown" unless the report actually said.
* **The verdict is an opinion, not a decision.** Nothing downstream may act on
  it automatically — see `SCORE_*` below. It is analyst evidence.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from app.models.schemas import (
    CapeBehaviourSummary,
    CapeDroppedFile,
    CapeNetworkIndicators,
    CapeNormalizedReport,
    CapeSignature,
)

logger = logging.getLogger(__name__)

# CAPE's malscore runs 0–10. These are a starting point for *display ordering*,
# deliberately not wired to any automatic action: a sandbox score is one input
# to an analyst's judgement, and this platform does not contain or remediate on
# the strength of one detonation.
SCORE_MALICIOUS = 7.0
SCORE_SUSPICIOUS = 4.0

# Ceilings per list. A busy sample can contact thousands of hosts; the point of
# the summary is that an analyst can read it.
_MAX_ITEMS = 200
_MAX_HTTP = 50
_MAX_PROCESS_TREE = 100
_MAX_SIGNATURES = 100
_MAX_DROPPED = 100


def normalize_report(
    payload: dict[str, Any],
    *,
    task_id: int | None = None,
    report_format: str | None = None,
    report_size_bytes: int | None = None,
) -> CapeNormalizedReport:
    """The authoritative mapping. `payload` is a CAPE JSON report."""
    if not isinstance(payload, dict):
        return CapeNormalizedReport(
            task_id=task_id,
            status="failed",
            errors=["CAPE report was not an object"],
            report_format=report_format,
        )

    info = _dict(payload.get("info"))
    target_file = _dict(_dict(payload.get("target")).get("file"))

    malscore = _as_float(payload.get("malscore"))
    if malscore is None:
        malscore = _as_float(info.get("malscore"))

    debug = _dict(payload.get("debug"))
    errors = _strings(debug.get("errors"))[:20]
    # CAPE records a failed launch in debug.log and leaves debug.errors empty,
    # so the one line that explains an empty analysis — "Unable to find any
    # Acrobat.exe executable" — was being dropped. Without it the report says
    # nothing happened and never says why.
    errors = (errors + _launch_failures(debug.get("log")))[:20]
    limitations: list[str] = []

    machine = _dict(info.get("machine"))
    signatures = _signatures(payload.get("signatures"))
    network = _network(payload.get("network"))
    behaviour = _behaviour(payload.get("behavior") or payload.get("behaviour"), payload)
    dropped = _dropped(payload)
    configs = _configs(payload)

    executed = bool(behaviour.process_count) or bool(network.domains) or bool(network.hosts)
    if not executed:
        # Nothing executed and nothing was contacted. Said out loud, because an
        # empty report reads exactly like a clean one otherwise.
        if errors:
            limitations.append(
                "The sample did not execute in the guest, so this analysis is not evidence "
                "about the file. CAPE reported: " + errors[0]
            )
        else:
            limitations.append(
                "No process activity and no network activity were recorded. "
                "The sample may not have executed in the guest."
            )
    if report_format == "iocs":
        # Said plainly, because the missing parts are ones an analyst would
        # otherwise read as absent rather than unfetched.
        limitations.append(
            "Read from CAPE's IOC summary because the full JSON report exceeded the size "
            "this platform will buffer. Behavioural signatures and CAPE's payload/config "
            "extraction are not included; open the task in CAPE for the complete report."
        )
    elif report_format and report_format != "json":
        limitations.append(
            f"Parsed from CAPE's '{report_format}' report, which carries less detail than the full JSON report."
        )

    return CapeNormalizedReport(
        task_id=task_id or _as_int(info.get("id")),
        status=str(payload.get("status") or info.get("status") or "reported").strip().lower(),
        malscore=malscore,
        # A score of zero from a sample that never ran is not evidence that the
        # file is safe — it is the absence of an analysis. Withholding the
        # verdict here is the difference between "we looked and found nothing"
        # and "we never got to look", which a green "likely benign" pill on an
        # unopened document actively misrepresents.
        verdict="unknown" if not executed else verdict_for(malscore),
        executed=executed,
        detections=_detections(payload),
        signatures=signatures,
        sha256=_lower(target_file.get("sha256")),
        sha1=_lower(target_file.get("sha1")),
        md5=_lower(target_file.get("md5")),
        file_name=_text(target_file.get("name")),
        file_type=_text(target_file.get("type")),
        file_size=_as_int(target_file.get("size")),
        ssdeep=_text(target_file.get("ssdeep")),
        tlsh=_text(target_file.get("tlsh")),
        crc32=_text(target_file.get("crc32")),
        yara_matches=_yara(target_file),
        clamav=_text(target_file.get("clamav")) or None,
        started_at=_text(info.get("started")),
        ended_at=_text(info.get("ended")),
        duration_seconds=_as_int(info.get("duration")),
        machine=_text(machine.get("name") or machine.get("label")) if machine else _text(info.get("machine")),
        route=_text(info.get("route")),
        package=_text(info.get("package")),
        network=network,
        behaviour=behaviour,
        dropped_files=dropped,
        extracted_configs=configs,
        has_screenshots=bool(payload.get("screenshots")),
        screenshot_count=len(payload.get("screenshots") or []) if isinstance(payload.get("screenshots"), list) else 0,
        report_format=report_format,
        report_size_bytes=report_size_bytes,
        errors=errors,
        limitations=limitations,
    )


# Lines in CAPE's analyser log that mean the sample was never started. Matched
# on the exception text rather than the whole log, which runs to thousands of
# lines of routine progress.
_LAUNCH_FAILURE_MARKERS = (
    "CuckooError",
    "CuckooPackageError",
    "start function raised an error",
    "Unable to find any",
    "Unable to execute",
    "could not be executed",
)

# Routine progress. "analysis package specified: pdf" is an INFO line and was
# matching a broader marker, so the limitation quoted it instead of the
# exception — the one line that explains the empty analysis ended up fifth.
_ROUTINE_LOG_LEVELS = ("] INFO:", "] DEBUG:", "] WARNING:")


def _launch_failures(log: Any) -> list[str]:
    """The reason an analysis produced nothing, out of CAPE's analyser log.

    Ordered so the most explanatory line comes first: a caller quoting
    `errors[0]` should get "Unable to find any Acrobat.exe executable", not a
    timestamped note that the pdf package was selected.
    """
    text = str(log or "")
    if not text:
        return []

    found: list[str] = []
    for line in text.splitlines():
        cleaned = line.strip()
        if not cleaned or len(cleaned) > 400:
            continue
        if any(level in cleaned for level in _ROUTINE_LOG_LEVELS):
            continue
        if not any(marker in cleaned for marker in _LAUNCH_FAILURE_MARKERS):
            continue
        # A traceback echoes the source that raised, so the log carries both
        # `raise CuckooPackageError(f"... {application} ...")` and the resolved
        # message. The template names nothing and is noise in a report — drop
        # it rather than merely ranking it last, which still showed it.
        if cleaned.startswith("raise ") or "{" in cleaned:
            continue
        # Strip the exception class and module path, which add nothing for a
        # reader: what matters is the sentence after the colon.
        for prefix in ("CuckooPackageError: ", "CuckooError: "):
            if prefix in cleaned:
                cleaned = cleaned.split(prefix, 1)[1]
        found.append(cleaned)

    def informativeness(line: str) -> int:
        if "Unable to find any" in line or "Unable to execute" in line:
            return 0
        if "raised an error" in line:
            return 1
        return 2

    return _dedupe(sorted(found, key=informativeness))[:5]


def verdict_for(malscore: float | None) -> str:
    """Unknown when CAPE did not say. Never "benign" by absence of evidence."""
    if malscore is None:
        return "unknown"
    if malscore >= SCORE_MALICIOUS:
        return "malicious"
    if malscore >= SCORE_SUSPICIOUS:
        return "suspicious"
    return "likely_benign"


# ── sections ─────────────────────────────────────────────────────────────────


def _detections(payload: dict) -> list[str]:
    """Family names. CAPE has used strings and objects in this list."""
    found: list[str] = []
    raw = payload.get("detections")
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            name = item.get("family") or item.get("name") or item.get("detection")
            if name:
                found.append(str(name))
    if isinstance(raw, str) and raw.strip():
        found.append(raw.strip())
    # CAPE's own extraction often names the family only here.
    for config in _configs(payload):
        family = config.get("family") or config.get("cape_name")
        if family:
            found.append(str(family))
    return _dedupe(found)


def _signatures(raw: Any) -> list[CapeSignature]:
    out: list[CapeSignature] = []
    seen: set[str] = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name")) or _text(item.get("signature"))
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            CapeSignature(
                name=name,
                description=_text(item.get("description")) or "",
                severity=_as_int(item.get("severity")) or 0,
                confidence=_as_int(item.get("confidence")),
                ttps=_ttps(item),
                details=_signature_details(item.get("data")),
            )
        )
        if len(out) >= _MAX_SIGNATURES:
            break
    out.sort(key=lambda s: s.severity, reverse=True)
    return out


def _signature_details(raw: Any) -> list[str]:
    """What a signature matched, flattened to readable lines.

    CAPE's `data` is a list of single-entry dicts — [{"Binary triggered YARA
    rule": "multiple_versions"}] — which carries the whole substance of the
    finding. Dropping it left every signature reading as its own category.
    """
    out: list[str] = []
    for entry in raw if isinstance(raw, list) else []:
        if isinstance(entry, dict):
            for key, value in entry.items():
                if isinstance(value, (list, tuple)):
                    value = ", ".join(str(v) for v in value[:8])
                text = f"{key}: {value}" if key else str(value)
                out.append(_trim(text, 300))
        elif isinstance(entry, str):
            out.append(_trim(entry, 300))
    return _dedupe(out)[:12]


def _ttps(item: dict) -> list[str]:
    """ATT&CK ids, from the several keys CAPE has used for them."""
    found: list[str] = []
    for key in ("ttp", "ttps", "attack", "attack_id", "mitre"):
        value = item.get(key)
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, str):
                    found.append(entry)
                elif isinstance(entry, dict):
                    tid = entry.get("id") or entry.get("technique_id") or entry.get("ttp")
                    if tid:
                        found.append(str(tid))
        elif isinstance(value, dict):
            found.extend(str(k) for k in value.keys())
    return _dedupe(found)[:20]


def _yara(target_file: dict) -> list[dict]:
    """YARA rules that matched the file, with the author's own description."""
    out: list[dict] = []
    seen: set[str] = set()
    for key in ("yara", "cape_yara"):
        for entry in target_file.get(key) if isinstance(target_file.get(key), list) else []:
            if not isinstance(entry, dict):
                continue
            name = _text(entry.get("name"))
            if not name or name in seen:
                continue
            seen.add(name)
            meta = _dict(entry.get("meta"))
            out.append(
                {
                    "name": name,
                    "description": _trim(meta.get("description") or "", 300),
                    "author": _text(meta.get("author")),
                    "source": "cape" if key == "cape_yara" else "yara",
                }
            )
            if len(out) >= 20:
                return out
    return out


def _network(raw: Any) -> CapeNetworkIndicators:
    net = _dict(raw)
    domains: list[str] = []
    hosts: list[str] = []

    for entry in net.get("domains") if isinstance(net.get("domains"), list) else []:
        if isinstance(entry, dict):
            if entry.get("domain"):
                domains.append(str(entry["domain"]))
            if entry.get("ip"):
                hosts.append(str(entry["ip"]))
        elif isinstance(entry, str):
            domains.append(entry)

    dns_queries: list[str] = []
    for entry in net.get("dns") if isinstance(net.get("dns"), list) else []:
        if isinstance(entry, dict):
            request = entry.get("request") or entry.get("name")
            if request:
                dns_queries.append(str(request))
        elif isinstance(entry, str):
            dns_queries.append(entry)

    for entry in net.get("hosts") if isinstance(net.get("hosts"), list) else []:
        if isinstance(entry, str):
            hosts.append(entry)
        elif isinstance(entry, dict) and entry.get("ip"):
            hosts.append(str(entry["ip"]))

    destinations: list[str] = []
    for proto in ("tcp", "udp", "icmp"):
        for entry in net.get(proto) if isinstance(net.get(proto), list) else []:
            if not isinstance(entry, dict):
                continue
            dst = entry.get("dst") or entry.get("dport_ip") or entry.get("daddr")
            port = entry.get("dport") or entry.get("port")
            if dst:
                destinations.append(f"{dst}:{port}/{proto}" if port else f"{dst}/{proto}")
                hosts.append(str(dst))

    http_requests: list[dict] = []
    for key in ("http", "http_ex", "https_ex"):
        for entry in net.get(key) if isinstance(net.get(key), list) else []:
            if not isinstance(entry, dict):
                continue
            http_requests.append(
                {
                    "method": _text(entry.get("method")) or "GET",
                    "host": _text(entry.get("host")) or "",
                    "uri": _text(entry.get("uri") or entry.get("path")) or "",
                    "status": _as_int(entry.get("status")),
                }
            )
            if entry.get("host"):
                domains.append(str(entry["host"]))
            if len(http_requests) >= _MAX_HTTP:
                break

    tls_sni: list[str] = []
    for entry in net.get("tls") if isinstance(net.get("tls"), list) else []:
        if isinstance(entry, dict):
            sni = entry.get("sni") or entry.get("server_name")
            if sni:
                tls_sni.append(str(sni))
                domains.append(str(sni))

    return CapeNetworkIndicators(
        # Hostnames are case-insensitive, and these are looked up by JSONB
        # containment later — storing them lowercased makes that exact.
        domains=_dedupe(d.lower() for d in domains),
        dns_queries=_dedupe(d.lower() for d in dns_queries),
        hosts=_dedupe(hosts),
        destinations=_dedupe(destinations),
        http_requests=http_requests[:_MAX_HTTP],
        tls_sni=_dedupe(s.lower() for s in tls_sni),
    )


def _behaviour(raw: Any, payload: dict | None = None) -> CapeBehaviourSummary:
    """Behaviour from either report shape.

    The full report nests it as `behavior.summary.{mutex,keys,write_files,...}`
    with `behavior.processtree`. CAPE's IOC summary puts the same facts at the
    top level as `mutexes`, `registry`, `files`, `executed_commands` and
    `process_tree`. Both are read, so a report and an IOC summary normalize to
    the same structure and nothing downstream has to know which it came from.
    """
    behavior = _dict(raw)
    summary = _dict(behavior.get("summary"))
    flat = _dict(payload)

    def pick(*keys: str) -> Any:
        for key in keys:
            if summary.get(key) is not None:
                return summary[key]
        for key in keys:
            if flat.get(key) is not None:
                return flat[key]
        return None

    tree_raw = (
        behavior.get("processtree")
        or behavior.get("process_tree")
        or flat.get("process_tree")
        or flat.get("processtree")
    )
    tree = _process_tree(tree_raw)

    processes = behavior.get("processes") or flat.get("processes")
    if isinstance(processes, list):
        process_count = len(processes)
    else:
        process_count = _count_tree(tree)

    return CapeBehaviourSummary(
        mutexes=_dedupe(_strings(pick("mutex", "mutexes"))),
        registry_keys=_dedupe(
            _strings(pick("keys", "registry"))
            + _strings(summary.get("write_keys"))
            + _strings(summary.get("read_keys"))
        ),
        # Process count from the tree when the summary carries no process list,
        # counting every node rather than only the roots.
        # CAPE's IOC summary groups file activity as {modified, deleted}, and
        # both are writes — mapping the whole `files` dict onto files_read, as
        # the first pass did, reported 497 modified paths as zero writes.
        files_written=_dedupe(
            _strings(pick("write_files", "files_written"))
            + _strings(_dict(flat.get("files")).get("modified"))
            + _strings(_dict(flat.get("files")).get("deleted"))
        ),
        files_read=_dedupe(_strings(summary.get("read_files") or summary.get("files"))),
        commands=_dedupe(_strings(pick("executed_commands", "commands"))),
        process_tree=tree,
        process_count=process_count,
    )


def _process_tree(raw: Any, depth: int = 0) -> list[dict]:
    """Flattened to name/pid/children: enough to read, not a memory dump.

    Two shapes again. The full report gives a list of roots with `children`;
    CAPE's IOC summary gives a single root dict whose children are under
    `spawned_processes`. Both are accepted, or the IOC path silently reports
    zero processes for an analysis that ran dozens.
    """
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or depth > 6:
        return []
    out: list[dict] = []
    for node in raw:
        if not isinstance(node, dict):
            continue
        children = node.get("children") or node.get("spawned_processes")
        out.append(
            {
                "name": _text(node.get("name") or node.get("process_name")) or "unknown",
                "pid": _as_int(node.get("pid")),
                "parent_pid": _as_int(node.get("parent_id") or node.get("ppid")),
                "command_line": (_text(node.get("command_line")) or "")[:500],
                "children": _process_tree(children, depth + 1),
            }
        )
        if len(out) >= _MAX_PROCESS_TREE:
            break
    return out


def _count_tree(nodes: list[dict]) -> int:
    """Every process in the tree, not just the roots.

    The IOC summary gives one root with its children nested, so counting the
    top level reported "1 process" for an analysis that ran several."""
    total = 0
    for node in nodes or []:
        total += 1
        total += _count_tree(node.get("children") or [])
    return total


def _dropped(payload: dict) -> list[CapeDroppedFile]:
    out: list[CapeDroppedFile] = []
    seen: set[str] = set()

    def add(entry: Any, *, is_payload: bool) -> None:
        if not isinstance(entry, dict) or len(out) >= _MAX_DROPPED:
            return
        digest = _lower(entry.get("sha256")) or ""
        key = digest or _text(entry.get("name")) or ""
        if not key or key in seen:
            return
        seen.add(key)
        out.append(
            CapeDroppedFile(
                name=_text(entry.get("name")),
                sha256=digest or None,
                md5=_lower(entry.get("md5")),
                size=_as_int(entry.get("size")),
                file_type=_text(entry.get("type")),
                is_cape_payload=is_payload,
                cape_type=_text(entry.get("cape_type")),
            )
        )

    for entry in payload.get("dropped") if isinstance(payload.get("dropped"), list) else []:
        add(entry, is_payload=False)

    cape_section = _dict(payload.get("CAPE"))
    payloads = cape_section.get("payloads") if isinstance(cape_section.get("payloads"), list) else []
    for entry in payloads:
        add(entry, is_payload=True)
    # Older reports put the payload list directly under "CAPE".
    if isinstance(payload.get("CAPE"), list):
        for entry in payload["CAPE"]:
            add(entry, is_payload=True)

    return out


def _configs(payload: dict) -> list[dict]:
    """CAPE's config extraction — the C2 details, when it recognised a family."""
    found: list[dict] = []
    cape_section = _dict(payload.get("CAPE"))
    for source in (cape_section.get("configs"), payload.get("CAPE_configs"), payload.get("configs")):
        if isinstance(source, list):
            found.extend(c for c in source if isinstance(c, dict))
        elif isinstance(source, dict):
            found.append(source)
    return found[:20]


# ── primitives ───────────────────────────────────────────────────────────────


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    """Strings out of a string, a list, or a dict of lists.

    The last case is CAPE's IOC summary, which groups registry and file
    activity as `{"modified": [...], "deleted": [...]}` rather than a flat
    list. Without it those sections normalize to empty and an analyst reads
    "no registry activity" from a report that recorded plenty.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for key in sorted(value):
            for item in _strings(value[key]):
                out.append(item)
        return out
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key in ("name", "value", "path", "key"):
                if item.get(key):
                    out.append(str(item[key]))
                    break
    return out


def _dedupe(values: Iterable[str]) -> list[str]:
    """Order-preserving, case-insensitive, trimmed, capped."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = str(value).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(cleaned)
        if len(out) >= _MAX_ITEMS:
            break
    return out


def _trim(value: Any, limit: int) -> str:
    """Bounded text. A signature detail can carry a whole command line."""
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _lower(value: Any) -> str | None:
    text = _text(value)
    return text.lower() if text else None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
