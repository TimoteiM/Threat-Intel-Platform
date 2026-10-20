"""How many identifiers actually reach the model today, per alert.

Not how many could. The question is what the model receives on the path that
runs, so the instrument is: take each stored `alert_body`, run the **real
shipped sanitiser** over it, and then apply the **boundary's own extra
detectors to that output**. What they find in the sanitised text is, by
construction, exactly what survived to the model.

The delta between the two paths is `_extra_pass` plus the keyed detectors the
shipped separator misses, so running those patterns on the shipped output is
the same measurement as "what the boundary would have caught and the shipped
path did not" — without having to diff two tokenisations.

Secrets are counted the same way, because nothing strips secrets from an
alert body: `log_secret_sanitizer` is applied to log records in the digest,
and `sanitize_entries` is identifier-only.

Guards are the boundary's real ones — `is_builtin_principal` and a token
check — so `SYSTEM`, `localhost` and an already-tokenised value are not
counted as leaks. Without them this would report the deny-list as a finding.

Prints counts and distributions. **No identifier values.** Field *names* are
printed for the colon gap, because the key is the diagnostic and a key is not
a value.
"""
from __future__ import annotations

import ipaddress
import pathlib
import re
import statistics
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services import log_secret_sanitizer as secrets
from app.services.assistant_sanitizer_service import sanitize_entries
from app.services.token_boundary import (
    BARE_DOMAIN_ACCOUNT_RE,
    IPV6_CANDIDATE_RE,
    KEYED_ACCOUNT_LAX_RE,
    KEYED_HOST_LAX_RE,
    SWITCH_ACCOUNT_RE,
    UNC_HOST_RE,
    is_builtin_principal,
)

TOKEN_RE = re.compile(r"\[(?:HOST|ACCOUNT|IP|EMAIL|SID)_[0-9a-f_]*\d+\]")

#: Bodies at or above this are excluded and reported separately. See the
#: comment at the query. Overridable: `--max-chars N`.
MAX_BODY_CHARS = 100_000


def _usable(value: str) -> bool:
    """The boundary's own guards. A built-in is a decision, not a leak."""
    return bool(value) and not is_builtin_principal(value) and not TOKEN_RE.fullmatch(value)


def classes_in(text_in: str) -> dict[str, list[str]]:
    """Every covered class surviving in `text_in`, by class.

    Returns the matched values so the caller can count distinct entities
    rather than occurrences — the privacy-relevant number is how many real
    machines and people were named, not how many times.
    """
    found: dict[str, list[str]] = defaultdict(list)

    for match in KEYED_HOST_LAX_RE.finditer(text_in):
        value = match.group("value")
        if _usable(value):
            # The pattern's own lookahead forbids a following dot, so every
            # match here is single-label: gap 1 by construction.
            found["gap1_single_label_host"].append(value)

    for match in KEYED_ACCOUNT_LAX_RE.finditer(text_in):
        value = match.group("value")
        if not _usable(value):
            continue
        prefix = match.group("prefix")
        # The separator is the whole point. A colon-separated key is what our
        # own ingest flattening emits from any structured post; `=` and a
        # quoted form are what the shipped detector already handles, so a
        # match on those means something else let it through.
        if ":" in prefix and "=" not in prefix:
            found["colon_keyed_account"].append(value)
        else:
            found["other_keyed_account"].append(value)

    for match in BARE_DOMAIN_ACCOUNT_RE.finditer(text_in):
        value = match.group("value")
        if _usable(value):
            found["gap2_bare_domain_account"].append(value)

    for match in UNC_HOST_RE.finditer(text_in):
        value = match.group("value")
        if _usable(value):
            found["gap3_unc_host"].append(value)

    for match in SWITCH_ACCOUNT_RE.finditer(text_in):
        value = match.group("value")
        if _usable(value):
            found["gap5_user_switch"].append(value)

    for match in IPV6_CANDIDATE_RE.finditer(text_in):
        raw = match.group(0)
        try:
            ipaddress.IPv6Address(raw)
        except ValueError:
            continue          # a timestamp or a MAC fragment, not an address
        found["gap4_ipv6"].append(raw)

    return found


def secret_labels_in(text_in: str) -> Counter:
    """Secrets surviving to the model. Nothing strips these from a body."""
    result = secrets.sanitize_text(text_in)
    return Counter(result.replacements)


def colon_keys_in(text_in: str) -> Counter:
    """Which field names carry a colon-separated account. Names, not values."""
    keys: Counter = Counter()
    for match in KEYED_ACCOUNT_LAX_RE.finditer(text_in):
        if not _usable(match.group("value")):
            continue
        prefix = match.group("prefix")
        if ":" in prefix and "=" not in prefix:
            keys[prefix.rstrip(": \t").strip()] += 1
    return keys


def control() -> None:
    """A known-present body must register in every class.

    Without this, a corpus of zeros is indistinguishable from a broken
    instrument — and a zero here would be read as good news.
    """
    probe = (
        'hostname: SENTFILESERVER\n'
        'sourceProcessInfo.user: sentuseralpha\n'
        r"logon by SENTDOM\sentuserbeta from \\SENTFS01\share" "\n"
        "remote=2001:db8:dead:beef::1\n"
        "powershell.exe -User sentusergamma\n"
        "vendor_detail: password=SentinelPassw0rd\n"
    )
    shipped = sanitize_entries([probe]).entries[0].sanitized_text
    found = classes_in(shipped)
    expected = {
        "gap1_single_label_host", "colon_keyed_account",
        "gap2_bare_domain_account", "gap3_unc_host",
        "gap4_ipv6", "gap5_user_switch",
    }
    missing = expected - set(found)
    if missing:
        raise SystemExit(f"INSTRUMENT BROKEN: no match for {sorted(missing)}")
    if not secret_labels_in(shipped):
        raise SystemExit("INSTRUMENT BROKEN: the secret probe registered nothing")
    print("instrument control: all 6 classes + secrets detected in a known body\n")


def main() -> None:
    global MAX_BODY_CHARS
    if "--max-chars" in sys.argv:
        MAX_BODY_CHARS = int(sys.argv[sys.argv.index("--max-chars") + 1])
    control()

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        total_runs = conn.execute(text(
            "SELECT COUNT(*) FROM alert_body_investigation_runs"
        )).scalar()

        # Every run, not a sample. `alert_source` is the shipper and
        # `tenant_id` the authoritative discriminator; `alert_client` is
        # self-declared and is NOT used to group anything.
        # **A stated bound, not a silent sample.** `sanitize_entries` is
        # superlinear: measured 0.94 M chars/s on bodies under 10k and
        # 0.05 M chars/s on a 1.22M body, ~19x worse per character. Twelve
        # bodies are over 100k and carry 30% of the corpus's characters;
        # scanning them costs hours, so they are counted and excluded here
        # and measured separately. The excluded count is printed, because a
        # bound nobody states is a bound somebody will read as totality.
        excluded = conn.execute(text("""
            SELECT COUNT(*), COALESCE(SUM(LENGTH(alert_body)), 0)
            FROM alert_body_investigation_runs
            WHERE alert_body <> '' AND LENGTH(alert_body) >= :cap
        """), {"cap": MAX_BODY_CHARS}).one()

        rows = conn.execute(text("""
            SELECT COALESCE(alert_source, '(null)') AS shipper,
                   COALESCE(tenant_id, '(unassigned)') AS tenant,
                   alert_body
            FROM alert_body_investigation_runs
            WHERE alert_body <> '' AND LENGTH(alert_body) < :cap
        """), {"cap": MAX_BODY_CHARS})

        per_class_occurrences: Counter = Counter()
        per_class_runs: Counter = Counter()
        per_class_distinct: dict[str, set] = defaultdict(set)
        by_shipper: dict[str, Counter] = defaultdict(Counter)
        by_tenant: dict[str, Counter] = defaultdict(Counter)
        shipper_runs: Counter = Counter()
        tenant_runs: Counter = Counter()
        secret_occurrences: Counter = Counter()
        secret_runs = 0
        colon_keys: Counter = Counter()
        per_alert_counts: list[int] = []
        shipped_tokens: list[int] = []
        scanned = 0
        chars = 0
        t0 = time.perf_counter()

        for shipper, tenant, body in rows:
            scanned += 1
            chars += len(body)
            result = sanitize_entries([body]).entries[0]
            shipped_text = result.sanitized_text
            shipped_tokens.append(len(result.token_map or {}))

            found = classes_in(shipped_text)
            distinct_here = set()
            for name, values in found.items():
                per_class_occurrences[name] += len(values)
                per_class_runs[name] += 1
                per_class_distinct[name].update(values)
                by_shipper[shipper][name] += len(values)
                by_tenant[tenant][name] += len(values)
                distinct_here.update((name, v) for v in values)
            per_alert_counts.append(len(distinct_here))

            labels = secret_labels_in(shipped_text)
            if labels:
                secret_runs += 1
                secret_occurrences.update(labels)
            colon_keys.update(colon_keys_in(shipped_text))
            shipper_runs[shipper] += 1
            tenant_runs[tenant] += 1

            if scanned % 2500 == 0:
                print(f"  … {scanned} runs, {chars/1e6:.1f}M chars, "
                      f"{time.perf_counter() - t0:.0f}s", file=sys.stderr)

    elapsed = time.perf_counter() - t0
    print(f"scanned {scanned} of {total_runs} runs ({chars/1e6:.1f}M chars) "
          f"in {elapsed:.0f}s")
    print(f"EXCLUDED by the {MAX_BODY_CHARS:,}-char bound: {excluded[0]} run(s), "
          f"{excluded[1]/1e6:.1f}M chars "
          f"({excluded[1]/(excluded[1]+chars)*100:.0f}% of all characters) — "
          f"measured separately\n")

    # ── the headline: identifiers per alert reaching the model ──
    leaking = [n for n in per_alert_counts if n]
    print("=" * 74)
    print("IDENTIFIERS REACHING THE MODEL, PER ALERT (distinct entities)")
    print("=" * 74)
    print(f"  runs with at least one          : {len(leaking):6} "
          f"({len(leaking) / scanned * 100:.1f}% of {scanned})")
    print(f"  total distinct-per-alert        : {sum(per_alert_counts):6}")
    if per_alert_counts:
        ordered = sorted(per_alert_counts)
        print(f"  mean over ALL runs              : {statistics.mean(per_alert_counts):6.2f}")
        print(f"  median over all runs            : {ordered[len(ordered)//2]:6}")
        print(f"  p95 over all runs               : {ordered[int(len(ordered)*0.95)]:6}")
        print(f"  max                             : {max(per_alert_counts):6}")
    if leaking:
        ol = sorted(leaking)
        print(f"  mean over LEAKING runs only     : {statistics.mean(leaking):6.2f}")
        print(f"  median over leaking runs        : {ol[len(ol)//2]:6}")
    print(f"\n  for contrast, tokens the shipped path DID mint, mean per run: "
          f"{statistics.mean(shipped_tokens):.2f}")

    # ── per class ──
    print("\n" + "=" * 74)
    print("BY CLASS (occurrences, runs affected, distinct entities named)")
    print("=" * 74)
    print(f"  {'class':30} {'occurrences':>12} {'runs':>8} {'% runs':>8} {'distinct':>9}")
    print(f"  {'-' * 30} {'-' * 12:>12} {'-' * 8:>8} {'-' * 8:>8} {'-' * 9:>9}")
    for name, n in per_class_occurrences.most_common():
        runs = per_class_runs[name]
        print(f"  {name:30} {n:12} {runs:8} {runs / scanned * 100:7.1f}% "
              f"{len(per_class_distinct[name]):9}")
    if not per_class_occurrences:
        print("  (nothing — which with a passing control means a clean corpus)")

    print(f"\n  secrets surviving to the model: {sum(secret_occurrences.values())} "
          f"occurrence(s) across {secret_runs} run(s) "
          f"({secret_runs / scanned * 100:.1f}%)")
    for label, n in secret_occurrences.most_common(8):
        print(f"      {label:24} {n}")

    # ── per shipper and per tenant ──
    for title, grouped, group_runs in (
        ("BY SHIPPER (alert_source)", by_shipper, shipper_runs),
        ("BY TENANT (tenant_id — the authoritative discriminator)", by_tenant, tenant_runs),
    ):
        print("\n" + "=" * 74)
        print(title)
        print("=" * 74)
        for group in sorted(group_runs, key=lambda g: -group_runs[g]):
            counts = grouped.get(group, Counter())
            runs = group_runs[group]
            per_run = sum(counts.values()) / runs if runs else 0
            print(f"  {group:24} runs={runs:6}  leaked occurrences="
                  f"{sum(counts.values()):7}  per run={per_run:6.2f}")
            for name, n in counts.most_common(4):
                print(f"      {name:30} {n:7}")

    # ── the colon gap, by field name ──
    print("\n" + "=" * 74)
    print("THE COLON GAP: WHICH FIELD NAMES CARRY IT (names only, no values)")
    print("=" * 74)
    if colon_keys:
        for key, n in colon_keys.most_common(20):
            print(f"  {key:46} {n:7}")
    else:
        print("  none — no colon-separated account key in the corpus")


if __name__ == "__main__":
    main()
