"""The two labelled changes in b-2, measured separately over the corpus.

They are deployed together and they have opposite properties, so they are
measured apart. A single "before/after" over both would let the reversible
change inherit the credibility of the irreversible one, or the reverse.

**Change 1 — identifier tokenisation.** Claim: the identity function. Run
`boundary.tokenize` then `boundary.restore` over every alert body and count
byte-identical round trips.

**Change 2 — secret redaction.** Claim: deliberately NOT the identity
function. Count the runs whose model-facing text changes, by label, and say
what it changes to.

Both run through `_protect_outbound`, the shipped function, so this measures
what will happen rather than a model of it.

Same stated bound as the other scans: `sanitize_entries` is superlinear, so
bodies at or above 100,000 chars are counted and excluded. Override with
`--max-chars`.
"""
from __future__ import annotations

import pathlib
import re
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services import alert_body_ai_service as ai
from app.services import log_secret_sanitizer as secrets
from app.services import token_boundary as tb

MAX_BODY_CHARS = 100_000
SECRET_RE = re.compile(r"<SECRET:([A-Za-z0-9_]+):[0-9a-f]{6}>")
TOKEN_RE = re.compile(r"\[(?:HOST|ACCOUNT|IP|EMAIL|SID)_[0-9a-f]{12}_\d+\]")

#: Validated 2026-10-21: `iban` is 0-for-13,778 against ISO 13616 mod-97 and
#: `card` has no registered issuer prefix on 4,413 of 4,515. They are counted
#: separately below and excluded from the credible total, because 23,293 is
#: the number that would otherwise end up on a slide.
UNVALIDATED_LABELS = {"iban", "card", "national_id"}


def main() -> None:
    global MAX_BODY_CHARS
    if "--max-chars" in sys.argv:
        MAX_BODY_CHARS = int(sys.argv[sys.argv.index("--max-chars") + 1])

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        excluded = conn.execute(text("""
            SELECT COUNT(*) FROM alert_body_investigation_runs
            WHERE alert_body <> '' AND LENGTH(alert_body) >= :cap
        """), {"cap": MAX_BODY_CHARS}).scalar()
        rows = conn.execute(text("""
            SELECT id::text, alert_body FROM alert_body_investigation_runs
            WHERE alert_body <> '' AND LENGTH(alert_body) < :cap
        """), {"cap": MAX_BODY_CHARS})

        n = 0
        # change 1
        identical = 0
        differing = 0
        diff_kinds: Counter = Counter()
        minted: list[int] = []
        no_token_bodies = 0
        # change 2
        secret_runs_credible: set = set()
        secret_runs_unvalidated: set = set()
        secret_occ: Counter = Counter()
        chars_before = 0
        chars_after = 0

        for rid, body in rows:
            n += 1
            boundary = tb.in_memory(tenant_id="measure", investigation_id=rid)

            # ── change 1, alone: identifiers only, no secret layer ──
            ident_only = boundary.tokenize(body)
            back = boundary.restore(ident_only)
            k = len(boundary.token_map)
            minted.append(k)
            if k == 0:
                no_token_bodies += 1
            if back == body:
                identical += 1
            else:
                differing += 1
                if back.lower() == body.lower():
                    diff_kinds["case-only"] += 1
                elif len(back) != len(body):
                    lost = {c for c in set(body) if body.count(c) > back.count(c)}
                    label = ("carriage returns only"
                             if lost == {"\r"} else f"length changed, lost {sorted(lost)!r}")
                    diff_kinds[label] += 1
                else:
                    diff_kinds["same length, chars changed"] += 1

            # ── change 2, alone: what the secret layer removes ──
            redacted = secrets.sanitize_text(body).text
            labels = Counter(SECRET_RE.findall(redacted))
            if labels:
                credible = {l: c for l, c in labels.items()
                            if l not in UNVALIDATED_LABELS}
                unvalidated = {l: c for l, c in labels.items()
                               if l in UNVALIDATED_LABELS}
                secret_occ.update(labels)
                if credible:
                    secret_runs_credible.add(rid)
                if unvalidated:
                    secret_runs_unvalidated.add(rid)

            # ── and the shipped function, both layers, end to end ──
            sent = ai._protect_outbound(body, boundary=boundary)
            chars_before += len(body)
            chars_after += len(sent)

            if n % 2500 == 0:
                print(f"  … {n} runs", file=sys.stderr)

    print("=" * 74)
    print("CHANGE 1 — identifier tokenisation. Claim: the identity function.")
    print("=" * 74)
    print(f"  bodies tested                  : {n}")
    print(f"  EXCLUDED by the {MAX_BODY_CHARS:,}-char bound : {excluded}")
    print(f"  round trip byte-IDENTICAL      : {identical}  "
          f"({identical / n * 100:.3f}%)")
    print(f"  differing                      : {differing}")
    for kind, k in diff_kinds.most_common():
        print(f"      {kind:44} {k}")
    print(f"  tokens minted, mean            : {sum(minted) / len(minted):.2f}"
          f"   max: {max(minted)}")
    print(f"  bodies minting NOTHING         : {no_token_bodies} "
          f"({no_token_bodies / n * 100:.2f}%) — identity is trivial for these,")
    print(f"                                   so the {identical} above is not "
          f"achieved by inaction")

    print("\n" + "=" * 74)
    print("CHANGE 2 — secret redaction. Claim: deliberately NOT identity.")
    print("=" * 74)
    print(f"  runs whose model-facing text CHANGES (credible labels): "
          f"{len(secret_runs_credible)} ({len(secret_runs_credible) / n * 100:.1f}%)")
    print(f"  runs changing only on UNVALIDATED labels             : "
          f"{len(secret_runs_unvalidated)} ({len(secret_runs_unvalidated) / n * 100:.1f}%)")
    print("\n  what changes, per label — the value becomes <SECRET:label:6hex>:")
    print(f"      {'label':22} {'occurrences':>12}  {'status':<14}")
    print(f"      {'-' * 22} {'-' * 12:>12}  {'-' * 14:<14}")
    credible_total = unvalidated_total = 0
    for label, k in secret_occ.most_common():
        status = "UNVALIDATED" if label in UNVALIDATED_LABELS else "key-anchored"
        if label in UNVALIDATED_LABELS:
            unvalidated_total += k
        else:
            credible_total += k
        print(f"      {label:22} {k:12}  {status:<14}")
    print(f"\n  credible total    : {credible_total}")
    print(f"  unvalidated total : {unvalidated_total}  "
          f"(iban 0-for-13,778 on mod-97; card no issuer prefix on 4,413 of 4,515)")

    print("\n" + "=" * 74)
    print("BOTH, through the shipped _protect_outbound")
    print("=" * 74)
    print(f"  characters in  : {chars_before:,}")
    print(f"  characters out : {chars_after:,}  "
          f"({(chars_after - chars_before) / chars_before * 100:+.2f}%)")
    print("  A token is longer than most hostnames and a placeholder shorter")
    print("  than most credentials, so this is a cost figure, not a safety one.")


if __name__ == "__main__":
    main()
