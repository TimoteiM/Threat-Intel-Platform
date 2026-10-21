"""Are the `iban` and `card` detector hits actually financial data?

13,443 rose to 23,293 once the large bodies were included, and `iban` is the
largest single label. That is the number someone puts in a slide, so it gets
validated before it gets quoted.

Both labels have a real checksum, and only one of them is being used:

* **IBAN** carries an ISO 13616 mod-97 check and a per-country length. The
  detector pattern checks **neither** — it matches `[A-Z]{2}\\d{2}` followed
  by alphanumeric groups, which is also the shape of a GUID fragment, a
  base32 token and plenty of vendor identifiers.
* **card** is already Luhn-filtered by `_is_real_secret`, so every hit passes
  Luhn. Luhn alone is weak: a random 16-digit string passes it about 1 time
  in 10. The additional evidence is the issuer prefix — a real card starts
  with a registered IIN and has the length that brand uses.

Prints counts only. No candidate values, no digits, nothing that could be a
real account if any of them are.
"""
from __future__ import annotations

import pathlib
import re
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services.log_secret_sanitizer import _PATTERNS, _is_real_secret

# Taken FROM the sanitiser, not retyped. A copied regex drifts from the one
# that actually produced the counts being validated, and then the validation
# is of something else.
_BY_LABEL = {label: rx for label, rx in _PATTERNS}
CARD_RE = _BY_LABEL["card"]
IBAN_RE = _BY_LABEL["iban"]

#: ISO 13616 registry: country -> total IBAN length. A country absent here
#: does not issue IBANs, so a match claiming it is not an IBAN.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22,
    "VG": 24, "XK": 20,
}


def iban_valid(candidate: str) -> tuple[bool, str]:
    """ISO 13616: known country, right length for it, mod-97 == 1."""
    value = re.sub(r"[ -]", "", candidate).upper()
    country = value[:2]
    if country not in IBAN_LENGTHS:
        return False, "country does not issue IBANs"
    if len(value) != IBAN_LENGTHS[country]:
        return False, "wrong length for that country"
    rearranged = value[4:] + value[:4]
    total = 0
    for char in rearranged:
        if char.isdigit():
            total = (total * 10 + int(char)) % 97
        elif char.isalpha():
            total = (total * 100 + (ord(char) - 55)) % 97
        else:
            return False, "non-alphanumeric"
    return (total == 1), ("mod-97 passes" if total == 1 else "mod-97 fails")


def card_brand(candidate: str) -> str:
    """A registered issuer prefix with the length that brand uses, or not."""
    digits = re.sub(r"[ -]", "", candidate)
    n = len(digits)
    if digits.startswith("4") and n in (13, 16, 19):
        return "visa"
    if n == 16 and (51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720):
        return "mastercard"
    if n == 15 and digits[:2] in ("34", "37"):
        return "amex"
    if n == 16 and (digits.startswith("6011") or digits[:2] == "65"
                    or 644 <= int(digits[:3]) <= 649):
        return "discover"
    if n in (14, 16, 19) and (digits[:2] in ("36", "38")
                              or 300 <= int(digits[:3]) <= 305):
        return "diners"
    if n == 16 and 3528 <= int(digits[:4]) <= 3589:
        return "jcb"
    return "no registered issuer prefix"


def main() -> None:
    engine = create_engine(get_settings().database_sync_url)

    iban_total = card_total = 0
    iban_valid_n = card_valid_n = 0
    iban_why: Counter = Counter()
    card_why: Counter = Counter()
    iban_runs: set = set()
    card_runs: set = set()
    iban_valid_runs: set = set()
    card_valid_runs: set = set()
    iban_distinct: set = set()
    card_distinct: set = set()
    iban_valid_distinct: set = set()
    card_valid_distinct: set = set()

    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id::text, alert_body FROM alert_body_investigation_runs
            WHERE alert_body <> ''
        """))
        for n, (rid, body) in enumerate(rows, 1):
            for match in IBAN_RE.finditer(body):
                value = match.group("secret")
                if not _is_real_secret("iban", value):
                    continue
                iban_total += 1
                iban_runs.add(rid)
                iban_distinct.add(value)
                ok, why = iban_valid(value)
                iban_why[why] += 1
                if ok:
                    iban_valid_n += 1
                    iban_valid_runs.add(rid)
                    iban_valid_distinct.add(value)
            for match in CARD_RE.finditer(body):
                value = match.group("secret")
                if not _is_real_secret("card", value):
                    continue
                card_total += 1
                card_runs.add(rid)
                card_distinct.add(value)
                brand = card_brand(value)
                card_why[brand] += 1
                if brand != "no registered issuer prefix":
                    card_valid_n += 1
                    card_valid_runs.add(rid)
                    card_valid_distinct.add(value)
            if n % 2500 == 0:
                print(f"  … {n} runs", file=sys.stderr)

    print("=" * 72)
    print("IBAN — detector hits against ISO 13616")
    print("=" * 72)
    print(f"  detector hits (what the 23,293 total counts) : {iban_total}")
    print(f"  distinct candidate strings                   : {len(iban_distinct)}")
    print(f"  runs affected                                : {len(iban_runs)}")
    print(f"  PASS country + length + mod-97               : {iban_valid_n}")
    print(f"  distinct that pass                           : {len(iban_valid_distinct)}")
    print(f"  runs with a passing candidate                : {len(iban_valid_runs)}")
    print("  why the rest fail:")
    for why, k in iban_why.most_common():
        print(f"      {why:34} {k:7}")

    print("\n" + "=" * 72)
    print("CARD — Luhn already passed; checked for a registered issuer prefix")
    print("=" * 72)
    print(f"  detector hits (Luhn-passing)                 : {card_total}")
    print(f"  distinct candidate strings                   : {len(card_distinct)}")
    print(f"  runs affected                                : {len(card_runs)}")
    print(f"  PASS issuer prefix + brand length            : {card_valid_n}")
    print(f"  distinct that pass                           : {len(card_valid_distinct)}")
    print(f"  runs with a passing candidate                : {len(card_valid_runs)}")
    print("  breakdown:")
    for brand, k in card_why.most_common():
        print(f"      {brand:34} {k:7}")


if __name__ == "__main__":
    main()
