"""
Domain Similarity Engine — detects typosquatting and visual lookalikes.

Pure-Python implementation. No external dependencies.

Called during analysis when a client_domain is provided.
Produces DomainSimilarityEvidence that becomes part of the evidence object
and generates investigative signals for the Claude analyst.
"""

from __future__ import annotations

from app.models.schemas import (
    DomainSimilarityEvidence,
    HomoglyphMatch,
    TyposquattingTechnique,
)


# ═════════════════════════════════════════════════
# Homoglyph mapping — characters that look alike
# ═════════════════════════════════════════════════

# Maps a character to the set of characters it can be confused with.
# Bidirectional: if a→b then b→a is also implied during comparison.
HOMOGLYPH_MAP: dict[str, set[str]] = {
    # Latin ↔ digit
    "o": {"0", "О", "о"},       # Latin o ↔ digit 0 ↔ Cyrillic О/о
    "0": {"o", "O", "О", "о"},
    "l": {"1", "i", "I", "|"},
    "1": {"l", "i", "I", "|"},
    "i": {"1", "l", "!", "|"},
    "s": {"5", "$"},
    "5": {"s", "$"},
    "b": {"6"},
    "6": {"b"},
    "g": {"9", "q"},
    "9": {"g", "q"},
    "q": {"9", "g"},
    "z": {"2"},
    "2": {"z"},

    # Latin ↔ Cyrillic (IDN homograph attacks)
    "a": {"а"},   # Cyrillic а
    "e": {"е"},   # Cyrillic е
    "p": {"р"},   # Cyrillic р
    "c": {"с"},   # Cyrillic с
    "x": {"х"},   # Cyrillic х
    "y": {"у"},   # Cyrillic у
    "k": {"к"},   # Cyrillic к
    "m": {"м"},   # Cyrillic м
    "t": {"т"},   # Cyrillic т
    "n": {"п"},   # Cyrillic п (visual, not exact)

    # Common visual confusions (Latin)
    "w": {"vv"},
    "d": {"cl"},
}

# Multi-char homoglyph sequences: a multi-char string that looks like a single char
MULTICHAR_HOMOGLYPHS: dict[str, str] = {
    "rn": "m",
    "cl": "d",
    "vv": "w",
    "nn": "m",  # nn can look like m in some fonts
    "li": "li",  # less useful but tracked
}


def analyze_similarity(
    investigated_domain: str,
    client_domain: str,
) -> DomainSimilarityEvidence:
    """
    Run full similarity analysis between investigated domain and client domain.

    Returns a DomainSimilarityEvidence object with all metrics and detections.
    """
    inv = investigated_domain.lower().strip()
    cli = client_domain.lower().strip()

    # Split into name and TLD parts
    inv_name, inv_tld = _split_domain(inv)
    cli_name, cli_tld = _split_domain(cli)

    # Core metrics
    edit_dist = _levenshtein_distance(inv_name, cli_name)
    max_len = max(len(inv_name), len(cli_name), 1)
    normalized_dist = edit_dist / max_len

    # Detection passes
    techniques = _detect_typosquatting_techniques(inv, cli, inv_name, cli_name, inv_tld, cli_tld)
    homoglyphs = _detect_homoglyphs(inv_name, cli_name)

    # Scores
    visual_sim = _compute_visual_similarity(inv_name, cli_name, homoglyphs)
    overall = _compute_overall_score(edit_dist, max_len, visual_sim, techniques, homoglyphs, inv_tld, cli_tld)

    is_typosquat = len(techniques) > 0 and overall >= 50
    is_lookalike = visual_sim >= 0.7 and len(homoglyphs) > 0

    summary = _build_summary(inv, cli, overall, is_typosquat, is_lookalike, techniques, homoglyphs)

    return DomainSimilarityEvidence(
        client_domain=client_domain,
        investigated_domain=investigated_domain,
        levenshtein_distance=edit_dist,
        normalized_distance=round(normalized_dist, 3),
        visual_similarity_score=round(visual_sim, 3),
        overall_similarity_score=overall,
        typosquatting_techniques=techniques,
        homoglyph_matches=homoglyphs,
        is_potential_typosquat=is_typosquat,
        is_visual_lookalike=is_lookalike,
        summary=summary,
    )


# ═════════════════════════════════════════════════
# Levenshtein distance
# ═════════════════════════════════════════════════

def _levenshtein_distance(s1: str, s2: str) -> int:
    """Standard Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Insertion, deletion, substitution
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (0 if c1 == c2 else 1)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ═════════════════════════════════════════════════
# Typosquatting technique detection
# ═════════════════════════════════════════════════

def _detect_typosquatting_techniques(
    inv_full: str,
    cli_full: str,
    inv_name: str,
    cli_name: str,
    inv_tld: str,
    cli_tld: str,
) -> list[TyposquattingTechnique]:
    """Detect specific typosquatting attack techniques."""
    techniques: list[TyposquattingTechnique] = []

    # 1. Character omission: client has a char that investigated skips
    if len(inv_name) == len(cli_name) - 1:
        for i in range(len(cli_name)):
            candidate = cli_name[:i] + cli_name[i + 1:]
            if candidate == inv_name:
                techniques.append(TyposquattingTechnique(
                    technique="character_omission",
                    description=f"Missing '{cli_name[i]}' at position {i} — '{inv_name}' vs '{cli_name}'",
                    original_segment=cli_name,
                    modified_segment=inv_name,
                ))
                break

    # 2. Character insertion: investigated has an extra char
    if len(inv_name) == len(cli_name) + 1:
        for i in range(len(inv_name)):
            candidate = inv_name[:i] + inv_name[i + 1:]
            if candidate == cli_name:
                techniques.append(TyposquattingTechnique(
                    technique="character_insertion",
                    description=f"Extra '{inv_name[i]}' inserted at position {i} — '{inv_name}' vs '{cli_name}'",
                    original_segment=cli_name,
                    modified_segment=inv_name,
                ))
                break

    # 3. Character swap / transposition: adjacent characters swapped
    if len(inv_name) == len(cli_name):
        for i in range(len(cli_name) - 1):
            swapped = list(cli_name)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            if "".join(swapped) == inv_name:
                techniques.append(TyposquattingTechnique(
                    technique="character_transposition",
                    description=f"Characters '{cli_name[i]}{cli_name[i+1]}' swapped at position {i} — '{inv_name}' vs '{cli_name}'",
                    original_segment=cli_name[i:i+2],
                    modified_segment=inv_name[i:i+2],
                ))
                break

    # 4. Character replacement: same length, one char different
    if len(inv_name) == len(cli_name):
        diffs = [(i, cli_name[i], inv_name[i]) for i in range(len(cli_name)) if cli_name[i] != inv_name[i]]
        if len(diffs) == 1:
            pos, orig, repl = diffs[0]
            techniques.append(TyposquattingTechnique(
                technique="character_replacement",
                description=f"'{orig}' replaced with '{repl}' at position {pos} — '{inv_name}' vs '{cli_name}'",
                original_segment=orig,
                modified_segment=repl,
            ))

    # 5. TLD swap
    if inv_name == cli_name and inv_tld != cli_tld:
        techniques.append(TyposquattingTechnique(
            technique="tld_swap",
            description=f"Same name but different TLD: '.{inv_tld}' vs '.{cli_tld}'",
            original_segment=f".{cli_tld}",
            modified_segment=f".{inv_tld}",
        ))

    # 6. Hyphenation: investigated adds hyphens to break up the client name
    if "-" in inv_name and "-" not in cli_name:
        dehyphenated = inv_name.replace("-", "")
        if dehyphenated == cli_name:
            techniques.append(TyposquattingTechnique(
                technique="hyphenation",
                description=f"Client domain name split with hyphens: '{inv_name}' vs '{cli_name}'",
                original_segment=cli_name,
                modified_segment=inv_name,
            ))
        elif _levenshtein_distance(dehyphenated, cli_name) <= 1:
            techniques.append(TyposquattingTechnique(
                technique="hyphenation",
                description=f"Hyphenated variant closely resembles client: '{inv_name}' vs '{cli_name}'",
                original_segment=cli_name,
                modified_segment=inv_name,
            ))

    # 7. Subdomain trick: client domain appears as subdomain of investigated
    # e.g., "google.com.evil.com" targeting "google.com"
    if cli_full in inv_full and inv_full != cli_full:
        techniques.append(TyposquattingTechnique(
            technique="subdomain_impersonation",
            description=f"Client domain '{cli_full}' embedded as subdomain in '{inv_full}'",
            original_segment=cli_full,
            modified_segment=inv_full,
        ))

    # 8. Dot omission / combosquatting
    # e.g., "googlecom.com" or "google-security.com"
    if cli_name in inv_name and inv_name != cli_name:
        extra = inv_name.replace(cli_name, "", 1)
        if extra:
            techniques.append(TyposquattingTechnique(
                technique="combosquatting",
                description=f"Client name '{cli_name}' with added segment '{extra}' — '{inv_name}'",
                original_segment=cli_name,
                modified_segment=inv_name,
            ))

    return techniques


# ═════════════════════════════════════════════════
# Homoglyph detection
# ═════════════════════════════════════════════════

def _detect_homoglyphs(inv_name: str, cli_name: str) -> list[HomoglyphMatch]:
    """Detect characters in the investigated domain that are visual lookalikes of client domain chars."""
    matches: list[HomoglyphMatch] = []

    # Single-char homoglyphs
    if len(inv_name) == len(cli_name):
        for i in range(len(cli_name)):
            if inv_name[i] != cli_name[i]:
                confusables = HOMOGLYPH_MAP.get(cli_name[i], set())
                if inv_name[i] in confusables:
                    matches.append(HomoglyphMatch(
                        position=i,
                        original_char=cli_name[i],
                        replaced_with=inv_name[i],
                        description=f"'{cli_name[i]}' replaced with visually similar '{inv_name[i]}' at position {i}",
                    ))

    # Multi-char homoglyphs: check if client has single char where investigated has multi-char sequence
    for multi, single in MULTICHAR_HOMOGLYPHS.items():
        if multi in inv_name and single in cli_name:
            # Check if replacing multi with single in investigated yields something closer to client
            replaced = inv_name.replace(multi, single, 1)
            if _levenshtein_distance(replaced, cli_name) < _levenshtein_distance(inv_name, cli_name):
                pos = inv_name.index(multi)
                matches.append(HomoglyphMatch(
                    position=pos,
                    original_char=single,
                    replaced_with=multi,
                    description=f"'{single}' replaced with multi-char lookalike '{multi}' at position {pos}",
                ))

        # Reverse: client has multi-char, investigated has single
        if multi in cli_name and single in inv_name:
            replaced = cli_name.replace(multi, single, 1)
            if _levenshtein_distance(inv_name, replaced) < _levenshtein_distance(inv_name, cli_name):
                pos = cli_name.index(multi)
                matches.append(HomoglyphMatch(
                    position=pos,
                    original_char=multi,
                    replaced_with=single,
                    description=f"Multi-char '{multi}' in client collapsed to '{single}' at position {pos}",
                ))

    return matches


# ═════════════════════════════════════════════════
# Visual similarity scoring
# ═════════════════════════════════════════════════

def _compute_visual_similarity(
    inv_name: str,
    cli_name: str,
    homoglyphs: list[HomoglyphMatch],
) -> float:
    """
    Compute visual similarity score (0.0–1.0).

    Treats homoglyphs as matching characters when computing similarity.
    """
    if not inv_name or not cli_name:
        return 0.0

    if inv_name == cli_name:
        return 1.0

    max_len = max(len(inv_name), len(cli_name))

    # Start with character-level match ratio
    if len(inv_name) == len(cli_name):
        exact_matches = sum(1 for a, b in zip(inv_name, cli_name) if a == b)
        homoglyph_positions = {h.position for h in homoglyphs}
        visual_matches = exact_matches + len(homoglyph_positions)
        return min(visual_matches / max_len, 1.0)

    # Different lengths: use normalized Levenshtein as base
    edit_dist = _levenshtein_distance(inv_name, cli_name)
    base_sim = 1.0 - (edit_dist / max_len)

    # Boost for homoglyph matches
    homoglyph_boost = len(homoglyphs) * 0.1
    return min(base_sim + homoglyph_boost, 1.0)


# ═════════════════════════════════════════════════
# Overall score computation
# ═════════════════════════════════════════════════

def _compute_overall_score(
    edit_distance: int,
    max_len: int,
    visual_sim: float,
    techniques: list[TyposquattingTechnique],
    homoglyphs: list[HomoglyphMatch],
    inv_tld: str,
    cli_tld: str,
) -> int:
    """
    Compute overall similarity score (0–100).

    Higher = more likely to be an impersonation attempt.
    Weighs: edit distance, visual similarity, detected techniques, homoglyphs.
    """
    if max_len == 0:
        return 0

    # Base score from normalized edit distance (inverted: closer = higher score)
    edit_sim = 1.0 - (edit_distance / max_len)
    base_score = edit_sim * 40  # Up to 40 points from edit distance

    # Visual similarity contribution
    visual_score = visual_sim * 25  # Up to 25 points

    # Technique detection bonus
    technique_score = min(len(techniques) * 10, 25)  # Up to 25 points

    # Homoglyph bonus
    homoglyph_score = min(len(homoglyphs) * 5, 10)  # Up to 10 points

    total = base_score + visual_score + technique_score + homoglyph_score

    # TLD match bonus: same TLD means more suspicious
    if inv_tld == cli_tld:
        total = min(total * 1.05, 100)

    return min(int(round(total)), 100)


# ═════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════

def _split_domain(domain: str) -> tuple[str, str]:
    """
    Split domain into (name, tld).

    Handles common multi-part TLDs (co.uk, com.au, etc.)
    """
    multi_tlds = {
        "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
        "com.au", "com.br", "com.mx", "com.ar", "com.sg", "com.tw",
        "org.uk", "org.au", "net.au", "net.uk",
        "ac.uk", "gov.uk", "gov.au",
    }

    parts = domain.split(".")
    if len(parts) <= 1:
        return domain, ""

    # Check for multi-part TLD
    if len(parts) >= 3:
        potential_tld = ".".join(parts[-2:])
        if potential_tld in multi_tlds:
            return ".".join(parts[:-2]), potential_tld

    return ".".join(parts[:-1]), parts[-1]


def _build_summary(
    inv: str,
    cli: str,
    overall: int,
    is_typosquat: bool,
    is_lookalike: bool,
    techniques: list[TyposquattingTechnique],
    homoglyphs: list[HomoglyphMatch],
) -> str:
    """Build a one-line summary of the similarity analysis."""
    if overall < 20:
        return f"Low similarity ({overall}/100) between '{inv}' and client domain '{cli}'"

    parts = []
    if is_typosquat:
        tech_names = [t.technique.replace("_", " ") for t in techniques[:3]]
        parts.append(f"potential typosquat ({', '.join(tech_names)})")
    if is_lookalike:
        parts.append(f"{len(homoglyphs)} homoglyph substitution(s)")

    if parts:
        detail = "; ".join(parts)
        return f"High similarity ({overall}/100): '{inv}' vs client '{cli}' — {detail}"

    return f"Moderate similarity ({overall}/100) between '{inv}' and client domain '{cli}'"
