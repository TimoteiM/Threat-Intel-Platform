# What the two-way token boundary still misses

**For a reviewer.** This is the list of identifier classes that survive
tokenisation and reach a model, written to be argued with rather than to
reassure. Every row marked *measured* was run through
`app/services/token_boundary.py` on 2026-10-19 and behaved as described; the
rows marked *structural* are properties of the design that no test can
observe.

The measured gaps are pinned by `test_the_known_gaps_are_still_these` in
`tests/unit/test_services/test_token_boundary.py`, which asserts they are
**still broken**. When one of them starts passing, that test fails and this
document is out of date — which is the point. A documented gap nothing checks
becomes a lie quietly.

Two of these were found while writing the tests, not predicted: the
alphabetic-hostname rule and the secret field list. The second is fixed; the
first is not.

---

## Measured: identifiers that reach the model today

| # | class | example | why |
|---|---|---|---|
| 1 | **Single-label hostname with no digit** | `FILESERVER`, `MAILGW`, `EXCHANGE`, `PRINTSRV` | **Not tokenised even with a key in front of it** — `computer="FILESERVER"` passes through whole. A name needs a digit or a dot to be recognised, so `srv01` and `web.int.expertware.net` are caught and `MAILGW` is not. In a Windows estate these are ordinary names, which makes this the most serious row in the table. |
| 2 | **Bare `DOMAIN\user` in free text** | `User INT\jdoe ran it` | The account patterns are *keyed*: they need `user=`, `srcuser="` or `Account Name:`. A domain-qualified account in a sentence has no key. |
| 3 | **Bare NetBIOS hostname with no keyword** | `EXPREU002 reported` | Same cause. `the host EXPREU002` is caught because `host ` is a keyword; the bare token is not. |
| 4 | **IPv6** | `fe80::1c2d:3e4f:5a6b:7c8d` | No pattern exists. IPv4 only, and the regex is explicitly four dotted octets. |
| 5 | **UNC paths** | `\\EXPFS01\finance\q3.xlsx` | The share path is untouched and the **server name leaks with it**. A Windows path with a user in it (`C:\Users\jdoe\…`) *is* handled; the UNC form is not. |
| 6 | **MAC addresses** | `00:1A:2B:3C:4D:5E` | No pattern. Identifies a device across networks and persists through re-imaging. |
| 7 | **Case variants of one host** | `EXPDC002` and `expdc002` | Not a leak — both are tokenised — but they get **two different tokens**, so the model sees two machines and may run two queries. Deliberately not fixed: normalising the key means choosing which casing is substituted back into a query, and that is wrong for any case-sensitive backend. |

## Structural: properties of the design, not bugs in it

| # | class | why it cannot be closed here |
|---|---|---|
| 8 | **Identifiers inside encoded payloads** | `powershell -enc <base64>` is one opaque string. Nothing decodes it, so a hostname inside survives. Decoding it would mean executing an attacker-controlled decoder on untrusted input. |
| 9 | **Semantic identification without the identifier** | A model can write "the domain controller in the Bucharest office" from tokenised input. No tokeniser addresses this; only the prompt and the reviewer do. |
| 10 | **Identifiers that are not of a known class** | Ticket ids, asset tags, serial numbers, licence keys, phone numbers, and personal names appearing as free text rather than as accounts. The boundary covers host, account, email, IP and SID — nothing else has a class. |
| 11 | **The map is the reverse index** | `investigation_token_maps` holds the real values by construction; reversibility requires it. Anyone with read access to that table has every identifier in it. Mitigated by the scope and the TTL, **not eliminated**. |
| 12 | **Fingerprint collision** | Six hex characters is one collision per ~16.7M scopes. A collision alone grants nothing — the token index must also exist in the other map — but it is the bound and it is stated rather than implied. |
| 13 | **A caller's own traceback** | A traceback renders each frame's *source line*. `b.tokenize("host EXPDC002")` puts the literal in the caller's frame, and the boundary cannot reach into its caller. Values must be passed by variable. The boundary itself holds values only in locals, which Python does not render. |
| 14 | **`restore()` is deliberately forgiving** | Unlike `detokenize_query`, it leaves an unknown token standing rather than raising, because a narrative containing `[HOST_9]` is a visible defect while a refused report is no report. That means a token a model invents appears in a report. |
| 15 | **Values the detector decides are not identifiers** | `_is_redactable_host` deliberately rejects file names, field names, code identifiers and SIEM field paths — added because a .NET crash report had 35 stack-trace namespaces tokenised as hostnames. Every such exclusion is a place a real host shaped like one of those passes. |

## Fixed while writing this, listed because the class remains

| # | class | what happened |
|---|---|---|
| 16 | **Secrets outside the default field list** | `log_secret_sanitizer.sanitize_records` scans `full_log`, `message` and `process.command_line` — the Wazuh shape. Measured: a credential in `vendor_detail` passed through untouched. **Fixed** — the boundary walks every string rather than taking a field list, with one shared placeholder map so a secret is the same placeholder everywhere. The class remains a hazard for any other caller still using the field list. |
| 17 | **Record fields whose key gives the value meaning** | Walking a record tokenises each value *in isolation*, and `{"agent": {"name": "EXPREU002"}}` is a bare string no keyed pattern can match. Measured: it survived a corpus pass. **Fixed** for the known normalised shape via `DECLARED_FIELDS` (`agent.name`, `agent.ip`, `users`), which synthesises the minimal context the existing detector needs. An unlisted vendor field falls back to the pattern pass — so gaps 1 and 3 apply to it. |

---

## What this means for the reviewer

**The boundary is a reduction, not a guarantee.** It removes the classes it
knows about from the model-facing text and refuses to resolve anything it did
not issue. It does not promise that no identifier reaches a model, and the
tests do not assert that — `test_no_covered_identifier_survives_the_corpus`
asserts that the *covered* classes do not survive, with a companion assertion
that the pass was earned rather than produced by tokenising nothing.

**The strongest property is on the return path, not the outbound one.** An
invented token, an unscoped token, a token from another tenant and a secret
placeholder are all refusals, and detokenisation is all-or-nothing — a query
is either fully resolved or it does not run. That is the half that prevents a
confidently wrong answer about the wrong estate, and it is enforced by the
token grammar rather than by a convention a caller must follow.

**Gap 1 is the one to fix first.** It needs a decision rather than a regex: a
single-label alphabetic token is indistinguishable from an ordinary word, so
covering it means either an allow-list of known estate hosts (which the asset
inventory could supply) or accepting false positives on words like `SYSTEM`,
`NETWORK` and `SERVICE` that appear in every Windows event.
