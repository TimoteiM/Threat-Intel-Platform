# Writing tests here

Rules, each with the instance that produced it. If a rule has no instance, it
is somebody's preference and belongs in a review comment instead.

---

## 1. A test that patches the thing under test agrees with the mistake

**The rule.** When the behaviour you are checking is *how a function obtains
its collaborator*, you may not replace that collaborator. Patch the layer
**below** it — settings, the environment, the database — and let the real
construction run.

**Why it is not obvious.** Patching the collaborator looks like good
isolation, and it is, for a test about what the function does with the
collaborator. The trap is that it also replaces the step where the function
*chooses* one. Every assertion then passes, because the test supplied the
object the code failed to build.

**The instance.** `token_boundary._seal()` sealed the token map with

```python
box = SecretBox()                     # ← takes keys as an argument; default None
```

`SecretBox.__init__` is `(self, keys: list[str] | None = None)`, so a bare
constructor is **never configured**, and `_seal` raised
`TokenBoundaryError("no INTEGRATION_ENCRYPTION_KEY is configured")` on every
call. No token boundary could be opened at all. The platform's own factory,
`secret_box.from_settings()`, had been there the whole time and had four other
callers.

The test written alongside it did this:

```python
monkeypatch.setattr(secret_box, "SecretBox", lambda *a, **k: _Fake())
```

— and passed. It asserted that `_seal` refuses when the box is unconfigured,
using a box it had made unconfigured itself. The defect was *which box
`_seal` asks for*, and that was the one thing the test had taken over.

What caught it:

```python
monkeypatch.setattr(app_config, "get_settings", lambda: _Settings())  # key in settings
sealed, key_id = tb._seal({"[HOST_abc_1]": "EXPDC002"})               # real from_settings()
assert tb._open_sealed(sealed)["[HOST_abc_1]"] == "EXPDC002"
```

Settings are below the seam; `from_settings()` and `SecretBox()` both run for
real. See `test_sealing_goes_through_the_deployment_s_configured_key`.

**How to apply.** Before writing a double, name the seam in one sentence: *"I
am checking that X gets its Y from Z."* Whatever appears after *from* is the
thing you must not replace. Two cheap checks:

- **`grep` the type name across `app/`.** If a factory (`from_settings`,
  `get_*`, `*_for`) has more callers than the bare constructor, the bare
  constructor is probably wrong.
- **Ask what an all-default constructor builds.** `Thing()` with every
  argument optional usually does *not* produce the configured object, and
  "unconfigured" is the state a refusal test will happily accept.

**The same rule, one level out.** It is why the database role split
(`scripts/check_db_privileges.sql`) is introspection against the real cluster
rather than a test with a fake connection: a test that supplies its own
connection cannot see a missing `GRANT`. Measured — the full unit suite run
against a database it could not connect to at all produced **one extra failure
out of 3,281 tests**, and the integration suite *skips* when the server is
unreachable. A suite that fakes the thing under test agrees with the mistake
at any scale.

---

## 2. Patch module objects, never dotted strings

**The rule.**

```python
from app.collectors import intel_collector as _mod
monkeypatch.setattr(_mod, "DNSBL_LISTS", [...])          # yes
monkeypatch.setattr(_mod.requests, "get", _fake_get)     # yes

monkeypatch.setattr("app.collectors.intel_collector.DNSBL_LISTS", [...])  # no
```

**Why.** pytest resolves a dotted target by walking `getattr(app,
"collectors")` from an already-imported `app`. Whether that attribute is bound
depends on what else has been imported first, so in a full-suite run the walk
raises

```
AttributeError: module 'app' has no attribute 'collectors'
```

while running the same file alone passes. A module object is already resolved,
so there is nothing to walk and nothing to fail.

**The instance.** This produced **12 of the 13** entries in
`tolerated-failures.txt` — 27 errors across 6 files — and sat there for days
labelled "monkeypatch target resolution, probably a harness fault". It was,
and the fix was mechanical. The set went from 13 to 1.

**The order-dependence is the tell.** A test that passes alone and fails in
the suite is almost never about the product. Check it before assuming
pollution: `pytest path/to/test_file.py` versus `pytest`.

**Finding them all needs the parser, not `grep`.** The first sweep searched
for `setattr("app.` and declared the file clean; one call had its target on
the next line, so one failure survived and the claim that it was "all
converted" was false. Multi-line calls, `delattr` and `setitem` all need the
same treatment:

```python
for node in ast.walk(ast.parse(path.read_text())):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("setattr", "delattr", "setitem") and node.args):
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and str(arg.value).startswith("app."):
            ...
```

A sweep over source is a search result, and "fixed everywhere" asserts a
search you have to actually run.

---

## 3. Run a new check against a case it must refuse

A check that cannot fail is decoration, and silence from a check whose
predicate can never be true is indistinguishable from silence meaning clean.
So before trusting one, break the thing it watches and watch it complain.

`scripts/check_db_privileges.sql` was exercised both ways — `GRANT SELECT` on
the token map to the application role, then `REVOKE` a grant it needs — and
each produced the right violation. Its two closing queries are inverted
positive controls for the same reason: they print a row when the
introspection is *not* working.

That pass also caught the first draft naming a table that does not exist
(`alerts`, not `client_alerts`), which took the whole file down rather than
passing vacuously — the loud version of the failure.

---

## 4. Tests may pin a decision; they may not pin its reason

Assert the behaviour, and put the measurement that justified it in a comment
or a design note. A test that encodes *why* fails when the reason is
re-measured, which is the one thing that should be allowed to change freely.

---

## 5. Pin an absence the same way you pin a value

`purge_investigation` has no callers, because the loop that would own an
investigation does not exist yet. That is a real property worth asserting, and
`test_the_completion_purge_has_no_caller_yet` asserts it — so the day somebody
wires it up, the test fails and the register row claiming it is unwired has to
be retired. An absence nobody pinned is an absence that silently becomes a
lie.
