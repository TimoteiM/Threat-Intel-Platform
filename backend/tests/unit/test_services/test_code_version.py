"""What a process reports about the code it loaded.

Built after seven backend commits sat pushed and unserved for an afternoon
while every filesystem check said "deployed". The properties below are the
ones that make this answer different from those checks; without them it is
another thing that cannot return the bad answer.
"""

from __future__ import annotations

from pathlib import Path

from app import code_version as mod


def test_the_fingerprint_is_captured_at_import_not_per_call() -> None:
    """A value computed per request reads the bind mount and reports the
    working tree — which is what every check that failed on 2026-10-12 did."""
    first = mod.code_version()["code_fingerprint"]
    second = mod.code_version()["code_fingerprint"]
    assert first == second == mod.CODE_FINGERPRINT


def test_imported_at_is_fixed_for_the_life_of_the_process() -> None:
    assert mod.code_version()["imported_at"] == mod.IMPORTED_AT
    assert mod.code_version()["imported_at"] == mod.IMPORTED_AT


def test_the_fingerprint_is_content_not_mtime(tmp_path: Path) -> None:
    """`touch` changes an mtime without changing the code. A fingerprint that
    moves when nothing moved is a false alarm that trains people to ignore it
    — and an mtime probe is literally what gave a wrong answer today."""
    (tmp_path / "a.py").write_text("x = 1\n")
    before, _ = mod._fingerprint(tmp_path)
    (tmp_path / "a.py").touch()
    after, _ = mod._fingerprint(tmp_path)
    assert before == after

    (tmp_path / "a.py").write_text("x = 2\n")
    assert mod._fingerprint(tmp_path)[0] != before


def test_the_fingerprint_notices_a_new_or_removed_file(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    one, count_one = mod._fingerprint(tmp_path)
    (tmp_path / "b.py").write_text("y = 2\n")
    two, count_two = mod._fingerprint(tmp_path)
    assert one != two
    assert count_two == count_one + 1


def test_the_fingerprint_does_not_depend_on_directory_order(tmp_path: Path) -> None:
    for name in ("c.py", "a.py", "b.py"):
        (tmp_path / name).write_text(f"# {name}\n")
    assert mod._fingerprint(tmp_path)[0] == mod._fingerprint(tmp_path)[0]


def test_pycache_is_ignored(tmp_path: Path) -> None:
    """Compiled files differ between processes that loaded identical source."""
    (tmp_path / "a.py").write_text("x = 1\n")
    before, _ = mod._fingerprint(tmp_path)
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "a.cpython-312.py").write_text("# noise\n")
    assert mod._fingerprint(tmp_path)[0] == before


def test_a_missing_git_is_named_rather_than_blank() -> None:
    """An empty value renders as "unknown" and gets read as "fine"."""
    assert mod.GIT_UNAVAILABLE
    assert "unavailable" in mod.GIT_UNAVAILABLE
    sha = mod.code_version()["git_sha"]
    assert sha, "git_sha must never be empty"
    if sha == mod.GIT_UNAVAILABLE:
        assert "code_fingerprint" in sha  # says what to use instead


def test_the_payload_says_imported_at_is_not_container_start() -> None:
    """With --reload, WatchFiles replaces the child without restarting the
    container, so the two diverge by design and permanently."""
    assert "container" in mod.code_version()["note"]


def test_two_processes_are_compared_on_the_fingerprint() -> None:
    payload = mod.code_version()
    assert set(payload) >= {"code_fingerprint", "code_files", "imported_at", "git_sha"}
    assert payload["code_files"] > 0
