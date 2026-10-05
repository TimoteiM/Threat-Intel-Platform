"""Read what a submitted file actually says, so the model can read it too.

A `.js` attachment used to reach an analyst as "this is a script, it executes
if opened, VirusTotal says X". The one question they had — *what does it do* —
needed the file opened by hand and pasted into the assistant, which is the step
this removes.

Three things are extracted, all of them source an analyst would otherwise read
themselves:

  * script and text files, decoded;
  * the contents of archives, including `.rar`, unpacked one layer at a time;
  * VBA macro source from Office documents, via oletools.

**Nothing is written to disk.** Entries are read from the archive straight into
memory under a byte cap. That is not a performance choice: an archive that
writes where it likes ("zip slip") cannot, because nothing is ever written, and
a decompression bomb stops at the cap rather than filling a volume. The usual
defence is to extract to a temporary directory and then validate the paths,
which is a defence that has to be remembered every time.

Bounds are stated as constants below and every one of them, when hit, is
reported in `limitations` rather than silently applied. A truncated script that
looks complete is worse than one that says it was cut.

RAR, 7z, CAB and ISO go through `bsdtar` (libarchive), which reads all of them
and is free — `unrar` is not. When the binary is absent the archive is reported
as unreadable rather than treated as empty, because "we could not look" and
"there was nothing inside" are different answers.
"""

from __future__ import annotations

import io
import logging
import re
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# One entry, and everything extracted, in bytes. A phishing script is a few
# kilobytes; these are generous enough that hitting one is itself a finding.
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 8_000_000
MAX_ENTRIES = 200

# How many archives deep to follow. Nesting is a packing trick, not a format,
# and each layer multiplies what a bomb can do.
MAX_DEPTH = 3

# bsdtar is reading hostile input; it does not get to run forever.
EXTERNAL_TIMEOUT_SECONDS = 30

# Handled in-process by the standard library.
_STDLIB_ARCHIVES = {"zip", "tar", "gzip"}

# Handed to bsdtar. libarchive exports readers for every one of these.
_EXTERNAL_ARCHIVES = {"rar", "7z", "cab", "iso", "lha"}

# Extensions whose content is worth reading as source, whatever the magic bytes
# say — a script has no signature to sniff.
SOURCE_EXTENSIONS = {
    ".js", ".jse", ".mjs", ".cjs", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
    ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".py", ".pl", ".rb", ".php",
    ".jar", ".lnk", ".reg", ".inf", ".sct", ".xsl", ".svg", ".html", ".htm",
    ".txt", ".json", ".xml", ".csv", ".eml", ".ini", ".conf", ".yaml", ".yml",
}

_MACRO_EXTENSIONS = {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx"}

# A run of NULs is the cheapest reliable sign that bytes are not text. Checked
# over a prefix because a text file with one stray NUL is still readable.
_NUL_RUN = re.compile(rb"\x00\x00")


@dataclass
class ExtractedFile:
    """One readable thing found inside what was submitted."""

    path: str
    kind: str
    size: int
    text: str
    truncated: bool = False
    depth: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "truncated": self.truncated,
            "depth": self.depth,
            "text": self.text,
        }


@dataclass
class ExtractionResult:
    files: list[ExtractedFile] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    entries_seen: int = 0
    bytes_read: int = 0
    encrypted: bool = False

    def note(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)

    def as_dict(self) -> dict[str, Any]:
        return {
            "files": [f.as_dict() for f in self.files],
            "limitations": list(self.limitations),
            "entries_seen": self.entries_seen,
            "bytes_read": self.bytes_read,
            "encrypted": self.encrypted,
            "readable_files": len(self.files),
        }


def _extension(name: str) -> str:
    base = str(name or "").rsplit("/", 1)[-1].lower()
    return "." + base.rsplit(".", 1)[-1] if "." in base else ""


def looks_textual(data: bytes) -> bool:
    """Whether these bytes are worth showing to a reader as text.

    Deliberately permissive. Obfuscated script is still text, and a
    conservative check here would reject exactly the files worth reading.
    """
    if not data:
        return False
    prefix = data[:4096]
    if _NUL_RUN.search(prefix):
        return False
    printable = sum(1 for b in prefix if 9 <= b <= 13 or 32 <= b <= 126 or b >= 160)
    return printable / len(prefix) > 0.75


def decode(data: bytes) -> str:
    """Bytes to text, preferring the encodings droppers actually use.

    UTF-16 first when the BOM says so: a PowerShell payload written by
    `Out-File` is UTF-16, and read as UTF-8 it becomes NUL-separated letters
    that look like binary and get discarded.
    """
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def sniff(data: bytes) -> str:
    """The container kind, from the bytes rather than the name."""
    signatures = (
        (b"Rar!\x1a\x07", "rar"),
        (b"\x37\x7a\xbc\xaf\x27\x1c", "7z"),
        (b"PK\x03\x04", "zip"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
        (b"%PDF-", "pdf"),
        (b"MZ", "pe"),
        (b"\x7fELF", "elf"),
        (b"\x1f\x8b", "gzip"),
        (b"MSCF", "cab"),
    )
    for signature, kind in signatures:
        if data.startswith(signature):
            return kind
    if len(data) > 32769 * 2 and data[32769:32774] == b"CD001":
        return "iso"
    try:
        if tarfile.is_tarfile(io.BytesIO(data)):
            return "tar"
    except Exception:  # noqa: BLE001 — not a tar, which is the answer
        pass
    return "unknown"


def extract(data: bytes, filename: str = "submitted") -> ExtractionResult:
    """Everything readable in this file, following archives to MAX_DEPTH."""
    result = ExtractionResult()
    _walk(data, filename, result, depth=0)
    return result


def _walk(
    data: bytes, path: str, result: ExtractionResult, *, depth: int,
    declared_size: int | None = None,
) -> None:
    if depth > MAX_DEPTH:
        result.note(
            f"Nested archives deeper than {MAX_DEPTH} levels were not opened "
            f"({path}). Deep nesting is a packing trick, not a format."
        )
        return
    if result.bytes_read >= MAX_TOTAL_BYTES:
        return

    kind = sniff(data)
    extension = _extension(path)

    if kind in _STDLIB_ARCHIVES or (kind == "zip" and extension not in _MACRO_EXTENSIONS):
        # An OOXML document is a zip, and its macro is the part worth reading —
        # but so is any other file an attacker packed beside it, so it is
        # walked as an archive *and* offered to the macro reader.
        _walk_archive(data, path, result, depth=depth, kind=kind)
        if extension in _MACRO_EXTENSIONS:
            _read_macros(data, path, result, depth=depth)
        return

    if kind in _EXTERNAL_ARCHIVES:
        _walk_external(data, path, result, depth=depth, kind=kind)
        return

    if kind == "ole":
        _read_macros(data, path, result, depth=depth)
        return

    if kind in {"pe", "elf"}:
        result.note(f"{path} is a compiled executable; its code is not readable as text.")
        return

    # Anything left: read it if it is text, or if its name says it is source.
    if looks_textual(data) or extension in SOURCE_EXTENSIONS:
        _add(data, path, result, depth=depth, declared_size=declared_size,
             kind="source" if extension in SOURCE_EXTENSIONS else "text")
    elif kind == "pdf":
        result.note(f"{path} is a PDF; its structure is reported separately.")
    else:
        result.note(f"{path} is not text and no reader recognised it.")


def _add(
    data: bytes, path: str, result: ExtractionResult, *, depth: int, kind: str,
    declared_size: int | None = None,
) -> None:
    """`declared_size` is the entry's real length when the container states it.

    Without it the only length available is that of the buffer already read,
    which is the cap plus one — so a 200 MB bomb reported itself as "cut to
    1,000,000 of 1,000,001 bytes". True of the buffer, and wrong about the
    file by two orders of magnitude.
    """
    if len(result.files) >= MAX_ENTRIES:
        result.note(f"Stopped after {MAX_ENTRIES} files; the archive holds more.")
        return
    remaining = MAX_TOTAL_BYTES - result.bytes_read
    if remaining <= 0:
        result.note(
            f"Stopped after {MAX_TOTAL_BYTES:,} bytes of extracted content; "
            "the rest was not read."
        )
        return

    cut = min(MAX_FILE_BYTES, remaining)
    body = data[:cut]
    truncated = len(data) > len(body)
    size = declared_size if declared_size is not None else len(data)
    if truncated:
        result.note(
            f"{path} was cut to {len(body):,} bytes"
            + (f" of {size:,}." if declared_size is not None else "; the file is larger.")
        )

    result.bytes_read += len(body)
    result.files.append(
        ExtractedFile(
            path=path, kind=kind, size=size,
            text=decode(body), truncated=truncated, depth=depth,
        )
    )


def _walk_archive(data: bytes, path: str, result: ExtractionResult, *, depth: int, kind: str) -> None:
    """zip, tar and gzip, in process."""
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if result.entries_seen >= MAX_ENTRIES:
                        result.note(f"Stopped after {MAX_ENTRIES} archive entries.")
                        return
                    result.entries_seen += 1
                    try:
                        with archive.open(info) as handle:
                            payload = handle.read(MAX_FILE_BYTES + 1)
                    except RuntimeError as exc:
                        if "password" in str(exc).lower():
                            result.encrypted = True
                            result.note(
                                f"{path} is password-protected, so its contents could not be "
                                "read. The password is often in the message that carried it."
                            )
                            return
                        raise
                    _walk(payload, f"{path}/{info.filename}", result,
                          depth=depth + 1, declared_size=info.file_size)
        elif kind == "tar":
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    if result.entries_seen >= MAX_ENTRIES:
                        result.note(f"Stopped after {MAX_ENTRIES} archive entries.")
                        return
                    result.entries_seen += 1
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    _walk(handle.read(MAX_FILE_BYTES + 1),
                          f"{path}/{member.name}", result, depth=depth + 1,
                          declared_size=member.size)
        elif kind == "gzip":
            import gzip

            payload = gzip.decompress(data[:MAX_TOTAL_BYTES])[: MAX_FILE_BYTES + 1]
            result.entries_seen += 1
            _walk(payload, path.removesuffix(".gz"), result, depth=depth + 1)
    except Exception as exc:  # noqa: BLE001 — a hostile archive is expected input
        result.note(f"{path} could not be read as {kind}: {type(exc).__name__}.")


def _walk_external(data: bytes, path: str, result: ExtractionResult, *, depth: int, kind: str) -> None:
    """rar, 7z, cab, iso — through bsdtar, which reads them all.

    The archive is written to a temporary file first, because libarchive cannot
    read 7z or RAR from a pipe: both keep their directory at the end, so the
    reader has to seek. Over stdin the first attempt reported every one of them
    as "no extractor installed", which was true of nothing.

    Only the archive we were already given touches disk. Members are read from
    bsdtar's stdout, so nothing an archive *claims* about its own paths is ever
    acted on.
    """
    import os
    import tempfile

    handle, archive_path = tempfile.mkstemp(prefix="submitted-", suffix=f".{kind}")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)

        listing = _bsdtar(["-t"], archive_path)
        if listing is None:
            result.note(
                f"{path} is a {kind.upper()} archive that could not be read. It may be "
                "password-protected, or no extractor is installed."
            )
            return

        names = [line for line in listing.splitlines() if line and not line.endswith("/")]
        if not names:
            result.note(f"{path} is a {kind.upper()} archive that reported no files.")
            return

        for name in names[:MAX_ENTRIES]:
            if result.bytes_read >= MAX_TOTAL_BYTES:
                result.note(f"Stopped after {MAX_TOTAL_BYTES:,} bytes of extracted content.")
                return
            result.entries_seen += 1
            # -O sends the member to stdout: read, never written.
            payload = _bsdtar(["-xO"], archive_path, members=[name], binary=True)
            if payload is None:
                result.encrypted = True
                result.note(
                    f"{path}/{name} could not be extracted — the archive may be "
                    "password-protected. The password is often in the message that carried it."
                )
                continue
            _walk(payload[: MAX_FILE_BYTES + 1], f"{path}/{name}", result,
                  depth=depth + 1, declared_size=len(payload))

        if len(names) > MAX_ENTRIES:
            result.note(f"{path} holds {len(names)} entries; the first {MAX_ENTRIES} were read.")
    finally:
        try:
            os.unlink(archive_path)
        except OSError:
            pass


def _bsdtar(
    flags: list[str], archive_path: str, *, members: list[str] | None = None,
    binary: bool = False,
) -> Any:
    """Run bsdtar against an archive on disk. None means it could not read it.

    `-f <archive>` goes before the member names, not after. Appended at the
    end it was parsed as two more members to extract, and every entry came
    back "Not found in archive" — which this module then reported as the
    archive being password-protected.
    """
    try:
        completed = subprocess.run(  # noqa: S603 — fixed binary, no shell
            ["bsdtar", *flags, "-f", archive_path, *(members or [])],
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        logger.warning("bsdtar timed out reading an archive")
        return None
    if completed.returncode != 0 and not completed.stdout:
        return None
    return completed.stdout if binary else completed.stdout.decode("utf-8", "replace")


def _read_macros(data: bytes, path: str, result: ExtractionResult, *, depth: int) -> None:
    """VBA source, which is the part of an Office document that executes."""
    try:
        from oletools.olevba import VBA_Parser
    except Exception:  # noqa: BLE001
        result.note(f"{path} may contain macros, but no macro reader is installed.")
        return

    try:
        parser = VBA_Parser(path.rsplit("/", 1)[-1], data=data)
        if not parser.detect_vba_macros():
            parser.close()
            return
        for _fname, _stream, vba_name, code in parser.extract_macros():
            if not str(code or "").strip():
                continue
            _add(str(code).encode("utf-8", "replace"),
                 f"{path}!{vba_name}", result, depth=depth, kind="vba")
        parser.close()
    except Exception as exc:  # noqa: BLE001 — a malformed document is the point
        result.note(f"{path}: macros could not be read ({type(exc).__name__}).")
