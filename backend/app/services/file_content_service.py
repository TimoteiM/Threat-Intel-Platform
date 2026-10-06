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

import hashlib
import io
import logging
import os
import re
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# One entry, and everything extracted, in bytes. A phishing script is a few
# kilobytes; these are generous enough that hitting one is itself a finding.
MAX_FILE_BYTES = 1_000_000
# How much of a compiled member will be streamed through a hash function.
#
# Separate from MAX_FILE_BYTES, and far larger, because the two limits exist
# for different reasons. MAX_FILE_BYTES bounds what is *kept* — text that goes
# into evidence, into the prompt and onto the screen, where a megabyte is
# already more than anyone reads. A hash keeps nothing: the bytes stream
# through a digest and are dropped, so the only cost is the time to decompress
# them, and the only thing worth bounding is a decompression bomb.
#
# 5.6 MB installers are ordinary. Capping the hash at a megabyte meant the one
# member of a dropper archive that actually runs could not be identified.
MAX_HASH_BYTES = 256_000_000
# Enough to recognise a format from its magic bytes before deciding whether to
# read the rest of the member.
SNIFF_BYTES = 65_536
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
class EmbeddedBinary:
    """A compiled file found inside a submission.

    The content reader has nothing to say about a PE beyond "this is not text",
    which is true and useless: the executable packed next to a one-line
    manifest is usually the whole point of the archive. Its hash is what every
    reputation source takes, so the hash is what gets recorded — and the bytes
    are kept on the object, out of `as_dict`, for a caller that wants to store
    or detonate it.
    """

    path: str
    kind: str
    size: int
    sha256: str
    sha1: str
    md5: str
    data: bytes | None = field(default=None, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
        }


@dataclass
class ExtractionResult:
    files: list[ExtractedFile] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    entries_seen: int = 0
    bytes_read: int = 0
    encrypted: bool = False
    # Three different answers that all used to read as "encrypted, sorry":
    #   password_required     — it is locked and nobody gave us a key
    #   password_incorrect    — a key was given and the archive rejected it
    #   encryption_unsupported— the key may well be right, the extractor
    #                           cannot decrypt this format at all (7z)
    # An analyst retypes a password for the second and never for the third.
    password_required: bool = False
    password_incorrect: bool = False
    encryption_unsupported: bool = False
    # Compiled files found inside, each worth a reputation lookup of its own.
    binaries: list[EmbeddedBinary] = field(default_factory=list)
    # The caller's password, riding along with the accumulator rather than as
    # a second parameter through six recursive calls. Never serialised: it
    # leaves this object only as an argument to an extractor.
    password: str | None = field(default=None, repr=False)

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
            "password_required": self.password_required,
            "password_incorrect": self.password_incorrect,
            "encryption_unsupported": self.encryption_unsupported,
            "readable_files": len(self.files),
            "binaries": [b.as_dict() for b in self.binaries],
        }


@dataclass
class EncryptionProbe:
    """Whether this submission is locked, and whether a password would help.

    Answered before anything is extracted, so the app can ask for a password
    instead of accepting a file it cannot read and reporting "nothing found"
    — and so it never shells out to an extractor that would sit at an
    interactive prompt (see `_bsdtar`).
    """

    encrypted: bool = False
    kind: str = ""
    supported: bool = True
    entries: list[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "encrypted": self.encrypted,
            "kind": self.kind,
            "supported": self.supported,
            "entries": list(self.entries[:20]),
            "reason": self.reason,
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


def extract(
    data: bytes, filename: str = "submitted", *, password: str | None = None
) -> ExtractionResult:
    """Everything readable in this file, following archives to MAX_DEPTH.

    `password` opens an encrypted archive. It is used and discarded: it is not
    logged, not returned in `as_dict`, and not written anywhere.
    """
    result = ExtractionResult(password=password or None)
    _walk(data, filename, result, depth=0)
    return result


def probe(data: bytes, filename: str = "submitted") -> EncryptionProbe:
    """Is this a locked archive, and could a password open it?

    Reads headers only. For a zip that is the general-purpose bit flag, which
    is in the local header of every member and needs no password to read, so
    the answer costs nothing and involves no subprocess. For the formats
    libarchive handles it is a listing, which succeeds for an encrypted 7z or
    RAR whose *names* are readable even when the contents are not.
    """
    kind = sniff(data)
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = [i for i in archive.infolist() if not i.is_dir()]
                locked = [i for i in members if i.flag_bits & 0x1]
                if not locked:
                    return EncryptionProbe(kind="zip", entries=[i.filename for i in members])
                # Compression method 99 is WinZip AES. Python's zipfile reads
                # the flag but cannot decrypt it; libarchive can, so this is
                # supported — just not in process.
                return EncryptionProbe(
                    encrypted=True,
                    kind="zip",
                    supported=True,
                    entries=[i.filename for i in locked],
                    reason="AES" if any(i.compress_type == 99 for i in locked) else "ZipCrypto",
                )
        except Exception:  # noqa: BLE001 — a corrupt zip is not an encrypted one
            return EncryptionProbe(kind="zip")

    if kind in _EXTERNAL_ARCHIVES:
        handle, archive_path = tempfile.mkstemp(prefix="probe-", suffix=f".{kind}")
        try:
            with os.fdopen(handle, "wb") as fh:
                fh.write(data)
            listing, stderr = _bsdtar_raw(["-t"], archive_path)
            names = [l for l in (listing or "").splitlines() if l and not l.endswith("/")]
            lowered = (stderr or "").lower()
            if "passphrase" in lowered or "encrypted" in lowered:
                # 7z content encryption is the one libarchive declines
                # outright, whatever password it is handed.
                unsupported = "not supported" in lowered or kind == "7z"
                return EncryptionProbe(
                    encrypted=True, kind=kind, supported=not unsupported,
                    entries=names,
                    reason="encrypted header" if not names else "encrypted contents",
                )
            return EncryptionProbe(kind=kind, entries=names)
        finally:
            try:
                os.unlink(archive_path)
            except OSError:
                pass

    return EncryptionProbe(kind=kind or "")


def extract_attachments(attachments: Any, *, password: str | None = None) -> ExtractionResult:
    """Read every attachment on an email, archives included.

    Attachments arrive with their bytes already decoded once into base64 by the
    parser, and the inspection pass alongside this one reads structure — is it
    really a PDF, does the OOXML hold a macro. This reads the source.

    One result covers all of them, so the bounds apply to the message rather
    than to each attachment: ten archives of a megabyte each is the same
    problem as one archive of ten.
    """
    import base64

    result = ExtractionResult(password=password or None)
    for item in attachments or []:
        if not isinstance(item, dict):
            continue
        encoded = item.get("content_b64")
        if not encoded:
            name = str(item.get("filename") or "attachment")
            result.note(f"{name}: content was not retained, so it could not be read.")
            continue
        try:
            data = base64.b64decode(encoded)
        except Exception:  # noqa: BLE001 — a malformed attachment is the point
            result.note(f"{item.get('filename') or 'attachment'}: content could not be decoded.")
            continue
        _walk(data, str(item.get("filename") or "attachment"), result, depth=0)
    return result


def _walk(
    data: bytes, path: str, result: ExtractionResult, *, depth: int,
    declared_size: int | None = None, digests: dict[str, Any] | None = None,
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
        _add_binary(data, path, result, kind=kind, declared_size=declared_size,
                    digests=digests)
        return

    if kind == "pdf":
        # A PDF is not text, so the textual branch below would discard it. Its
        # JavaScript is the executable part and the only part worth reading.
        _read_pdf_scripts(data, path, result, depth=depth)
        return

    # Anything left: read it if it is text, or if its name says it is source.
    if looks_textual(data) or extension in SOURCE_EXTENSIONS:
        _add(data, path, result, depth=depth, declared_size=declared_size,
             kind="source" if extension in SOURCE_EXTENSIONS else "text")
    elif kind == "pdf":
        _read_pdf_scripts(data, path, result, depth=depth)
    else:
        result.note(f"{path} is not text and no reader recognised it.")


def _digests(data: bytes) -> dict[str, Any]:
    """The three hashes every reputation source takes, plus the length."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),   # noqa: S324 — an identifier, not a signature
        "md5": hashlib.md5(data).hexdigest(),     # noqa: S324 — same
        "size": len(data),
        "complete": True,
    }


def _stream_digests(head: bytes, handle: Any) -> dict[str, Any]:
    """Hash a member that is too large to keep, without keeping it.

    The bytes are decompressed in chunks, fed to the digests and dropped, so
    peak memory is one chunk regardless of how big the executable is. Returns
    `complete: False` if the member runs past MAX_HASH_BYTES — a partial hash
    is never recorded, because an identifier that matches nothing is worse
    than no identifier at all.
    """
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324
    total = 0
    chunk = head
    while chunk:
        total += len(chunk)
        if total > MAX_HASH_BYTES:
            return {"complete": False, "size": total}
        sha256.update(chunk)
        sha1.update(chunk)
        md5.update(chunk)
        chunk = handle.read(1_048_576)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "size": total,
        "complete": True,
    }


def _add_binary(
    data: bytes, path: str, result: ExtractionResult, *, kind: str,
    declared_size: int | None = None, digests: dict[str, Any] | None = None,
) -> None:
    """Record a compiled member so something else can look it up.

    `digests` are hashes of the *whole* member, computed by streaming it past
    the read limit — a 5.6 MB installer is ordinary and must still be
    identifiable. Without them the member is hashed from `data`, which is only
    valid when `data` is the whole thing: a hash of the first megabyte looks
    real, matches nothing, and makes every reputation source answer
    confidently about a file that does not exist.
    """
    if len(result.binaries) >= MAX_ENTRIES:
        return
    if any(b.path == path for b in result.binaries):
        return

    if digests is None and declared_size is not None and len(data) < declared_size:
        # Nothing streamed it and what is in hand is a prefix.
        result.note(
            f"{path} is a compiled executable that could not be read in full, so it could "
            "not be hashed or looked up."
        )
        return
    if digests is not None and not digests.get("complete"):
        result.note(
            f"{path} is a compiled executable larger than the {MAX_HASH_BYTES:,}-byte hash "
            "limit, so it could not be identified. That size is itself unusual."
        )
        return

    computed = digests or _digests(data)
    result.binaries.append(
        EmbeddedBinary(
            path=path,
            kind=kind,
            size=computed.get("size") or declared_size or len(data),
            sha256=computed["sha256"],
            sha1=computed["sha1"],
            md5=computed["md5"],
            # Only when the whole member is in hand. A prefix is useless to a
            # sandbox and dangerous to store as if it were the sample.
            data=data if len(data) >= (computed.get("size") or 0) else None,
        )
    )
    result.note(
        f"{path} is a compiled executable; its code is not readable as text, so it is "
        "identified by hash and looked up separately."
    )


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


# PDF JavaScript lives either as a literal string after /JS, or inside a
# compressed stream the action points at. Both are matched here rather than by
# parsing the object graph, because that needs a PDF library and the cost of
# adding one is not obviously smaller than the cost of this.
#
# This is explicitly a heuristic, and says so when it finds nothing while the
# document clearly declares JavaScript — "we could not read it" and "there was
# none" must not look the same.
_PDF_JS_MARKER = re.compile(rb"/(?:JS|JavaScript)\b")
_PDF_JS_LITERAL = re.compile(rb"/JS\s*\((.{4,20000}?)\)\s*(?:/|>>|\n|\r)", re.DOTALL)
_PDF_JS_HEX = re.compile(rb"/JS\s*<([0-9A-Fa-f\s]{8,40000})>")
_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)

# What JavaScript in a PDF actually uses. A decompressed stream matching none
# of these is font data or an image, not a script.
_PDF_JS_HINTS = (
    b"app.", b"this.", b"eval(", b"unescape(", b"util.", b"getAnnots",
    b"exportDataObject", b"launchURL", b"submitForm", b"String.fromCharCode",
    b"function ", b"var ",
)

# How many streams to decompress. A document with thousands is a document, and
# the script is not in the thousandth.
_PDF_MAX_STREAMS = 400


def _pdf_unescape(raw: bytes) -> bytes:
    """Undo the PDF string escapes that matter for reading code."""
    return (
        raw.replace(b"\\n", b"\n").replace(b"\\r", b"\r").replace(b"\\t", b"\t")
        .replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
    )


def _read_pdf_scripts(data: bytes, path: str, result: ExtractionResult, *, depth: int) -> None:
    """The JavaScript a PDF carries, which is the part of it that runs."""
    import binascii
    import zlib

    declares_js = bool(_PDF_JS_MARKER.search(data))
    found = 0

    for match in _PDF_JS_LITERAL.finditer(data):
        body = _pdf_unescape(match.group(1))
        if looks_textual(body):
            found += 1
            _add(body, f"{path}!javascript-{found}", result, depth=depth, kind="pdf-js")

    for match in _PDF_JS_HEX.finditer(data):
        try:
            body = binascii.unhexlify(re.sub(rb"\s", b"", match.group(1)))
        except binascii.Error:
            continue
        if looks_textual(body):
            found += 1
            _add(body, f"{path}!javascript-{found}", result, depth=depth, kind="pdf-js")

    for index, match in enumerate(_PDF_STREAM.finditer(data)):
        if index >= _PDF_MAX_STREAMS or result.bytes_read >= MAX_TOTAL_BYTES:
            break
        raw = match.group(1)
        try:
            body = zlib.decompress(raw)
        except zlib.error:
            body = raw if looks_textual(raw) else b""
        if not body or not looks_textual(body):
            continue
        if not any(hint in body for hint in _PDF_JS_HINTS):
            continue
        found += 1
        _add(body[: MAX_FILE_BYTES + 1], f"{path}!stream-{index}", result,
             depth=depth, kind="pdf-js", declared_size=len(body))

    if declares_js and not found:
        result.note(
            f"{path} declares JavaScript that could not be extracted. Its absence here "
            "is a limit of this reader, not evidence that the document is inert."
        )
    elif not declares_js:
        result.note(f"{path} is a PDF and declares no JavaScript.")


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
                    locked = bool(info.flag_bits & 0x1)
                    if locked:
                        result.encrypted = True
                    digests: dict[str, Any] | None = None
                    try:
                        with archive.open(
                            info,
                            pwd=(result.password.encode("utf-8") if locked and result.password else None),
                        ) as handle:
                            # The format is decided from the magic bytes before
                            # anything else is read, because what to do next
                            # depends on it: a compiled member is streamed to
                            # the end to be hashed, everything else stops at
                            # the read limit. Reading every member to the end
                            # just in case would decompress an archive of
                            # videos in full to learn nothing.
                            head = handle.read(SNIFF_BYTES)
                            if sniff(head) in {"pe", "elf"}:
                                keep = head[: MAX_FILE_BYTES + 1]
                                digests = _stream_digests(head, handle)
                                payload = keep
                            else:
                                payload = head + handle.read(
                                    max(0, MAX_FILE_BYTES + 1 - len(head))
                                )
                    except NotImplementedError:
                        # WinZip AES (compression method 99). The stdlib reads
                        # the flag but will not decrypt it; libarchive will, so
                        # the archive goes out to bsdtar rather than being
                        # written off as unreadable.
                        if result.password:
                            _walk_external(data, path, result, depth=depth, kind="zip")
                        else:
                            result.password_required = True
                            result.note(
                                f"{path} is an AES-encrypted zip. Supply the password to read "
                                "what is inside."
                            )
                        return
                    except RuntimeError as exc:
                        message = str(exc).lower()
                        if "password" in message:
                            # "Bad password" and "password required" are both
                            # RuntimeError from zipfile; only the wording says
                            # which, and the analyst's next action differs.
                            if result.password and "bad password" in message:
                                result.password_incorrect = True
                                result.note(
                                    f"{path} did not open with the password supplied. "
                                    "Archive passwords are case-sensitive."
                                )
                            else:
                                result.password_required = True
                                result.note(
                                    f"{path} is password-protected. Supply the password to read "
                                    "what is inside; it is often in the message that carried it."
                                )
                            return
                        raise
                    _walk(payload, f"{path}/{info.filename}", result,
                          depth=depth + 1, declared_size=info.file_size,
                          digests=digests)
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
                    head = handle.read(SNIFF_BYTES)
                    if sniff(head) in {"pe", "elf"}:
                        member_digests = _stream_digests(head, handle)
                        member_payload = head[: MAX_FILE_BYTES + 1]
                    else:
                        member_digests = None
                        member_payload = head + handle.read(
                            max(0, MAX_FILE_BYTES + 1 - len(head))
                        )
                    _walk(member_payload, f"{path}/{member.name}", result,
                          depth=depth + 1, declared_size=member.size,
                          digests=member_digests)
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
    handle, archive_path = tempfile.mkstemp(prefix="submitted-", suffix=f".{kind}")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)

        # Decided before anything is extracted: an encrypted archive with no
        # password must not reach the extractor at all, because bsdtar sits at
        # an interactive prompt rather than failing.
        lock = probe(data, path)
        if lock.encrypted and not lock.supported:
            result.encrypted = True
            result.encryption_unsupported = True
            result.note(
                f"{path} is an encrypted {kind.upper()} archive. The extractor can list its "
                "contents but cannot decrypt them, so a password does not help here — send "
                "the file to the sandbox, or repack it as a zip."
            )
            return
        if lock.encrypted and not result.password:
            result.encrypted = True
            result.password_required = True
            result.note(
                f"{path} is a password-protected {kind.upper()} archive. Supply the password "
                "to read what is inside; it is often in the message that carried it."
            )
            return
        if lock.encrypted:
            result.encrypted = True

        listing = _bsdtar(["-t"], archive_path, passphrase=result.password)
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
            payload, stderr = _bsdtar_raw(
                ["-xO"], archive_path, members=[name], binary=True,
                passphrase=result.password,
            )
            if payload is None:
                lowered = stderr.lower()
                if "incorrect passphrase" in lowered:
                    result.encrypted = True
                    result.password_incorrect = True
                    result.note(
                        f"{path} did not open with the password supplied. Archive passwords "
                        "are case-sensitive."
                    )
                    return
                if "not supported" in lowered and "encrypt" in lowered:
                    result.encrypted = True
                    result.encryption_unsupported = True
                    result.note(
                        f"{path} is encrypted in a form the extractor cannot decrypt, whatever "
                        "password is given."
                    )
                    return
                if "passphrase" in lowered:
                    result.encrypted = True
                    result.password_required = True
                    result.note(f"{path} is password-protected. Supply the password to read it.")
                    return
                result.note(f"{path}/{name} could not be extracted from the archive.")
                continue
            # `payload` is the whole member: bsdtar writes it to stdout and
            # subprocess buffers all of it. Truncating before hashing threw
            # away an identifier that was already in hand.
            member_digests = (
                _digests(payload) if sniff(payload[:SNIFF_BYTES]) in {"pe", "elf"} else None
            )
            _walk(payload[: MAX_FILE_BYTES + 1], f"{path}/{name}", result,
                  depth=depth + 1, declared_size=len(payload),
                  digests=member_digests)

        if len(names) > MAX_ENTRIES:
            result.note(f"{path} holds {len(names)} entries; the first {MAX_ENTRIES} were read.")
    finally:
        try:
            os.unlink(archive_path)
        except OSError:
            pass


def _bsdtar(
    flags: list[str], archive_path: str, *, members: list[str] | None = None,
    binary: bool = False, passphrase: str | None = None,
) -> Any:
    """Run bsdtar against an archive on disk. None means it could not read it.

    `-f <archive>` goes before the member names, not after. Appended at the
    end it was parsed as two more members to extract, and every entry came
    back "Not found in archive" — which this module then reported as the
    archive being password-protected.
    """
    stdout, _ = _bsdtar_raw(flags, archive_path, members=members, binary=binary,
                            passphrase=passphrase)
    return stdout


def _bsdtar_raw(
    flags: list[str], archive_path: str, *, members: list[str] | None = None,
    binary: bool = False, passphrase: str | None = None,
) -> tuple[Any, str]:
    """`(stdout, stderr)`. stdout is None when the archive could not be read.

    stderr is returned because it is the only thing that distinguishes "wrong
    passphrase" from "this encryption is not supported" from "no passphrase
    given", and those need three different answers.

    Two things that are not optional:

    `stdin` is closed. Handed an encrypted archive and no `--passphrase`,
    bsdtar prompts — and with no terminal it re-prompts in a tight loop. It
    produced 332 KB of "Enter passphrase:" and then died on the timeout, so
    every locked archive cost a full timeout and a flooded pipe. Closing stdin
    is not enough on its own, which is why `probe` decides whether a password
    is needed before anything calls this.

    `--passphrase` is only passed when there is one. An empty value is still a
    value, and bsdtar treats it as a wrong password rather than as absent —
    which would report "incorrect password" to an analyst who never gave one.
    """
    argv = ["bsdtar"]
    if passphrase:
        # The passphrase is in argv, so it is visible in /proc to anything
        # running in this container for the life of the call. Unavoidable with
        # bsdtar, which has no stdin or environment form — and the reason the
        # in-process zipfile path is tried first for ZipCrypto.
        argv += ["--passphrase", passphrase]
    argv += [*flags, "-f", archive_path, *(members or [])]
    try:
        completed = subprocess.run(  # noqa: S603 — fixed binary, no shell
            argv,
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None, ""
    except subprocess.TimeoutExpired:
        logger.warning("bsdtar timed out reading an archive")
        return None, "timed out"
    stderr = completed.stderr.decode("utf-8", "replace") if completed.stderr else ""
    if completed.returncode != 0 and not completed.stdout:
        return None, stderr
    return (completed.stdout if binary else completed.stdout.decode("utf-8", "replace")), stderr


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


# ── choosing what to detonate ────────────────────────────────────────────────

# The largest member that will be handed to a sandbox. ANY.RUN's upload limit
# is the real bound; this keeps a decompression bomb from being read into
# memory on the way there.
MAX_DETONATION_BYTES = 100_000_000


@dataclass
class DetonationTarget:
    """The file inside a submission that is worth running, and why."""

    name: str
    data: bytes
    sha256: str
    source_path: str
    reason: str


def read_member(
    data: bytes, member_path: str, *, password: str | None = None
) -> bytes | None:
    """The full bytes of one member, re-read from the archive.

    Extraction keeps a member's bytes only when the whole thing fitted inside
    the read limit — a 5.6 MB installer is streamed through a digest and
    dropped, because the limit bounds what is *kept* for reading as text. A
    sandbox needs the file itself, so it is read again here, once, for the one
    member that is going to be run.

    `member_path` is as `EmbeddedBinary.path` records it: the archive's own
    name, a slash, then the member. Only members directly inside the submitted
    archive are returned — a file nested two archives deep is not something to
    hand a sandbox without being asked.
    """
    if "/" not in str(member_path or ""):
        return None
    name = str(member_path).split("/", 1)[1]
    if "/" in name.rstrip("/") and name.count("/") > 3:
        return None

    kind = sniff(data)
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                info = next((i for i in archive.infolist() if i.filename == name), None)
                if info is None or info.file_size > MAX_DETONATION_BYTES:
                    return None
                pwd = password.encode("utf-8") if (info.flag_bits & 0x1 and password) else None
                with archive.open(info, pwd=pwd) as handle:
                    return handle.read(MAX_DETONATION_BYTES + 1)[:MAX_DETONATION_BYTES]
        except NotImplementedError:
            # WinZip AES. libarchive can, the stdlib cannot.
            pass
        except Exception:  # noqa: BLE001 — a member we cannot read is not a target
            return None

    if kind == "zip" or kind in _EXTERNAL_ARCHIVES:
        handle, archive_path = tempfile.mkstemp(prefix="detonate-", suffix=f".{kind}")
        try:
            with os.fdopen(handle, "wb") as fh:
                fh.write(data)
            payload = _bsdtar(
                ["-xO"], archive_path, members=[name], binary=True, passphrase=password,
            )
            if not payload or len(payload) > MAX_DETONATION_BYTES:
                return None
            return payload
        finally:
            try:
                os.unlink(archive_path)
            except OSError:
                pass
    return None


def detonation_target(
    data: bytes, filename: str = "submitted", *, password: str | None = None
) -> DetonationTarget | None:
    """The executable to send to a sandbox instead of the archive carrying it.

    A sandbox handed a zip has to open it and find the payload itself, with
    whatever time its automated interactivity has. Handed the executable, it
    runs it. The platform has already opened the archive — so the thing worth
    running is known before anything is submitted.

    Returns None, meaning "submit what was submitted", whenever the answer is
    not obvious:

      * the submission is not an archive;
      * it holds no compiled file;
      * it holds *several*, because choosing between them is a guess, and a
        guess that runs the decoy instead of the payload is worse than letting
        the sandbox decide.
    """
    if sniff(data) not in _EXTERNAL_ARCHIVES and sniff(data) not in _STDLIB_ARCHIVES:
        return None

    result = extract(data, filename, password=password)
    if len(result.binaries) != 1:
        return None

    binary = result.binaries[0]
    payload = binary.data or read_member(data, binary.path, password=password)
    if not payload:
        return None
    # The hash is what the extraction recorded over the whole member. If the
    # re-read disagrees, the two are not the same bytes and nothing is run.
    if hashlib.sha256(payload).hexdigest() != binary.sha256:
        return None

    return DetonationTarget(
        name=binary.path.split("/")[-1],
        data=payload,
        sha256=binary.sha256,
        source_path=binary.path,
        reason=(
            f"{filename} is an archive holding one executable; it was submitted to the "
            "sandbox in place of the archive so the payload runs directly."
        ),
    )
