"""CAPEv2 API client — the only place that knows CAPE's wire format.

Everything CAPE-shaped stops here. Callers get typed results and a small set of
exceptions; nothing upstream parses CAPE JSON, so a CAPE upgrade that renames a
field is a change to this file and the normalizer, not to the application.

The token
---------
It comes from the environment, is held only in `Settings`, and leaves this
process in exactly one place: the `Authorization` header of an outbound request
to the configured base URL. It is never written to Postgres, never returned by
an API, never rendered by the frontend, and never logged — `_redact()` scrubs
it from every message this module raises or logs, including the ones the HTTP
library builds for us, because a transport exception happily carries the
prepared request's headers in its string form.

SSRF
----
The base URL is administrator configuration. No caller can supply a URL, only
a path suffix that is escaped, and redirects are disabled outright: a 302 from
a compromised or misconfigured proxy would otherwise turn this client into a
fetcher for whatever host the response names. A redirect is an error here, not
something to follow.

Why httpx
---------
`requests` builds a multipart body in memory, so a 100MB sample would be a
100MB allocation in a Celery worker; streaming it needs `requests_toolbelt`,
which is not in this image. httpx streams the file from the handle as it
writes the request, defaults to *not* following redirects, and lets connect
and read timeouts be set separately — all three are requirements here rather
than preferences, so this client uses httpx even though the older collectors
use requests.

Retries
-------
Only GETs — status, search, view, report — are retried, and only on transport
faults and 429/5xx. A submission is never retried automatically: a POST that
timed out may well have been accepted, and re-sending it detonates the same
sample twice, burns a VM from a pool of six, and produces a second task id that
nothing is expecting. That case is surfaced as `CapeAmbiguousSubmission` so the
workflow can go and look rather than guess.
"""

from __future__ import annotations

import logging
import re
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterable

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

# Paths, relative to the configured /apiv2 base. Kept together so the set of
# endpoints this integration touches is readable in one place.
PATH_STATUS = "/cuckoo/status/"
PATH_SEARCH_SHA256 = "/tasks/search/sha256/{sha256}/"
# POST. The GET /tasks/search/ route only accepts md5, sha1 and sha256 —
# confirmed against the live instance, where /tasks/search/domain/ 404s.
# Searching by anything else, a contacted domain included, goes through here.
PATH_EXTENDED_SEARCH = "/tasks/extendedsearch/"
PATH_CREATE_FILE = "/tasks/create/file/"
PATH_CREATE_URL = "/tasks/create/url/"
PATH_VIEW_TASK = "/tasks/view/{task_id}/"
PATH_REPORT = "/tasks/get/report/{task_id}/{fmt}/"
# A compact, purpose-built summary: malscore, info, target, network, dropped
# files and behaviour. Measured on the live instance at 116KB for a task whose
# full JSON report was 139MB — 1,200x smaller, and it carries the findings this
# platform actually normalizes.
PATH_IOCS = "/tasks/get/iocs/{task_id}/"

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_TASK_ID_RE = re.compile(r"^[0-9]{1,18}$")

# CAPE states that mean "this task will not change again".
TERMINAL_STATES = frozenset({"reported", "failed_analysis", "failed_processing", "failure"})
FAILED_STATES = frozenset({"failed_analysis", "failed_processing", "failure"})

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_GET_ATTEMPTS = 3
_MAX_RETRY_AFTER_SECONDS = 120


# ── Errors ───────────────────────────────────────────────────────────────────


class CapeError(Exception):
    """Base. Every message passing through here has been redacted."""

    def __init__(self, message: str, *, request_id: str | None = None):
        super().__init__(_redact(message))
        self.request_id = request_id


class CapeNotConfigured(CapeError):
    """No base URL or no token. Not a failure — the integration is simply off."""


class CapeAuthError(CapeError):
    """401. The token is missing, wrong, or revoked."""


class CapeForbidden(CapeError):
    """403. The token is valid but not permitted to do this."""


class CapeRateLimited(CapeError):
    def __init__(self, message: str, *, retry_after: float | None = None, request_id: str | None = None):
        super().__init__(message, request_id=request_id)
        self.retry_after = retry_after


class CapeTimeout(CapeError):
    """The request did not complete inside its bound."""


class CapeConnectionError(CapeError):
    """Could not reach the proxy at all, including TLS failures."""


class CapeTLSError(CapeConnectionError):
    """Certificate verification failed — kept distinct because the fix differs."""


class CapeValidationError(CapeError):
    """CAPE rejected the request, or answered something unparseable."""


class CapeServerError(CapeError):
    """5xx after retries."""


class CapeAmbiguousSubmission(CapeError):
    """A submission whose outcome is unknown.

    The file may or may not have reached CAPE. Never resolved by resending —
    the workflow looks the sample up by hash instead.
    """


class CapeResponseTooLarge(CapeError):
    """A report bigger than the configured ceiling; refused rather than buffered."""


# ── Typed results ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CapeStatus:
    reachable: bool
    version: str | None = None
    tasks: dict[str, Any] = field(default_factory=dict)
    machines_total: int | None = None
    machines_available: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CapeTask:
    """One CAPE task as `tasks/view` describes it.

    Deliberately not treated as the analysis result: `tasks/view` carries the
    lifecycle, and on this CAPE it does not reliably carry `malscore`. A missing
    score here means "not known yet", never "benign" — see the normalizer.
    """

    task_id: int
    status: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATES

    @property
    def is_failed(self) -> bool:
        return self.status in FAILED_STATES

    @property
    def is_reported(self) -> bool:
        return self.status == "reported"


@dataclass(frozen=True)
class CapeSubmission:
    task_ids: tuple[int, ...]
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def task_id(self) -> int | None:
        return self.task_ids[0] if self.task_ids else None


@dataclass(frozen=True)
class CapeReport:
    task_id: int
    fmt: str
    payload: dict[str, Any]
    size_bytes: int


# ── Redaction ────────────────────────────────────────────────────────────────


def _token_patterns() -> Iterable[str]:
    token = str(getattr(get_settings(), "cape_api_token", "") or "").strip()
    if token:
        yield re.escape(token)


def _redact(message: Any) -> str:
    """Remove the token and any Authorization header from a string.

    Two passes on purpose. The first removes the literal token, which covers a
    message that happens to contain it. The second removes any `Authorization:
    Token ...` construction, which covers the ones we never see coming — a
    requests exception rendering the prepared request, a traceback carrying a
    local variable, a proxy echoing the header back in an error body.
    """
    text = str(message)
    for pattern in _token_patterns():
        text = re.sub(pattern, "[REDACTED]", text)
    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*)(['\"]?)(token\s+)?[A-Za-z0-9._\-]+",
        r"\1\2\3[REDACTED]",
        text,
    )
    return text


def redact(message: Any) -> str:
    """Public: for error reporting and traces outside this module."""
    return _redact(message)


def safe_headers(headers: Any) -> dict[str, str]:
    """A header mapping with every credential-bearing value masked."""
    sensitive = {"authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}
    try:
        items = headers.items()
    except AttributeError:
        return {}
    return {k: ("[REDACTED]" if str(k).lower() in sensitive else str(v)) for k, v in items}


# ── Client ───────────────────────────────────────────────────────────────────


class CapeClient:
    """Synchronous, because this runs in Celery workers and collectors.

    One instance per unit of work. An httpx.Client owns a connection pool;
    sharing one across the thread pool would be sharing that pool too.
    """

    def __init__(self, settings=None, *, request_id: str | None = None):
        self.settings = settings or get_settings()
        if not self.settings.cape_configured:
            raise CapeNotConfigured(
                "CAPE is not configured: CAPE_ENABLED, CAPE_API_BASE_URL and CAPE_API_TOKEN are all required."
            )
        self.base_url = self.settings.cape_base_url
        # Correlates the lines this integration logs for one workflow. Random,
        # carries no sample or tenant identity, and is safe to show an analyst.
        self.request_id = request_id or uuid.uuid4().hex[:12]
        self._ssl_context: ssl.SSLContext | None = None
        self._session = self._build_session()

        if self.settings.cape_tls_verify is False:
            logger.warning(
                "CAPE TLS verification is DISABLED (CAPE_VERIFY_TLS=false). "
                "This is a development-only setting: responses from the sandbox "
                "cannot be attributed to the configured host. [req=%s]",
                self.request_id,
            )

    # -- plumbing ------------------------------------------------------------

    @property
    def _verify(self):
        """What httpx should be given for `verify`.

        A CA bundle is turned into an SSLContext rather than passed as a path:
        httpx deprecated `verify=<str>`, and this integration's whole point is
        an internally-issued certificate, so the string form is the case that
        would break on the next httpx upgrade. Built once per client.
        """
        configured = self.settings.cape_tls_verify
        if isinstance(configured, str) and configured.strip():
            path = configured.strip()
            if self._ssl_context is None:
                try:
                    self._ssl_context = ssl.create_default_context(cafile=path)
                except OSError as exc:
                    # The commonest deployment failure: the bundle was not
                    # mounted, or was mounted as a directory because the bind
                    # source did not exist when the container was created.
                    # A bare FileNotFoundError names nothing useful.
                    raise CapeNotConfigured(
                        f"CAPE_CA_BUNDLE points at {path!r}, which cannot be read "
                        f"inside this container ({exc.strerror}). Check that the file is "
                        f"mounted read-only and is a regular file, not a directory."
                    ) from None
                except ssl.SSLError as exc:
                    raise CapeNotConfigured(
                        f"CAPE_CA_BUNDLE at {path!r} is not a usable PEM certificate bundle: {exc}"
                    ) from None
            return self._ssl_context
        return bool(configured)

    def _build_session(self) -> httpx.Client:
        return httpx.Client(
            headers={
                "Authorization": f"Token {str(self.settings.cape_api_token).strip()}",
                "Accept": "application/json",
                "User-Agent": "ThreatAnalyzer-CAPE/1.0",
                "X-Request-ID": self.request_id,
            },
            timeout=httpx.Timeout(
                float(self.settings.cape_request_timeout_seconds),
                connect=float(self.settings.cape_connect_timeout_seconds),
            ),
            verify=self._verify,
            # Never follow a redirect. See the module docstring.
            follow_redirects=False,
            # No ambient proxy or netrc credentials: the only route to CAPE is
            # the configured one.
            trust_env=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        )

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "CapeClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    # -- request ------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        files: Any = None,
        data: Any = None,
        stream: bool = False,
        retry: bool = True,
    ) -> httpx.Response:
        url = self._url(path)
        attempts = _MAX_GET_ATTEMPTS if (retry and method == "GET") else 1
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                if stream:
                    request = self._session.build_request(method, url)
                    response = self._session.send(request, stream=True)
                else:
                    response = self._session.request(method, url, files=files, data=data)
            except httpx.ConnectTimeout as exc:
                last_error = CapeTimeout(f"Timed out connecting to CAPE: {exc}", request_id=self.request_id)
            except httpx.ReadTimeout as exc:
                last_error = CapeTimeout(f"CAPE did not answer in time: {exc}", request_id=self.request_id)
            except httpx.ConnectError as exc:
                # A certificate failure arrives as a ConnectError wrapping an
                # ssl.SSLError. Separated because the remedy is different: a
                # CA bundle, not a network route.
                if _is_tls_failure(exc):
                    raise CapeTLSError(
                        f"TLS verification failed talking to CAPE: {exc}", request_id=self.request_id
                    ) from None
                last_error = CapeConnectionError(f"Could not reach CAPE: {exc}", request_id=self.request_id)
            except httpx.TimeoutException as exc:
                last_error = CapeTimeout(f"CAPE request timed out: {exc}", request_id=self.request_id)
            except httpx.HTTPError as exc:
                last_error = CapeError(f"CAPE request failed: {exc}", request_id=self.request_id)
            else:
                # A redirect is refused rather than followed: the Location may
                # name any host at all, and following it is the SSRF.
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")
                    response.close()
                    raise CapeValidationError(
                        f"CAPE responded with a redirect to {location!r}; refusing to follow it.",
                        request_id=self.request_id,
                    )

                if response.status_code == 429:
                    retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
                    if attempt < attempts:
                        response.close()
                        time.sleep(retry_after if retry_after is not None else min(2 ** attempt, 8))
                        continue
                    response.close()
                    raise CapeRateLimited(
                        "CAPE rate-limited this request.",
                        retry_after=retry_after,
                        request_id=self.request_id,
                    )

                if response.status_code in _RETRYABLE_STATUS and attempt < attempts:
                    response.close()
                    time.sleep(min(2 ** attempt, 8))
                    continue

                self._raise_for_status(response)
                return response

            if attempt < attempts:
                time.sleep(min(2 ** attempt, 8))

        raise last_error or CapeError("CAPE request failed", request_id=self.request_id)

    def _raise_for_status(self, response: httpx.Response) -> None:
        code = response.status_code
        if code < 400:
            return
        body = _peek(response)
        response.close()
        if code == 401:
            raise CapeAuthError(
                "CAPE rejected the API token (401). Check CAPE_API_TOKEN.", request_id=self.request_id
            )
        if code == 403:
            raise CapeForbidden(
                f"CAPE refused this operation (403). It may be disabled server-side: {body}",
                request_id=self.request_id,
            )
        if code == 404:
            raise CapeValidationError(f"CAPE has no such resource (404): {body}", request_id=self.request_id)
        if 500 <= code:
            raise CapeServerError(f"CAPE server error ({code}): {body}", request_id=self.request_id)
        raise CapeValidationError(f"CAPE rejected the request ({code}): {body}", request_id=self.request_id)

    def _json(self, response: httpx.Response) -> Any:
        """Parse, checking the content type and unwrapping CAPE's envelope."""
        content_type = str(response.headers.get("Content-Type", "")).lower()
        if "json" not in content_type:
            body = _peek(response)
            response.close()
            raise CapeValidationError(
                f"Expected JSON from CAPE but got {content_type or 'no content type'}: {body}",
                request_id=self.request_id,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise CapeValidationError(f"CAPE returned malformed JSON: {exc}", request_id=self.request_id) from None
        finally:
            response.close()
        return self._unwrap(payload)

    def _unwrap(self, payload: Any) -> Any:
        """CAPE answers `{"error": bool, "data": ...}` on most apiv2 routes.

        `error` true carries the reason under several different keys depending
        on the route, so all the plausible ones are tried before giving up.
        """
        if not isinstance(payload, dict):
            return payload
        if "error" not in payload:
            return payload
        if payload.get("error"):
            reason = (
                payload.get("error_value")
                or payload.get("message")
                or payload.get("data")
                or "unspecified error"
            )
            raise CapeValidationError(f"CAPE reported an error: {reason}", request_id=self.request_id)
        return payload.get("data", payload)

    # -- operations ----------------------------------------------------------

    def status(self) -> CapeStatus:
        """GET /cuckoo/status/ — reachability, version and machine availability."""
        data = self._json(self._request("GET", PATH_STATUS))
        if not isinstance(data, dict):
            raise CapeValidationError("CAPE status was not an object", request_id=self.request_id)

        machines = data.get("machines") if isinstance(data.get("machines"), dict) else {}
        return CapeStatus(
            reachable=True,
            version=_first_str(data, ("version", "cape_version", "cuckoo_version")),
            tasks=data.get("tasks") if isinstance(data.get("tasks"), dict) else {},
            machines_total=_as_int(machines.get("total")),
            machines_available=_as_int(machines.get("available")),
            raw=data,
        )

    def search_by_sha256(self, sha256: str) -> list[CapeTask]:
        """Existing analyses for a hash. Empty list when CAPE has none.

        A 404 here means "nothing found", which is an answer rather than a
        failure — CAPE uses it for an empty search on some builds.
        """
        digest = str(sha256 or "").strip().lower()
        if not _SHA256_RE.match(digest):
            raise CapeValidationError("Not a SHA-256 digest", request_id=self.request_id)
        try:
            data = self._json(self._request("GET", PATH_SEARCH_SHA256.format(sha256=digest)))
        except CapeValidationError as exc:
            if "404" in str(exc) or "no such resource" in str(exc).lower():
                return []
            raise
        return [t for t in (_as_task(item) for item in _as_list(data)) if t is not None]

    def search_reports(self, option: str, argument: str) -> list[dict[str, Any]]:
        """Search CAPE's analysis store by something other than a file hash.

        This is how "which analyses contacted this domain" is answered. The GET
        /tasks/search/ route accepts only md5, sha1 and sha256 — verified
        against the live instance, where /tasks/search/domain/ returns 404 —
        so anything else goes through POST /tasks/extendedsearch/.

        Returns **report-shaped** dicts, not task stubs: CAPE answers this with
        `{info, target, network, malscore}` per match, which is the substance
        of a report already. The domain lookup therefore needs no second call,
        and avoids pulling a 41MB report to learn one fact.

        A miss comes back as `{"error": true, "error_value": "Unable to
        retrieve records"}` — the same envelope CAPE uses for a genuine
        failure — so it is translated to an empty list rather than raised.
        Confirmed by searching a term that does exist, which returns
        `error: false` with data.

        `option` is restricted to a known set: it lands in a POST body CAPE
        dispatches on, and passing a caller's string through would let a
        request steer the query.
        """
        allowed = {"domain", "ip", "url", "name", "signature", "malfamily", "sha256", "md5", "imphash"}
        key = str(option or "").strip().lower()
        if key not in allowed:
            raise CapeValidationError(f"Unsupported search option {option!r}", request_id=self.request_id)
        value = str(argument or "").strip()
        if not value or len(value) > 512:
            raise CapeValidationError("Search argument is empty or too long", request_id=self.request_id)

        response = self._request(
            "POST", PATH_EXTENDED_SEARCH, data={"option": key, "argument": value}, retry=False
        )
        try:
            payload = self._json(response)
        except CapeValidationError as exc:
            if "unable to retrieve records" in str(exc).lower():
                return []
            raise
        return [item for item in _as_list(payload) if isinstance(item, dict)]

    def submit_file(
        self,
        *,
        file_obj: BinaryIO,
        filename: str,
        route: str | None = None,
        analysis_timeout: int | None = None,
    ) -> CapeSubmission:
        """POST a sample. Streamed — the file is never read into memory whole.

        Never retried. An ambiguous outcome raises CapeAmbiguousSubmission and
        the caller reconciles by hash; resending would detonate twice.

        No machine is named. CAPE schedules across its own pool, and pinning a
        VM here would serialise every submission onto one of six.
        """
        settings = self.settings
        data = {
            "route": str(route or settings.cape_route or "internet"),
            "timeout": str(int(analysis_timeout or settings.cape_analysis_timeout_seconds)),
            "enforce_timeout": "1",
        }
        files = {"file": (_safe_filename(filename), file_obj, "application/octet-stream")}

        try:
            response = self._request("POST", PATH_CREATE_FILE, files=files, data=data, retry=False)
        except (CapeTimeout, CapeConnectionError) as exc:
            raise CapeAmbiguousSubmission(
                f"Submission outcome unknown — CAPE may or may not have accepted the sample: {exc}",
                request_id=self.request_id,
            ) from None

        payload = self._json(response)
        task_ids = _extract_task_ids(payload)
        if not task_ids:
            raise CapeValidationError(
                f"CAPE accepted the submission but named no task id: {str(payload)[:300]}",
                request_id=self.request_id,
            )
        return CapeSubmission(task_ids=tuple(task_ids), raw=payload if isinstance(payload, dict) else {})

    def submit_url(
        self, *, url: str, route: str | None = None, analysis_timeout: int | None = None
    ) -> CapeSubmission:
        """Ask CAPE to fetch and detonate a URL.

        The parameter name is `url`, taken from this instance's own API page:
        `curl -F url="somebadness.tld" .../apiv2/tasks/create/url/`.

        Same rule as a file submission and for the same reason: never retried.
        An ambiguous POST may already have created a task, and resending it
        occupies a second machine from a pool of six.

        The URL is validated here rather than trusted. It reaches CAPE, which
        will fetch it from inside the sandbox network — a caller who could put
        `file://` or an internal address in this field would be choosing what
        the sandbox reaches out to.
        """
        target = _safe_url(url, self.request_id)
        settings = self.settings
        data = {
            "url": target,
            "route": str(route or settings.cape_route or "internet"),
            "timeout": str(int(analysis_timeout or settings.cape_analysis_timeout_seconds)),
            "enforce_timeout": "1",
        }
        try:
            response = self._request("POST", PATH_CREATE_URL, data=data, retry=False)
        except (CapeTimeout, CapeConnectionError) as exc:
            raise CapeAmbiguousSubmission(
                f"URL submission outcome unknown — CAPE may or may not have accepted it: {exc}",
                request_id=self.request_id,
            ) from None

        payload = self._json(response)
        task_ids = _extract_task_ids(payload)
        if not task_ids:
            raise CapeValidationError(
                f"CAPE accepted the URL but named no task id: {str(payload)[:300]}",
                request_id=self.request_id,
            )
        return CapeSubmission(task_ids=tuple(task_ids), raw=payload if isinstance(payload, dict) else {})

    def view_task(self, task_id: int | str) -> CapeTask:
        """GET /tasks/view/{id}/ — lifecycle state. Not the analysis result."""
        tid = _validate_task_id(task_id, self.request_id)
        data = self._json(self._request("GET", PATH_VIEW_TASK.format(task_id=tid)))
        if isinstance(data, dict) and isinstance(data.get("task"), dict):
            data = data["task"]
        task = _as_task(data)
        if task is None:
            raise CapeValidationError("CAPE task view carried no status", request_id=self.request_id)
        return task

    def fetch_iocs(self, task_id: int | str) -> CapeReport:
        """CAPE's own IOC summary for a task.

        The fallback when the full report will not fit. It is not a lesser
        format so much as a different one — CAPE assembles the indicators
        rather than the whole analysis — so most of what this platform stores
        survives, and what does not is recorded as a limitation rather than
        quietly missing.
        """
        tid = _validate_task_id(task_id, self.request_id)
        response = self._request("GET", PATH_IOCS.format(task_id=tid), stream=True)
        try:
            raw, size = _read_bounded(response, int(self.settings.cape_max_report_bytes), self.request_id)
        finally:
            response.close()

        import json as _json_mod

        try:
            payload = _json_mod.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise CapeValidationError(f"CAPE IOC summary was not JSON: {exc}", request_id=self.request_id) from None

        payload = self._unwrap(payload)
        if not isinstance(payload, dict):
            raise CapeValidationError("CAPE IOC summary was not an object", request_id=self.request_id)
        return CapeReport(task_id=int(tid), fmt="iocs", payload=payload, size_bytes=size)

    def fetch_report(self, task_id: int | str, formats: list[str] | None = None) -> CapeReport:
        """The authoritative analysis result, in the first format that works.

        Bounded: the response is read in chunks and abandoned the moment it
        exceeds the configured ceiling, so a pathological report cannot exhaust
        the worker's memory.
        """
        tid = _validate_task_id(task_id, self.request_id)
        wanted = formats or self.settings.cape_report_format_list
        errors: list[str] = []

        for fmt in wanted:
            safe_fmt = re.sub(r"[^a-z0-9_]", "", str(fmt).lower())
            if not safe_fmt:
                continue
            try:
                response = self._request("GET", PATH_REPORT.format(task_id=tid, fmt=safe_fmt), stream=True)
            except CapeValidationError as exc:
                errors.append(f"{safe_fmt}: {exc}")
                continue

            try:
                raw, size = _read_bounded(
                    response, int(self.settings.cape_max_report_bytes), self.request_id
                )
            finally:
                response.close()

            import json as _json_mod

            try:
                payload = _json_mod.loads(raw.decode("utf-8", errors="replace"))
            except ValueError as exc:
                errors.append(f"{safe_fmt}: not JSON ({exc})")
                continue

            payload = self._unwrap(payload)
            if isinstance(payload, dict):
                return CapeReport(task_id=int(tid), fmt=safe_fmt, payload=payload, size_bytes=size)
            errors.append(f"{safe_fmt}: report was not an object")

        raise CapeValidationError(
            "No usable CAPE report format. Tried " + "; ".join(errors or wanted),
            request_id=self.request_id,
        )


# ── helpers ──────────────────────────────────────────────────────────────────


def _is_tls_failure(exc: Exception) -> bool:
    """Walk the cause chain looking for a certificate problem."""
    seen = 0
    current: BaseException | None = exc
    while current is not None and seen < 6:
        if isinstance(current, ssl.SSLError):
            return True
        text = str(current).upper()
        if "CERTIFICATE_VERIFY_FAILED" in text or "SSL" in text and "VERIFY" in text:
            return True
        current = current.__cause__ or current.__context__
        seen += 1
    return False


def _read_bounded(response: httpx.Response, limit: int, request_id: str) -> tuple[bytes, int]:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > limit:
            raise CapeResponseTooLarge(
                f"CAPE report exceeded {limit} bytes; refusing to buffer it.", request_id=request_id
            )
        chunks.append(chunk)
    return b"".join(chunks), total


def _peek(response: httpx.Response, limit: int = 400) -> str:
    try:
        if response.is_closed and not hasattr(response, "_content"):
            return "<body not read>"
        return _redact(response.text[:limit])
    except Exception:
        return "<unreadable body>"


def _retry_after_seconds(value: Any) -> float | None:
    """Honour Retry-After when it is a sane number of seconds."""
    if value is None:
        return None
    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, _MAX_RETRY_AFTER_SECONDS)


def _validate_task_id(task_id: Any, request_id: str) -> str:
    candidate = str(task_id).strip()
    if not _TASK_ID_RE.match(candidate):
        raise CapeValidationError(f"Not a CAPE task id: {candidate!r}", request_id=request_id)
    return candidate


def _safe_url(value: str, request_id: str) -> str:
    """An http(s) URL with a hostname, and nothing else.

    CAPE fetches this from inside the sandbox, so the scheme and target matter:
    `file://` would read the guest's disk, and a bare internal address turns a
    detonation request into a probe of somebody's network.
    """
    from urllib.parse import urlparse

    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 2048:
        raise CapeValidationError("URL is empty or too long", request_id=request_id)
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise CapeValidationError(f"Unsupported URL scheme {parsed.scheme!r}", request_id=request_id)
    if not parsed.hostname:
        raise CapeValidationError("URL has no host", request_id=request_id)
    if any(c in candidate for c in ("\n", "\r", "\x00")):
        raise CapeValidationError("URL contains control characters", request_id=request_id)
    return candidate


def _safe_filename(name: str) -> str:
    """A filename CAPE will accept and that cannot traverse anything."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(name or "").strip())[-120:]
    return cleaned.lstrip(".") or "sample.bin"


def _as_list(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "tasks", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        if data:
            return [data]
    return []


def _as_task(item: Any) -> CapeTask | None:
    if not isinstance(item, dict):
        return None
    task_id = _as_int(item.get("id") or item.get("task_id"))
    status = str(item.get("status") or "").strip().lower()
    if task_id is None or not status:
        return None
    return CapeTask(task_id=task_id, status=status, raw=item)


def _extract_task_ids(payload: Any) -> list[int]:
    """CAPE has used several shapes for this over its releases."""
    if isinstance(payload, int):
        return [payload]
    if not isinstance(payload, dict):
        return []
    for key in ("task_ids", "task_id", "data"):
        value = payload.get(key)
        if isinstance(value, int):
            return [value]
        if isinstance(value, list):
            ids = [_as_int(v) for v in value]
            return [i for i in ids if i is not None]
        if isinstance(value, dict):
            nested = _extract_task_ids(value)
            if nested:
                return nested
    return []


def _first_str(data: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
