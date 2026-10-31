"""Trusted HTTP/HTTPS transport for WPE's brokered data plane.

WPE itself has no direct origin route. This module is trusted-side transport:
policy is decided before fetch by WPEGatewayRenderer/RequestChannel. Stage 5E
adds bounded trusted-side top-level session-cookie continuity without giving WPE
cookie authority. Renderer-originated static/XHR/POST requests remain cookie-free
until their credential mode can be represented faithfully. Persistent/domain
cookies and renderer credential headers remain outside that path. Stage 5G adds a
bounded trusted-side exact-origin Basic Authorization store for top-level HTTPS
navigation only; WPE and renderer-originated requests never receive that authority.
Stage 5H adds an optional challenge-only mode for those already-provisioned Basic
credentials: the first trusted top-level HTTPS request carries no Authorization,
and at most one exact-origin retry is permitted after a real Basic 401 challenge.
Stage 5I adds a typed trusted-side Basic credential resolver for credentials that
were not pre-provisioned. The resolver is consulted only after an exact top-level
HTTPS Basic 401 challenge and never crosses into WPE or renderer request metadata.
Stage 5K adds one deliberately narrow RFC 7616 Digest path: an unambiguous
top-level HTTPS Digest 401 using algorithm=SHA-256 and qop=auth may invoke a
separate trusted frontend resolver and receive exactly one same-URL retry.
Digest credentials and the computed Authorization header are never persisted or
made available to renderer-originated requests. The live crawler may additionally
supply an internal pre-resolved public address set; when supplied, the TCP connection
is pinned to that set while the original hostname remains authoritative for Host,
TLS SNI, and certificate validation.
"""
from __future__ import annotations

from dataclasses import dataclass
import mmap
import base64
import errno
import sys
from http.cookies import CookieError, SimpleCookie
import http.client
import hashlib
import ipaddress
import secrets
import socket
import ssl
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from bojangles.security.privacy import BROWSER_USER_AGENT, PrivacyPolicyError, minimized_referer


MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BODY_BYTES = 1024 * 1024 * 1024
MAX_MEMORY_REQUEST_BODY_BYTES = 64 * 1024 * 1024
MAX_CROSS_ORIGIN_POST_BYTES = 256 * 1024
MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 16 * 1024
# Responses carry multiple independent policy/reporting fields. Keep their
# aggregate budget separate from renderer-originated request authority.
MAX_RESPONSE_HEADER_BYTES = 32 * 1024
MAX_REQUEST_HEADER_VALUE_BYTES = 4096
MAX_RESPONSE_HEADER_VALUE_BYTES = 8 * 1024
MAX_SESSION_COOKIES = 64
MAX_COOKIE_BYTES = 4096
MAX_COOKIE_HEADER_BYTES = 8192
MAX_AUTH_ORIGINS = 16
MAX_AUTH_CREDENTIAL_BYTES = 2048

_REQUEST_HEADER_ALLOWLIST = frozenset({
    "accept",
    "accept-language",
    "origin",
    "access-control-request-method",
    "access-control-request-headers",
    "cache-control",
    "pragma",
    "range",
    "if-modified-since",
    "if-none-match",
    "content-type",
    "x-csrftoken",
    "x-xsrf-token",
    "x-wp-nonce",
})
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
})
_RESPONSE_HEADER_DENY = _HOP_BY_HOP | frozenset({"set-cookie", "set-cookie2"})


class WPETransportError(RuntimeError):
    pass


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Dial only addresses already approved by the trusted network policy."""

    def __init__(self, host, *, approved_addresses, **kwargs):
        super().__init__(host, **kwargs)
        self.approved_addresses = tuple(approved_addresses)
        if not self.approved_addresses:
            raise WPETransportError("approved address set is empty")

    def connect(self):
        if self._tunnel_host:
            raise WPETransportError("pinned connections do not permit proxy tunnels")
        sys.audit("http.client.connect", self, self.host, self.port)
        last_error = None
        for address in self.approved_addresses:
            try:
                self.sock = socket.create_connection(
                    (address, self.port), self.timeout, self.source_address
                )
                break
            except OSError as error:
                last_error = error
        else:
            raise last_error or OSError("no approved resolved address available")
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as error:
            if error.errno != errno.ENOPROTOOPT:
                self.close()
                raise


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    """Pinned TCP destination with the original TLS hostname and trust policy."""

    default_port = 443

    def __init__(self, host, *, context=None, **kwargs):
        self.tls_context = context if context is not None else ssl.create_default_context()
        if context is None:
            self.tls_context.set_alpn_protocols(["http/1.1"])
        super().__init__(host, **kwargs)

    def connect(self):
        super().connect()
        try:
            self.sock = self.tls_context.wrap_socket(self.sock, server_hostname=self.host)
        except BaseException:
            self.close()
            raise


class WPERedirectRequired(WPETransportError):
    def __init__(self, target: str, status: int, headers=(), *, accepted_cookie_headers=()) -> None:
        super().__init__(f"HTTP redirect {status} requires frontend authority: {target}")
        self.target = target
        self.status = status
        self.headers = tuple(headers)
        self.accepted_cookie_headers = tuple(accepted_cookie_headers)


def response_offers_download(url: str, mime_type: str, disposition: str) -> bool:
    """Honor explicit attachments and first-party Archive download-file media."""
    if str(disposition).lstrip().casefold().startswith('attachment'):
        return True
    parsed = urlsplit(url)
    host = (parsed.hostname or '').lower()
    media = mime_type.split(';', 1)[0].strip().lower().startswith(('audio/', 'video/'))
    if not media:
        return False
    if host == 'archive.org' and parsed.path.startswith('/download/'):
        return True
    # The Archive download endpoint redirects to its storage hosts. Preserve
    # download treatment after that frontend-authorized redirect.
    return host.endswith('.archive.org') and '/items/' in parsed.path


class WPEDownloadOffered(WPETransportError):
    """A trusted response must be authorized as a file, before buffering it."""

    def __init__(self, url: str, suggested_filename: str = '') -> None:
        super().__init__('response offered as a download')
        self.url = url
        self.suggested_filename = suggested_filename


class WPEMediaOffered(WPETransportError):
    """A page media resource needs the trusted media handoff, not a download."""

    def __init__(self, url: str, mime_type: str) -> None:
        super().__init__('media requires frontend handoff')
        self.url = url
        self.mime_type = mime_type


@dataclass(frozen=True, slots=True)
class WPEFetchedDocument:
    url: str
    status: int
    mime_type: str
    encoding: str
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()


def _header_name_is_token(name: str) -> bool:
    if not name or len(name) > 128 or not name.isascii():
        return False
    token = "!#$%&'*+-.^_`|~"
    return all(ch.isalnum() or ch in token for ch in name)


def _clean_header_pairs(
    pairs,
    *,
    allow_names: frozenset[str] | None = None,
    deny_names: frozenset[str] = frozenset(),
    max_value_bytes: int = MAX_REQUEST_HEADER_VALUE_BYTES,
    max_total_bytes: int = MAX_HEADER_BYTES,
) -> tuple[tuple[str, str], ...]:
    cleaned: list[tuple[str, str]] = []
    total = 0
    for raw_name, raw_value in pairs or ():
        name = str(raw_name)
        value = str(raw_value)
        lower = name.casefold()
        if allow_names is not None and lower not in allow_names:
            continue
        if lower in deny_names:
            continue
        if not _header_name_is_token(name):
            raise WPETransportError("invalid WPE HTTP header name")
        if len(value.encode("utf-8")) > max_value_bytes or any(ch in value for ch in "\r\n\0"):
            raise WPETransportError("invalid WPE HTTP header value")
        total += len(name.encode("ascii", errors="strict")) + len(value.encode("utf-8")) + 4
        if len(cleaned) >= MAX_HEADER_COUNT or total > max_total_bytes:
            raise WPETransportError("WPE HTTP headers exceed trusted bound")
        cleaned.append((name, value))
    return tuple(cleaned)


# Script application headers are distinct from host-owned transport metadata.
# CORS approval is required before these reach a cross-origin HTTP receiver.
_FORBIDDEN_APPLICATION_HEADERS = frozenset({
    "accept-charset", "accept-encoding", "access-control-request-headers",
    "access-control-request-method", "connection", "content-length", "cookie",
    "cookie2", "date", "dnt", "expect", "host", "keep-alive", "origin",
    "permissions-policy", "referer", "set-cookie", "te", "trailer",
    "transfer-encoding", "upgrade", "via", "user-agent", "proxy-authorization",
})


def _application_header_name(name):
    return (_header_name_is_token(name)
            and name not in _FORBIDDEN_APPLICATION_HEADERS
            and not name.startswith(("proxy-", "sec-")))


def sanitize_application_headers(pairs):
    # Validate the whole bounded envelope, including fields that will be dropped.
    checked = _clean_header_pairs(pairs)
    result = []
    for name, value in checked:
        lower = name.casefold()
        if lower in _REQUEST_HEADER_ALLOWLIST or _application_header_name(lower):
            if lower in {"x-http-method", "x-http-method-override", "x-method-override"}:
                if any(v.strip().upper() in {"CONNECT", "TRACE", "TRACK"} for v in value.split(",")):
                    raise WPETransportError("forbidden application method override")
            result.append((name, value))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class _WPESessionCookie:
    name: str
    value: str
    host: str
    path: str
    secure: bool


def _default_cookie_path(path: str) -> str:
    if not path.startswith("/") or path == "/":
        return "/"
    slash = path.rfind("/")
    return "/" if slash <= 0 else path[:slash]


def _cookie_path_matches(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path):len(cookie_path)+1] == "/"


class WPESessionCookieJar:
    """Bounded trusted-side host-only session cookies for top-level navigation.

    This is deliberately not a browser cookie database. Nothing is written to
    disk, Domain cookies and persistent lifetime attributes are rejected, and
    renderer-originated requests do not consult this jar in Stage 5E.
    """

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, str], _WPESessionCookie] = {}

    def __len__(self) -> int:
        return len(self._cookies)

    def _delete(self, host: str, path: str, name: str) -> None:
        self._cookies.pop((host, path, name), None)

    def store_set_cookie(self, url: str, header: str) -> None:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold()
        if parsed.scheme.casefold() not in {"http", "https"} or not host:
            raise WPETransportError("session cookie source requires HTTP/HTTPS host")
        raw = str(header)
        if len(raw.encode("utf-8")) > MAX_COOKIE_BYTES or any(ch in raw for ch in "\r\n\0"):
            raise WPETransportError("invalid Set-Cookie value")
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except CookieError as exc:
            raise WPETransportError("malformed Set-Cookie value") from exc
        if len(jar) != 1:
            raise WPETransportError("ambiguous Set-Cookie value")
        name, morsel = next(iter(jar.items()))
        if not _header_name_is_token(name):
            raise WPETransportError("invalid session cookie name")
        value = morsel.value
        if len(value.encode("utf-8")) > MAX_COOKIE_BYTES or any(ch in value for ch in ";\r\n\0"):
            raise WPETransportError("invalid session cookie value")
        if morsel["domain"]:
            raise WPETransportError("Stage 5E rejects Domain cookies")
        if morsel["expires"]:
            raise WPETransportError("Stage 5E rejects persistent Expires cookies")
        max_age = morsel["max-age"]
        path = morsel["path"] or _default_cookie_path(parsed.path or "/")
        if not path.startswith("/") or len(path) > 1024 or any(ch in path for ch in "\r\n\0"):
            raise WPETransportError("invalid session cookie path")
        if max_age:
            if max_age.strip() == "0":
                self._delete(host, path, name)
                return
            raise WPETransportError("Stage 5E rejects persistent Max-Age cookies")
        secure = bool(morsel["secure"])
        same_site = morsel["samesite"].casefold() if morsel["samesite"] else ""
        if same_site not in {"", "lax", "strict", "none"}:
            raise WPETransportError("invalid SameSite cookie attribute")
        if same_site == "strict":
            raise WPETransportError("Stage 5E rejects SameSite=Strict without site-context fidelity")
        if secure and parsed.scheme.casefold() != "https":
            raise WPETransportError("Secure session cookie requires HTTPS source")
        if same_site == "none" and not secure:
            raise WPETransportError("SameSite=None session cookie requires Secure")
        key = (host, path, name)
        if key not in self._cookies and len(self._cookies) >= MAX_SESSION_COOKIES:
            raise WPETransportError("trusted session cookie budget exceeded")
        self._cookies[key] = _WPESessionCookie(name, value, host, path, secure)

    def store_response(self, url: str, headers) -> None:
        for header in headers or ():
            try:
                self.store_set_cookie(url, header)
            except WPETransportError:
                # Cookie acceptance is fail-closed, but an unsupported cookie is
                # not allowed to convert a valid HTTP response into navigation failure.
                continue

    def cookie_header(
        self,
        url: str,
        *,
        site_for_cookies: str = "",
        top_level_navigation: bool = False,
        method: str = "GET",
    ) -> str:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold()
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"} or not host:
            return ""
        path = parsed.path or "/"
        candidates = [
            cookie for cookie in self._cookies.values()
            if cookie.host == host
            and (not cookie.secure or scheme == "https")
            and _cookie_path_matches(path, cookie.path)
        ]
        candidates.sort(key=lambda cookie: (-len(cookie.path), cookie.name))
        header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in candidates)
        if len(header.encode("utf-8")) > MAX_COOKIE_HEADER_BYTES:
            raise WPETransportError("trusted session Cookie header exceeds bound")
        return header


@dataclass(frozen=True, slots=True)
class WPEBasicChallenge:
    """Bounded frontend-visible Basic challenge metadata.

    It contains no WPE state, request body, cookies, or credentials. The URL is
    the already-authorized trusted top-level HTTPS URL that produced the 401.
    """

    url: str
    realm: str = ""


@dataclass(frozen=True, slots=True)
class WPEBasicCredential:
    """One in-memory Basic credential returned by trusted frontend authority."""

    username: str
    password: str


class WPEBasicCredentialResolver(Protocol):
    """Trusted frontend hook used only after an explicit Basic 401 challenge."""

    def resolve_basic(self, challenge: WPEBasicChallenge) -> WPEBasicCredential | None: ...


@dataclass(frozen=True, slots=True)
class WPEDigestChallenge:
    """Bounded trusted-side RFC 7616 SHA-256/qop=auth challenge."""

    url: str
    realm: str
    nonce: str
    opaque: str = ""
    algorithm: str = "SHA-256"
    qop: str = "auth"


@dataclass(frozen=True, slots=True)
class WPEDigestCredential:
    """One ephemeral Digest username/password returned by frontend authority."""

    username: str
    password: str


class WPEDigestCredentialResolver(Protocol):
    """Trusted frontend hook for one exact HTTPS Digest challenge."""

    def resolve_digest(self, challenge: WPEDigestChallenge) -> WPEDigestCredential | None: ...


class WPEAuthorizationStore:
    """Bounded trusted-side Basic Authorization for exact HTTPS origins.

    The store is memory-only and deliberately separate from renderer request
    metadata. Stage 5G retains explicit preemptive top-level Basic credentials.
    Stage 5H additionally allows an entry to be challenge-only: BoJangles sends
    no Authorization on the first request and may retry exactly once only after
    a real HTTP 401 response carrying a Basic challenge. There is still no
    browser prompt, automatic credential discovery, or persistence surface. Stage
    5I may populate the same bounded memory-only store through a trusted frontend
    resolver after an explicit Basic 401 challenge.
    """

    def __init__(self) -> None:
        self._headers: dict[tuple[str, str, int], str] = {}
        self._challenge_only: set[tuple[str, str, int]] = set()

    def __len__(self) -> int:
        return len(self._headers)

    @staticmethod
    def _https_origin(url: str) -> tuple[str, str, int]:
        parsed = urlsplit(url)
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").casefold()
        if scheme != "https" or not host:
            raise WPETransportError("trusted Basic Authorization requires HTTPS origin")
        if parsed.username is not None or parsed.password is not None:
            raise WPETransportError("userinfo is not accepted in Authorization origin")
        try:
            parsed_port = parsed.port
            port = 443 if parsed_port is None else parsed_port
        except ValueError as exc:
            raise WPETransportError("invalid Authorization origin port") from exc
        return scheme, host, port

    @staticmethod
    def _ascii_secret(value: str, *, field: str, allow_empty: bool) -> str:
        value = str(value)
        if not value and not allow_empty:
            raise WPETransportError(f"Basic Authorization {field} is empty")
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise WPETransportError(f"Basic Authorization {field} must be printable ASCII")
        try:
            encoded = value.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise WPETransportError(f"Basic Authorization {field} must be ASCII") from exc
        if len(encoded) > MAX_AUTH_CREDENTIAL_BYTES:
            raise WPETransportError(f"Basic Authorization {field} exceeds trusted bound")
        return value

    def set_basic(
        self,
        url: str,
        username: str,
        password: str,
        *,
        challenge_only: bool = False,
    ) -> None:
        origin = self._https_origin(url)
        username = self._ascii_secret(username, field="username", allow_empty=False)
        password = self._ascii_secret(password, field="password", allow_empty=True)
        if ":" in username:
            raise WPETransportError("Basic Authorization username may not contain colon")
        raw = f"{username}:{password}".encode("ascii", errors="strict")
        if len(raw) > MAX_AUTH_CREDENTIAL_BYTES:
            raise WPETransportError("Basic Authorization credential exceeds trusted bound")
        if origin not in self._headers and len(self._headers) >= MAX_AUTH_ORIGINS:
            raise WPETransportError("trusted Authorization origin budget exceeded")
        token = base64.b64encode(raw).decode("ascii")
        self._headers[origin] = f"Basic {token}"
        if bool(challenge_only):
            self._challenge_only.add(origin)
        else:
            self._challenge_only.discard(origin)

    def clear(self, url: str) -> None:
        origin = self._https_origin(url)
        self._headers.pop(origin, None)
        self._challenge_only.discard(origin)

    def authorization_header(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() != "https":
            return ""
        return self._headers.get(self._https_origin(url), "")

    def challenge_only(self, url: str) -> bool:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() != "https":
            return False
        return self._https_origin(url) in self._challenge_only


class WPEAllowedDataTransport:
    def __init__(
        self,
        *,
        timeout: float = 15.0,
        max_bytes: int = MAX_DOCUMENT_BYTES,
        max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES,
        ssl_context: ssl.SSLContext | None = None,
        session_cookies: WPESessionCookieJar | None = None,
        authorization_store: WPEAuthorizationStore | None = None,
        basic_credential_resolver: WPEBasicCredentialResolver | None = None,
        digest_credential_resolver: WPEDigestCredentialResolver | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_bytes <= 0 or max_bytes > MAX_DOCUMENT_BYTES:
            raise ValueError("invalid WPE document byte budget")
        if max_request_body_bytes <= 0 or max_request_body_bytes > MAX_REQUEST_BODY_BYTES:
            raise ValueError("invalid WPE request-body budget")
        self.timeout = float(timeout)
        self.max_bytes = int(max_bytes)
        self.max_request_body_bytes = int(max_request_body_bytes)
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.session_cookies = session_cookies if session_cookies is not None else WPESessionCookieJar()
        self.authorization_store = (
            authorization_store if authorization_store is not None else WPEAuthorizationStore()
        )
        self.basic_credential_resolver = basic_credential_resolver
        self.digest_credential_resolver = digest_credential_resolver

    @staticmethod
    def _parts(url: str):
        parsed = urlsplit(url)
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise WPETransportError("trusted WPE transport requires HTTP/HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise WPETransportError("userinfo is not accepted in renderer URLs")
        try:
            port = parsed.port
        except ValueError as exc:
            raise WPETransportError("invalid renderer URL port") from exc
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        return parsed, scheme, port, target

    def request_timeout(self, body=None):
        # Bulk uploads have a size-based total deadline; ordinary page requests
        # retain their original budget. A 15-minute ceiling remains bounded.
        if body is not None and len(body) > 1024 * 1024:
            return max(self.timeout, min(900.0, self.timeout + len(body) / (128 * 1024)))
        return self.timeout

    @staticmethod
    def sanitize_request_headers(pairs) -> tuple[tuple[str, str], ...]:
        return _clean_header_pairs(pairs, allow_names=_REQUEST_HEADER_ALLOWLIST)

    @classmethod
    def trusted_origin_header(cls, source_url: str) -> str:
        parsed, scheme, port, _target = cls._parts(source_url)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        default_port = 443 if scheme == "https" else 80
        suffix = f":{port}" if port is not None and port != default_port else ""
        return f"{scheme}://{host}{suffix}"

    @classmethod
    def trusted_referer_header(cls, source_url: str, target_url: str) -> str | None:
        source = str(source_url)
        target = str(target_url)
        if any(
            len(value.encode("utf-8")) > 8192 or any(
                ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value
            )
            for value in (source, target)
        ):
            raise WPETransportError("invalid trusted Referer value")
        try:
            return minimized_referer(source, target)
        except PrivacyPolicyError as exc:
            raise WPETransportError(str(exc)) from exc

    @staticmethod
    def sanitize_response_headers(pairs) -> tuple[tuple[str, str], ...]:
        return _clean_header_pairs(
            pairs,
            deny_names=_RESPONSE_HEADER_DENY,
            max_value_bytes=MAX_RESPONSE_HEADER_VALUE_BYTES,
            max_total_bytes=MAX_RESPONSE_HEADER_BYTES,
        )

    def fetch_once(
        self,
        url: str,
        *,
        method: str = "GET",
        request_headers=(),
        body: bytes | bytearray | memoryview | None = None,
        send_session_cookies: bool = False,
        store_session_cookies: bool = False,
        cookie_site_url: str = "",
        top_level_navigation: bool = False,
        send_authorization: bool = False,
        _trusted_authorization_header: str = "",
        _trusted_referer: str = "",
        _resolved_addresses: tuple[str, ...] = (),
        _cors_preflight: bool = False,
        _application_request: bool = False,
        offer_download: bool = False,
        offer_media: bool = False,
    ) -> WPEFetchedDocument:
        from bojangles.diagnostics import record

        parsed, scheme, port, target = self._parts(url)
        method = str(method).upper()
        if method not in {"GET", "POST", "HEAD", "OPTIONS"}:
            raise WPETransportError("trusted transport permits GET/POST/HEAD only")
        body_bytes = normalize_request_body(body)
        if method == "OPTIONS":
            if _cors_preflight:
                if send_session_cookies or store_session_cookies or send_authorization or top_level_navigation:
                    raise WPETransportError("OPTIONS requires credential-free trusted preflight")
            else:
                if top_level_navigation or not _trusted_referer:
                    raise WPETransportError("ordinary OPTIONS requires a trusted same-origin document")
                if classify_options_request(url, _trusted_referer, request_headers):
                    raise WPETransportError("preflight requires explicit trusted preflight authority")
        if method in {"GET", "HEAD", "OPTIONS"} and body_bytes:
            raise WPETransportError(f"{method} request body is not permitted")
        if len(body_bytes) > self.max_request_body_bytes:
            raise WPETransportError("WPE request body exceeded trusted byte budget")

        host = parsed.hostname
        approved: list[str] = []
        for raw_address in _resolved_addresses:
            try:
                address = ipaddress.ip_address(str(raw_address))
            except ValueError as exc:
                raise WPETransportError("invalid trusted resolved address") from exc
            if not address.is_global:
                raise WPETransportError("trusted resolved address is not globally routable")
            canonical = str(address)
            if canonical not in approved:
                approved.append(canonical)

        connection: http.client.HTTPConnection
        if scheme == "https":
            if approved:
                connection = _PinnedHTTPSConnection(
                    host, port=port, timeout=self.timeout, context=self.ssl_context,
                    approved_addresses=approved,
                )
            else:
                connection = http.client.HTTPSConnection(
                    host, port=port, timeout=self.timeout, context=self.ssl_context,
                )
        elif approved:
            connection = _PinnedHTTPConnection(
                host, port=port, timeout=self.timeout, approved_addresses=approved,
            )
        else:
            connection = http.client.HTTPConnection(host, port=port, timeout=self.timeout)

        if _application_request and (not _trusted_referer or _cors_preflight):
            raise WPETransportError("application headers require document resource authority")
        forwarded = (sanitize_application_headers(request_headers) if _application_request
                     else self.sanitize_request_headers(request_headers))
        headers = {
            "User-Agent": BROWSER_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        for name, value in forwarded:
            for existing in tuple(headers):
                if existing.casefold() == name.casefold():
                    del headers[existing]
            headers[name] = value
        if _trusted_referer:
            referer = self.trusted_referer_header(_trusted_referer, url)
            if referer:
                headers["Referer"] = referer
        if method == "POST" and not any(name.casefold() == "content-type" for name in headers):
            headers["Content-Type"] = "application/octet-stream"
        if send_session_cookies:
            cookie_header = self.session_cookies.cookie_header(
                url,
                site_for_cookies=cookie_site_url,
                top_level_navigation=top_level_navigation,
                method=method,
            )
            if cookie_header:
                headers["Cookie"] = cookie_header
        if send_authorization:
            authorization = self.authorization_store.authorization_header(url)
            if authorization:
                headers["Authorization"] = authorization
        if _trusted_authorization_header:
            if send_authorization:
                raise WPETransportError("conflicting trusted Authorization sources")
            if scheme != "https":
                raise WPETransportError("trusted Digest Authorization requires HTTPS")
            digest_header = str(_trusted_authorization_header)
            if not digest_header.startswith("Digest "):
                raise WPETransportError("trusted Authorization override is not Digest")
            try:
                digest_header_bytes = digest_header.encode("ascii", errors="strict")
            except UnicodeEncodeError as exc:
                raise WPETransportError("trusted Digest Authorization must be ASCII") from exc
            if len(digest_header_bytes) > MAX_HEADER_BYTES:
                raise WPETransportError("trusted Digest Authorization exceeds header bound")
            if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in digest_header):
                raise WPETransportError("trusted Digest Authorization contains unsafe bytes")
            headers["Authorization"] = digest_header

        if isinstance(body_bytes, mmap.mmap):
            body_bytes.seek(0)
            headers["Content-Length"] = str(len(body_bytes))
        try:
            record(
                "http_attempt",
                url=url,
                method=method,
                top_level=bool(top_level_navigation),
            )
            connection.request(
                method,
                target,
                body=(body_bytes if method == "POST" else None),
                headers=headers,
            )
            response = connection.getresponse()
            if store_session_cookies:
                self.session_cookies.store_response(
                    url, response.headers.get_all("Set-Cookie", []) or ()
                )
            location = response.getheader("Location")
            if 300 <= response.status < 400 and location:
                record(
                    "http_redirect",
                    url=url,
                    redirect=urljoin(url, location),
                    status=response.status,
                )
                raise WPERedirectRequired(urljoin(url, location), response.status,
                                          self.sanitize_response_headers(response.getheaders()))
            mime_type = response.headers.get_content_type() or "application/octet-stream"
            if offer_download and method == 'GET' and 200 <= response.status < 300:
                disposition = response.getheader('Content-Disposition') or ''
                if response_offers_download(url, mime_type, disposition):
                    from bojangles.downloads import _suggested_name
                    record("transport_handoff", url=url, kind="download", status=response.status)
                    raise WPEDownloadOffered(url, _suggested_name(url, disposition, mime_type))
            if offer_media and method == 'GET' and 200 <= response.status < 300:
                if mime_type.casefold().startswith(("audio/", "video/")):
                    record("transport_handoff", url=url, kind="media", status=response.status,
                           mime_type=mime_type)
                    raise WPEMediaOffered(url, mime_type)
            response_body = b"" if method == "HEAD" else response.read(self.max_bytes + 1)
            if len(response_body) > self.max_bytes:
                raise WPETransportError("renderer document exceeded trusted byte budget")
            encoding = response.headers.get_content_charset() or ""
            response_headers = self.sanitize_response_headers(response.getheaders())
            record(
                "http_response",
                url=url,
                status=response.status,
                mime_type=mime_type,
                bytes=len(response_body),
            )
            return WPEFetchedDocument(
                url, response.status, mime_type, encoding, response_body, response_headers
            )
        except (WPERedirectRequired, WPEDownloadOffered, WPEMediaOffered):
            raise
        except WPETransportError as exc:
            record("transport_error", url=url, error=str(exc))
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            record("transport_error", url=url, error=str(exc))
            raise WPETransportError(f"trusted HTTP/HTTPS fetch failed: {exc}") from exc
        finally:
            connection.close()

    @staticmethod
    def _has_basic_challenge(headers: tuple[tuple[str, str], ...]) -> bool:
        """Return True only for an explicit leading Basic WWW-Authenticate challenge."""
        for name, value in headers:
            if name.casefold() != "www-authenticate":
                continue
            candidate = value.lstrip()
            if not candidate:
                continue
            scheme = candidate.split(None, 1)[0]
            if scheme.casefold() == "basic":
                return True
        return False

    @staticmethod
    def _basic_challenge(url: str, headers: tuple[tuple[str, str], ...]) -> WPEBasicChallenge | None:
        """Return one unambiguous leading Basic challenge for a trusted HTTPS URL."""
        parsed = urlsplit(url)
        if parsed.scheme.casefold() != "https" or not parsed.hostname:
            return None
        values: list[str] = []
        for name, value in headers:
            if name.casefold() != "www-authenticate":
                continue
            candidate = value.lstrip()
            if not candidate:
                continue
            scheme = candidate.split(None, 1)[0]
            if scheme.casefold() == "basic":
                values.append(candidate)
        if len(values) != 1:
            return None
        candidate = values[0]
        params = candidate[len(candidate.split(None, 1)[0]):].strip()
        realm = ""
        if params:
            # Stage 5I deliberately accepts only one simple optional realm
            # parameter. Combined challenge grammar is not guessed.
            lower = params.casefold()
            if not lower.startswith("realm="):
                return None
            raw = params[len("realm="):].lstrip()
            if raw.startswith('"'):
                out: list[str] = []
                escaped = False
                closed = False
                consumed = 1
                for ch in raw[1:]:
                    consumed += 1
                    if escaped:
                        out.append(ch)
                        escaped = False
                        continue
                    if ch == "\\":
                        escaped = True
                        continue
                    if ch == '"':
                        closed = True
                        break
                    out.append(ch)
                if not closed or raw[consumed:].strip():
                    return None
                realm = "".join(out)
            else:
                if any(ch.isspace() or ch == "," for ch in raw):
                    return None
                realm = raw
        if any(ch in realm for ch in "\r\n\0"):
            return None
        if len(realm.encode("utf-8")) > 512:
            return None
        return WPEBasicChallenge(url=url, realm=realm)

    @staticmethod
    def _digest_auth_params(raw: str) -> dict[str, str] | None:
        """Parse one strict comma-separated RFC auth-param list.

        Stage 5K intentionally does not guess combined challenges or duplicate
        directives. Values are bounded ASCII because the terminal credential
        gate is likewise ASCII-only.
        """
        params: dict[str, str] = {}
        i = 0
        n = len(raw)
        while True:
            while i < n and raw[i] in " \t":
                i += 1
            if i >= n:
                break
            start = i
            token_chars = "!#$%&'*+-.^_`|~"
            while i < n and (raw[i].isalnum() or raw[i] in token_chars):
                i += 1
            if i == start:
                return None
            name = raw[start:i].casefold()
            if name in params:
                return None
            while i < n and raw[i] in " \t":
                i += 1
            if i >= n or raw[i] != "=":
                return None
            i += 1
            while i < n and raw[i] in " \t":
                i += 1
            if i >= n:
                return None
            if raw[i] == '"':
                i += 1
                out: list[str] = []
                while i < n:
                    ch = raw[i]
                    i += 1
                    if ch == '"':
                        break
                    if ch == "\\":
                        if i >= n:
                            return None
                        ch = raw[i]
                        i += 1
                    if ord(ch) < 0x20 or ord(ch) > 0x7E:
                        return None
                    out.append(ch)
                else:
                    return None
                value = "".join(out)
            else:
                start_value = i
                while i < n and raw[i] not in ", \t":
                    ch = raw[i]
                    if ord(ch) < 0x21 or ord(ch) > 0x7E:
                        return None
                    i += 1
                if i == start_value:
                    return None
                value = raw[start_value:i]
            if len(value.encode("ascii", errors="strict")) > 2048:
                return None
            params[name] = value
            while i < n and raw[i] in " \t":
                i += 1
            if i >= n:
                break
            if raw[i] != ",":
                return None
            i += 1
        return params

    @classmethod
    def _digest_challenge(
        cls,
        url: str,
        headers: tuple[tuple[str, str], ...],
    ) -> WPEDigestChallenge | None:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() != "https" or not parsed.hostname:
            return None
        values = [
            value.lstrip()
            for name, value in headers
            if name.casefold() == "www-authenticate" and value.lstrip()
        ]
        # Stage 5K accepts exactly one authentication challenge total. This
        # avoids scheme-choice ambiguity and combined-header grammar.
        if len(values) != 1:
            return None
        candidate = values[0]
        parts = candidate.split(None, 1)
        if not parts or parts[0].casefold() != "digest" or len(parts) != 2:
            return None
        params = cls._digest_auth_params(parts[1].strip())
        if params is None:
            return None
        allowed = {
            "realm", "nonce", "opaque", "algorithm", "qop",
            "stale", "charset", "userhash",
        }
        if not set(params).issubset(allowed):
            return None
        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        algorithm = params.get("algorithm", "")
        qop = params.get("qop", "")
        if not realm or not nonce:
            return None
        if algorithm.casefold() != "sha-256":
            return None
        if qop.casefold() != "auth":
            return None
        stale = params.get("stale", "false").casefold()
        if stale not in {"", "false"}:
            return None
        charset = params.get("charset", "")
        if charset and charset.casefold() != "utf-8":
            return None
        userhash = params.get("userhash", "false").casefold()
        if userhash not in {"", "false"}:
            return None
        opaque = params.get("opaque", "")
        return WPEDigestChallenge(
            url=url,
            realm=realm,
            nonce=nonce,
            opaque=opaque,
        )

    @staticmethod
    def _digest_credential_text(value: str, *, field: str, allow_empty: bool) -> str:
        value = str(value)
        if not value and not allow_empty:
            raise WPETransportError(f"Digest {field} is empty")
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise WPETransportError(f"Digest {field} must be printable ASCII")
        if len(value.encode("ascii", errors="strict")) > MAX_AUTH_CREDENTIAL_BYTES:
            raise WPETransportError(f"Digest {field} exceeds trusted bound")
        if field == "username" and ":" in value:
            raise WPETransportError("Digest username may not contain colon")
        return value

    @staticmethod
    def _digest_quote(value: str) -> str:
        value = str(value)
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise WPETransportError("Digest challenge value is not printable ASCII")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _digest_authorization(
        self,
        challenge: WPEDigestChallenge,
        credential: WPEDigestCredential,
    ) -> str:
        if not isinstance(challenge, WPEDigestChallenge):
            raise WPETransportError("invalid Digest challenge object")
        if not isinstance(credential, WPEDigestCredential):
            raise WPETransportError("invalid Digest credential object")
        username = self._digest_credential_text(
            credential.username, field="username", allow_empty=False
        )
        password = self._digest_credential_text(
            credential.password, field="password", allow_empty=True
        )
        _parsed, _scheme, _port, target = self._parts(challenge.url)
        try:
            username_b = username.encode("ascii", errors="strict")
            realm_b = challenge.realm.encode("ascii", errors="strict")
            password_b = password.encode("ascii", errors="strict")
            nonce_b = challenge.nonce.encode("ascii", errors="strict")
            target_b = target.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise WPETransportError("Stage 5K Digest subset requires ASCII fields") from exc
        cnonce = secrets.token_hex(16)
        nc = "00000001"
        qop = "auth"

        def h(data: bytes) -> str:
            return hashlib.sha256(data).hexdigest()

        ha1 = h(username_b + b":" + realm_b + b":" + password_b)
        ha2 = h(b"GET:" + target_b)
        response = h(
            ha1.encode("ascii") + b":" + nonce_b + b":" + nc.encode("ascii")
            + b":" + cnonce.encode("ascii") + b":" + qop.encode("ascii")
            + b":" + ha2.encode("ascii")
        )
        fields = [
            f"username={self._digest_quote(username)}",
            f"realm={self._digest_quote(challenge.realm)}",
            f"nonce={self._digest_quote(challenge.nonce)}",
            f"uri={self._digest_quote(target)}",
            "algorithm=SHA-256",
            f"response={self._digest_quote(response)}",
            "qop=auth",
            f"nc={nc}",
            f"cnonce={self._digest_quote(cnonce)}",
        ]
        if challenge.opaque:
            fields.append(f"opaque={self._digest_quote(challenge.opaque)}")
        header = "Digest " + ", ".join(fields)
        if len(header.encode("ascii", errors="strict")) > MAX_HEADER_BYTES:
            raise WPETransportError("trusted Digest Authorization exceeds header bound")
        return header

    def fetch_top_level(self, url: str) -> WPEFetchedDocument:
        """Trusted top-level GET with Basic authority plus Stage 5K Digest.

        Basic behavior from Stages 5G-5J is retained exactly in precedence:
        preemptive/challenge-only provisioned Basic entries first, then one
        unprovisioned Basic resolver path. Stage 5K is considered only when
        there is no usable Basic challenge/credential path and the 401 carries
        exactly one supported Digest SHA-256/qop=auth challenge. Digest secrets
        are never stored; one computed Authorization header exists only for one
        same-URL trusted retry.
        """
        challenge_only = self.authorization_store.challenge_only(url)
        had_authorization = bool(self.authorization_store.authorization_header(url))
        first = self.fetch_once(
            url,
            method="GET",
            send_session_cookies=True,
            store_session_cookies=True,
            cookie_site_url=url,
            top_level_navigation=True,
            send_authorization=not challenge_only,
            offer_download=True,
        )
        if first.status != 401:
            return first

        if challenge_only and self._has_basic_challenge(first.headers):
            return self.fetch_once(
                url,
                method="GET",
                send_session_cookies=True,
                store_session_cookies=True,
                cookie_site_url=url,
                top_level_navigation=True,
                send_authorization=True,
            )

        if had_authorization:
            return first

        basic_challenge = self._basic_challenge(url, first.headers)
        if basic_challenge is not None:
            if self.basic_credential_resolver is None:
                return first
            try:
                credential = self.basic_credential_resolver.resolve_basic(basic_challenge)
            except Exception as exc:
                raise WPETransportError("trusted Basic credential resolver failed") from exc
            if credential is None:
                return first
            if not isinstance(credential, WPEBasicCredential):
                raise WPETransportError("trusted Basic credential resolver returned invalid value")

            self.authorization_store.set_basic(
                url,
                credential.username,
                credential.password,
                challenge_only=True,
            )
            try:
                second = self.fetch_once(
                    url,
                    method="GET",
                    send_session_cookies=True,
                    store_session_cookies=True,
                    cookie_site_url=url,
                    top_level_navigation=True,
                    send_authorization=True,
                )
            except WPERedirectRequired:
                raise
            except Exception:
                self.authorization_store.clear(url)
                raise
            if second.status == 401:
                self.authorization_store.clear(url)
            return second

        digest_challenge = self._digest_challenge(url, first.headers)
        if digest_challenge is None or self.digest_credential_resolver is None:
            return first
        try:
            digest_credential = self.digest_credential_resolver.resolve_digest(digest_challenge)
        except Exception as exc:
            raise WPETransportError("trusted Digest credential resolver failed") from exc
        if digest_credential is None:
            return first
        if not isinstance(digest_credential, WPEDigestCredential):
            raise WPETransportError("trusted Digest credential resolver returned invalid value")
        digest_header = self._digest_authorization(digest_challenge, digest_credential)
        return self.fetch_once(
            url,
            method="GET",
            send_session_cookies=True,
            store_session_cookies=True,
            cookie_site_url=url,
            top_level_navigation=True,
            _trusted_authorization_header=digest_header,
        )


def validate_preflight_request(headers, initiator_url):
    """Bound preflight metadata to the current trusted document."""
    fields = {str(k).casefold(): str(v).strip() for k, v in headers}
    origin = fields.get("origin", "")
    expected = WPEAllowedDataTransport.trusted_origin_header(initiator_url)
    if origin not in {expected, "null"}:
        raise WPETransportError("preflight Origin does not match document authority")
    if fields.get("access-control-request-method", "") not in {"GET", "POST"}:
        raise WPETransportError("preflight method is not supported")
    tokens = [v.strip().casefold() for v in fields.get("access-control-request-headers", "").split(",") if v.strip()]
    if len(tokens) > MAX_HEADER_COUNT or any(
            not _application_header_name(name) and name not in _REQUEST_HEADER_ALLOWLIST
            or name in {"origin", "access-control-request-method", "access-control-request-headers"}
            for name in tokens):
        raise WPETransportError("preflight headers exceed trusted authority")
    return origin, tokens


def _cors_safelisted_value(name, value):
    if len(value.encode("utf-8")) > 128:
        return False
    if name in {"accept-language", "content-language"}:
        return all(ch.isascii() and (ch.isalnum() or ch in " *,-.;=") for ch in value)
    return all(ord(ch) >= 0x20 and ord(ch) != 0x7f
               and ch not in '"():<>?@[\\]{}' for ch in value)


def preflight_resource_request(transport, url, initiator_url, method, headers, *, credentialed):
    """Authorize non-simple cross-origin traffic without credentials or retries."""
    fields = {str(k).casefold(): str(v).strip() for k, v in headers}
    unsafe = []
    for name, value in fields.items():
        if name in {"origin", "referer", "user-agent"} or name.startswith("sec-fetch-") or name.startswith("sec-bojangles-"):
            continue
        if name in {"accept", "accept-language", "content-language"} and _cors_safelisted_value(name, value):
            continue
        if name == "content-type" and _cors_safelisted_value(name, value) and value.split(";", 1)[0].strip().casefold() in {
                "application/x-www-form-urlencoded", "multipart/form-data", "text/plain"}:
            continue
        unsafe.append(name)
    if not unsafe:
        return
    origin = fields.get("origin") or transport.trusted_origin_header(initiator_url)
    request_headers = (("Origin", origin), ("Access-Control-Request-Method", method),
                       ("Access-Control-Request-Headers", ", ".join(sorted(unsafe))))
    validate_preflight_request(request_headers, initiator_url)
    try:
        response = transport.fetch_once(
            url, method="OPTIONS", request_headers=request_headers,
            _cors_preflight=True, send_session_cookies=False,
            store_session_cookies=False, send_authorization=False)
    except WPERedirectRequired as error:
        raise WPETransportError("CORS preflight redirect is not permitted") from error
    if not 200 <= response.status < 300:
        raise WPETransportError("CORS preflight returned unsuccessful status")
    returned = {}
    for name, value in response.headers:
        key = str(name).casefold()
        if not key.startswith("access-control-allow-"):
            continue
        if key in returned:
            raise WPETransportError("ambiguous CORS preflight response headers")
        returned[key] = str(value).strip()
    allowed = returned.get("access-control-allow-origin", "")
    if allowed != origin and not (allowed == "*" and not credentialed):
        raise WPETransportError("CORS preflight did not allow document Origin")
    if credentialed and returned.get("access-control-allow-credentials") != "true":
        raise WPETransportError("CORS preflight did not allow credentials")
    methods = {v.strip() for v in returned.get("access-control-allow-methods", "").split(",")}
    if method not in methods and not ("*" in methods and not credentialed):
        raise WPETransportError("CORS preflight did not allow request method")
    allowed_headers = {v.strip().casefold() for v in returned.get("access-control-allow-headers", "").split(",")}
    if "authorization" in unsafe and "authorization" not in allowed_headers:
        raise WPETransportError("CORS preflight did not explicitly allow Authorization")
    if not set(unsafe) <= allowed_headers and not ("*" in allowed_headers and not credentialed):
        raise WPETransportError("CORS preflight did not allow request headers")


def classify_options_request(url, initiator_url, headers):
    """Separate REST capability requests from browser-generated CORS preflight."""
    fields = {str(k).casefold(): str(v).strip() for k, v in headers}
    if "access-control-request-method" in fields:
        validate_preflight_request(headers, initiator_url)
        return True
    if ("access-control-request-headers" in fields or not initiator_url
            or WPEAllowedDataTransport.trusted_origin_header(url)
            != WPEAllowedDataTransport.trusted_origin_header(initiator_url)):
        raise WPETransportError("ordinary OPTIONS requires same-origin document authority")
    return False


def normalize_request_body(body):
    """Keep validated read-only descriptor mappings streamed, never copied."""
    if isinstance(body, mmap.mmap):
        if not memoryview(body).readonly:
            raise WPETransportError("request body mapping must be immutable")
        return body
    return b"" if body is None else bytes(body)
