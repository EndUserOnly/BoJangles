"""Browser-compatible trusted HTTP/HTTPS transport.

Network authority remains on the trusted BoJangles side.

WPE receives no origin socket, DNS authority, TLS authority, cookie database,
redirect-following authority, or unrestricted network path.  This transport
changes only the trusted client's TLS/HTTP fingerprint used after the existing
broker has authorized a request.
"""
from __future__ import annotations

from email.message import Message
from urllib.parse import urljoin, urlsplit

from curl_cffi import Curl, CurlError, CurlHttpVersion, CurlOpt, requests
from curl_cffi._wrapper import ffi, lib
from curl_cffi.curl import CURL_READFUNC_ABORT

import mmap
from .upload_body import SelectedUploadBody
import io
import time
from .wpe_transport import classify_options_request, normalize_request_body
from .browser_cookies import BrowserSessionCookieJar
from bojangles.security.privacy import BROWSER_USER_AGENT

from .wpe_transport import (
    MAX_HEADER_BYTES,
    WPEAllowedDataTransport,
    WPEFetchedDocument,
    WPERedirectRequired,
    WPEDownloadOffered,
    response_offers_download,
    WPEMediaOffered,
    WPETransportError,
)


class BrowserTransportError(WPETransportError):
    """Trusted transport failure with conservative HTTPS availability metadata."""

    def __init__(
        self,
        message: str,
        *,
        https_service_unavailable: bool = False,
    ) -> None:
        super().__init__(message)
        self.https_service_unavailable = bool(
            https_service_unavailable
        )


def _curl_could_not_connect(exc: CurlError) -> bool:
    """CURLE_COULDNT_CONNECT only.

    DNS, timeout and TLS/certificate failures do not authorize downgrade.
    """

    try:
        return int(getattr(exc, "code", -1)) == 7
    except (TypeError, ValueError):
        return False


def _curl_http2_stream_failed(exc: CurlError) -> bool:
    """CURLE_HTTP2_STREAM only; safe to retry once over HTTPS/HTTP1.1."""

    try:
        return int(getattr(exc, "code", -1)) == 92
    except (TypeError, ValueError):
        return False


def _header_pairs(headers) -> tuple[tuple[str, str], ...]:
    multi_items = getattr(headers, "multi_items", None)

    if callable(multi_items):
        return tuple(
            (str(name), str(value))
            for name, value in multi_items()
        )

    return tuple(
        (str(name), str(value))
        for name, value in headers.items()
    )


def _set_cookie_values(headers) -> tuple[str, ...]:
    get_list = getattr(headers, "get_list", None)

    if callable(get_list):
        values = get_list("set-cookie")
        return tuple(str(value) for value in values)

    value = headers.get("set-cookie")

    if value is None:
        return ()

    return (str(value),)


def _content_type(value: str) -> tuple[str, str]:
    message = Message()
    message["content-type"] = (
        value or "application/octet-stream"
    )

    return (
        message.get_content_type()
        or "application/octet-stream",
        message.get_content_charset() or "",
    )


class BrowserCompatibleTransport(WPEAllowedDataTransport):
    """Trusted transport using a browser-grade TLS/HTTP fingerprint."""

    impersonate = "chrome136"
    allow_first_party_cookies = True
    supports_upload_cancellation = True

    def __init__(self, **kwargs):
        if kwargs.get("session_cookies") is None:
            kwargs["session_cookies"] = BrowserSessionCookieJar()
        super().__init__(**kwargs)

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
        _cors_preflight: bool = False,
        _application_request: bool = False,
        _cancelled=None,
        offer_download: bool = False,
        offer_media: bool = False,
    ) -> WPEFetchedDocument:

        from bojangles.diagnostics import record

        parsed, scheme, _port, _target = self._parts(url)

        method = str(method).upper()

        if method not in {"GET", "POST", "OPTIONS"}:
            raise WPETransportError(
                "trusted browser transport permits GET/POST only"
            )

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
        if method in {"GET", "OPTIONS"} and body_bytes:
            raise WPETransportError(
                "GET request body is not permitted"
            )

        if not isinstance(body_bytes, SelectedUploadBody) and len(body_bytes) > self.max_request_body_bytes:
            raise WPETransportError(
                "WPE request body exceeded trusted byte budget"
            )

        from .wpe_transport import sanitize_application_headers
        if _application_request and (not _trusted_referer or _cors_preflight):
            raise WPETransportError("application headers require document resource authority")
        forwarded = (sanitize_application_headers(request_headers) if _application_request
                     else self.sanitize_request_headers(request_headers))

        # Keep response bytes semantically identical to the HTTP entity
        # delivered to WPE.  Browser TLS/HTTP fingerprinting is still supplied
        # by curl_cffi, but compressed transfer is not requested.
        # Keep response bytes semantically identical to the HTTP entity
        # delivered to WPE. Browser TLS/HTTP fingerprinting is supplied by
        # curl_cffi while the explicit identity remains WPE-native.
        headers: dict[str, str] = {
            "User-Agent": BROWSER_USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Encoding": "identity",
        }
        if top_level_navigation:
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"

        for name, value in forwarded:
            for existing in tuple(headers):
                if existing.casefold() == name.casefold():
                    del headers[existing]

            headers[name] = value

        if _trusted_referer:
            referer = self.trusted_referer_header(_trusted_referer, url)
            if referer:
                headers["Referer"] = referer

        if (
            method == "POST"
            and not any(
                name.casefold() == "content-type"
                for name in headers
            )
        ):
            headers["Content-Type"] = (
                "application/octet-stream"
            )

        cookie_header = ""
        if send_session_cookies:
            cookie_header = self.session_cookies.cookie_header(
                url,
                site_for_cookies=cookie_site_url,
                top_level_navigation=top_level_navigation,
                method=method,
            )

            if cookie_header:
                headers["Cookie"] = cookie_header
                record(
                    "cookie_sent",
                    url=url,
                    cookie_names=[
                        part.partition("=")[0].strip()[:128]
                        for part in cookie_header.split(";") if "=" in part
                    ],
                    top_level=bool(top_level_navigation),
                )

            # Browser pages commonly read a non-HttpOnly CSRF cookie and echo
            # it into an AJAX header. BoJangles keeps cookie state trusted-side,
            # so reproduce only that narrow same-origin reflection here.
            if method == "POST" and cookie_site_url:
                target = urlsplit(url)
                site = urlsplit(cookie_site_url)
                same_origin = (
                    target.scheme.casefold(),
                    (target.hostname or "").casefold(),
                    target.port or (443 if target.scheme.casefold() == "https" else 80),
                ) == (
                    site.scheme.casefold(),
                    (site.hostname or "").casefold(),
                    site.port or (443 if site.scheme.casefold() == "https" else 80),
                )
                csrf_names = ("X-CSRFToken", "X-XSRF-TOKEN")
                if not same_origin:
                    for csrf_name in csrf_names:
                        headers.pop(csrf_name, None)
                        headers.pop(csrf_name.casefold(), None)
                else:
                    csrf = self.session_cookies.script_cookie_value(
                        url, "csrftoken", site_for_cookies=cookie_site_url
                    )
                    xsrf = self.session_cookies.script_cookie_value(
                        url, "XSRF-TOKEN", site_for_cookies=cookie_site_url
                    )
                    if csrf:
                        headers["X-CSRFToken"] = csrf
                    if xsrf:
                        headers["X-XSRF-TOKEN"] = xsrf

        if send_authorization:
            authorization = (
                self.authorization_store
                .authorization_header(url)
            )

            if authorization:
                headers["Authorization"] = authorization

        if _trusted_authorization_header:
            if send_authorization:
                raise WPETransportError(
                    "conflicting trusted Authorization sources"
                )

            if scheme != "https":
                raise WPETransportError(
                    "trusted Digest Authorization requires HTTPS"
                )

            digest_header = str(
                _trusted_authorization_header
            )

            if not digest_header.startswith("Digest "):
                raise WPETransportError(
                    "trusted Authorization override is not Digest"
                )

            try:
                digest_bytes = digest_header.encode(
                    "ascii",
                    errors="strict",
                )
            except UnicodeEncodeError as exc:
                raise WPETransportError(
                    "trusted Digest Authorization must be ASCII"
                ) from exc

            if len(digest_bytes) > MAX_HEADER_BYTES:
                raise WPETransportError(
                    "trusted Digest Authorization exceeds header bound"
                )

            if any(
                ord(ch) < 0x20 or ord(ch) > 0x7E
                for ch in digest_header
            ):
                raise WPETransportError(
                    "trusted Digest Authorization contains unsafe bytes"
                )

            headers["Authorization"] = digest_header

        response = None
        upload_source = None
        if method == "POST" and (isinstance(body_bytes, SelectedUploadBody) or len(body_bytes) > 1024 * 1024):
            upload_source = body_bytes if isinstance(body_bytes, (mmap.mmap, SelectedUploadBody)) else io.BytesIO(body_bytes)
            headers["Content-Length"] = str(len(body_bytes))
        request_timeout = self.request_timeout(body_bytes)
        curl_options = {CurlOpt.TIMEOUT_MS: 0 if request_timeout is None else max(1, int(request_timeout * 1000))}
        if upload_source is not None:
            def read_upload(maximum):
                if _cancelled is not None and _cancelled.is_set():
                    return CURL_READFUNC_ABORT
                return upload_source.read(min(maximum, 65536))
            curl_options.update({
                CurlOpt.CONNECTTIMEOUT_MS: max(1, int(self.timeout * 1000)),
                CurlOpt.LOW_SPEED_LIMIT: 1024,
                CurlOpt.LOW_SPEED_TIME: max(1, int(self.timeout)),
                CurlOpt.READFUNCTION: read_upload,
            })
        progress_callback = None
        if upload_source is not None:
            activity = [time.monotonic(), 0, 0]
            def upload_progress(_context, _download_total, downloaded, _upload_total, uploaded):
                now = time.monotonic()
                if (downloaded, uploaded) != (activity[1], activity[2]):
                    activity[:] = [now, downloaded, uploaded]
                if _cancelled is not None and _cancelled.is_set():
                    return 1
                return int(now - activity[0] > self.timeout)
            progress_callback = ffi.callback(
                "int(void *, long long, long long, long long, long long)", upload_progress)
            curl_options[CurlOpt.NOPROGRESS] = 0
        request_kwargs = dict(
            headers=headers,
            **({"content": upload_source} if upload_source is not None
               else {"data": body_bytes if method == "POST" else None}),
            allow_redirects=False,
            timeout=request_timeout,
            impersonate=self.impersonate,
            default_headers=False,
            verify=True,
            stream=True,
            # Streaming otherwise substitutes a low-speed limit for a total
            # timeout. A trickling dead page must still finish within budget.
            curl_options=curl_options,
        )

        if upload_source is not None:
            upload_source.seek(0)
        try:
            try:
                record(
                    "http_attempt",
                    url=url,
                    method=method,
                    top_level=bool(top_level_navigation),
                    transport="browser-compatible",
                )
                if upload_source is not None:
                    curl = Curl()
                    if lib._curl_easy_setopt(curl._curl, CurlOpt.XFERINFOFUNCTION,
                                             ffi.cast("void *", progress_callback)):
                        curl.close()
                        raise WPETransportError("native upload progress callback unavailable")
                    with requests.Session(curl=curl, curl_options=curl_options, use_thread_local_curl=False) as client:
                        response = client.request(method, url,
                            **{k: v for k, v in request_kwargs.items() if k != "curl_options"})
                else:
                    response = requests.request(
                        method,
                        url,
                        **request_kwargs,
                    )
            except CurlError as exc:
                if not _curl_http2_stream_failed(exc):
                    raise
                record(
                    "http2_stream_recovery",
                    url=url,
                    curl_code=int(getattr(exc, "code", -1)),
                    retry_protocol="HTTP/1.1",
                )
                record(
                    "http_attempt",
                    url=url,
                    method=method,
                    top_level=bool(top_level_navigation),
                    transport="browser-compatible",
                    retry="http2-stream-recovery",
                )
                if upload_source is not None:
                    upload_source.seek(0)
                if upload_source is not None:
                    curl = Curl()
                    if lib._curl_easy_setopt(curl._curl, CurlOpt.XFERINFOFUNCTION,
                                             ffi.cast("void *", progress_callback)):
                        curl.close()
                        raise WPETransportError("native upload progress callback unavailable")
                    activity[:] = [time.monotonic(), 0, 0]
                    with requests.Session(curl=curl, curl_options=curl_options, use_thread_local_curl=False) as client:
                        response = client.request(method, url, http_version=CurlHttpVersion.V1_1,
                            **{k: v for k, v in request_kwargs.items() if k != "curl_options"})
                else:
                    response = requests.request(
                        method,
                        url,
                        http_version=CurlHttpVersion.V1_1,
                        **request_kwargs,
                    )

            status = int(response.status_code)

            accepted_cookie_headers: tuple[str, ...] = ()
            if store_session_cookies:
                accepted_cookie_headers = self.session_cookies.store_response(
                    url,
                    _set_cookie_values(response.headers),
                    site_for_cookies=(cookie_site_url or (url if top_level_navigation else "")),
                )

            location = response.headers.get(
                "location"
            )

            if (
                300 <= status < 400
                and location
            ):
                record(
                    "http_redirect",
                    url=url,
                    redirect=urljoin(url, str(location)),
                    status=status,
                )
                raise WPERedirectRequired(
                    urljoin(url, str(location)),
                    status,
                    self.sanitize_response_headers(_header_pairs(response.headers)),
                    accepted_cookie_headers=accepted_cookie_headers,
                )

            mime_type, encoding = _content_type(
                str(response.headers.get("content-type", ""))
            )
            if offer_download and method == "GET" and 200 <= status < 300:
                disposition = str(response.headers.get("content-disposition", ""))
                if response_offers_download(url, mime_type, disposition):
                    from bojangles.downloads import _suggested_name
                    record("transport_handoff", url=url, kind="download", status=status)
                    raise WPEDownloadOffered(url, _suggested_name(url, disposition, mime_type))
            if offer_media and method == "GET" and 200 <= status < 300:
                if mime_type.casefold().startswith(("audio/", "video/")):
                    record("transport_handoff", url=url, kind="media",
                           status=status, mime_type=mime_type)
                    raise WPEMediaOffered(url, mime_type)

            body_out = bytearray()
            budget = self.response_byte_budget(method, top_level_navigation)

            for chunk in response.iter_content(
                chunk_size=65536
            ):
                if not chunk:
                    continue

                if len(body_out) + len(chunk) > budget:
                    raise WPETransportError(
                        "renderer document exceeded "
                        "trusted byte budget"
                    )
                body_out.extend(chunk)

            sent_cookie_names = {
                part.partition("=")[0].strip().casefold()
                for part in cookie_header.split(";")
                if "=" in part
            }
            cf_ray = str(response.headers.get("cf-ray", "")).strip()
            server_header = str(response.headers.get("server", "")).casefold()
            cloudflare_refused = (
                top_level_navigation
                and method == "GET"
                and status == 403
                and "cf_clearance" in sent_cookie_names
                and (bool(cf_ray) or "cloudflare" in server_header)
            )
            if cloudflare_refused:
                record(
                    "cloudflare_verification_refused",
                    url=url,
                    status=status,
                )
                body_out = bytearray(
                    b"<!doctype html><html><head><meta charset='utf-8'>"
                    b"<title>Cloudflare verification refused</title>"
                    b"<style>body{font-family:sans-serif;max-width:760px;margin:4em auto;"
                    b"padding:0 1.5em;line-height:1.5}h1{font-size:1.5em}</style>"
                    b"</head><body><h1>Cloudflare verification refused</h1>"
                    b"<p>This site declined the completed browser verification. "
                    b"BoJangles stopped the verification loop.</p>"
                    b"<p>Use Back, Refresh, New Browser, or Exit from the BoJangles controls.</p>"
                    b"</body></html>"
                )
                mime_type = "text/html"
                encoding = "utf-8"
                accepted_cookie_headers = ()

            response_headers = list(
                self.sanitize_response_headers(
                    _header_pairs(
                        response.headers
                    )
                )
            )
            # WebKit receives only cookies already accepted by the trusted jar.
            # It is a browser-state mirror, never the network authority.
            for cookie_header in accepted_cookie_headers[:16]:
                response_headers.append(("Set-Cookie", cookie_header))
            response_headers = tuple(response_headers)

            record(
                "http_response",
                url=url,
                status=status,
                mime_type=mime_type,
                bytes=len(body_out),
            )
            return WPEFetchedDocument(
                url,
                status,
                mime_type,
                encoding,
                bytes(body_out),
                response_headers,
            )

        except (WPERedirectRequired, WPEDownloadOffered, WPEMediaOffered):
            raise

        except WPETransportError as exc:
            record(
                "transport_error",
                url=url,
                transport="browser-compatible",
                error_type=type(exc).__name__,
            )
            raise

        except CurlError as exc:
            unavailable = (
                scheme == "https"
                and _curl_could_not_connect(exc)
            )
            try:
                curl_code = int(getattr(exc, "code", -1))
            except (TypeError, ValueError):
                curl_code = -1
            record(
                "transport_error",
                url=url,
                transport="browser-compatible",
                curl_code=curl_code,
                tls=(curl_code in {35, 51, 53, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91}),
                https_service_unavailable=unavailable,
            )

            raise BrowserTransportError(
                "trusted browser HTTP/HTTPS "
                f"fetch failed: {exc}",
                https_service_unavailable=unavailable,
            ) from exc

        finally:
            if response is not None:
                response.close()
            progress_callback = None


__all__ = [
    "BrowserCompatibleTransport",
    "BrowserTransportError",
]
