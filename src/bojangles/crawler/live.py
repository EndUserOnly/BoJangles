"""Session-only direct spider/crawler for first-hand site search."""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from fnmatch import fnmatchcase
import gzip
from html import unescape
from html.parser import HTMLParser
from io import BytesIO
import ipaddress
from pathlib import PurePosixPath
import re
import socket
from threading import Lock
from time import monotonic, sleep
from urllib.parse import parse_qsl, urlencode, unquote, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser
from xml.etree import ElementTree

from .media import media_from_mime, media_from_url, media_summary, archive_media, reported_size, content_length

from .age import (
    AgeDecision,
    DateCandidate,
    Qualifier,
    decide_age,
    evaluate_html,
    extract_html_candidates,
)
from bojangles.renderer.wpe_transport import (
    WPEAllowedDataTransport,
    WPEFetchedDocument,
    WPERedirectRequired,
    WPETransportError,
)

UTC = timezone.utc
MAX_REDIRECTS = 5
CRAWLER_USER_AGENT = "BoJangles-WPE/1"
_LOCAL_HOST_SUFFIXES = (".localhost", ".local", ".localdomain", ".lan", ".home", ".internal")
MAX_SITEMAP_DOCUMENTS = 16
MAX_FEED_DOCUMENTS = 8
MAX_STRUCTURED_ORIGINS = 6
MAX_STRUCTURED_XML_BYTES = 16 * 1024 * 1024
MAX_PDF_METADATA_BYTES = 16 * 1024 * 1024
MAX_DNS_ADDRESSES = 16
MAX_CONCURRENT_FETCHES = 4
_DISCOVERY_MULTIPLIER = 4
_TRACKING_QUERY_KEYS = frozenset({"fbclid", "gclid", "dclid", "igshid", "mc_cid", "mc_eid", "msclkid"})
_MEDIA_SUFFIXES = frozenset({
    ".aac", ".aiff", ".ape", ".avi", ".avif", ".bmp", ".flac", ".gif", ".heic",
    ".heif", ".ico", ".jpeg", ".jpg", ".m2ts", ".m3u8", ".m4a", ".m4v", ".mkv",
    ".mov", ".mp3", ".mp4", ".mpd", ".mpeg", ".mpg", ".oga", ".ogg", ".ogv",
    ".opus", ".png", ".svg", ".tif", ".tiff", ".ts", ".wav", ".webm", ".webp",
    ".wma", ".wmv",
})
_MEDIA_MIME_PREFIXES = ("audio/", "video/", "image/")
_MEDIA_MIME_TYPES = frozenset({
    "application/dash+xml",
    "application/vnd.apple.mpegurl",
    "application/x-mpegurl",
})
_NON_DOCUMENT_SUFFIXES = frozenset({
    ".7z", ".css", ".csv", ".doc", ".docx", ".eot", ".exe", ".gz", ".js",
    ".json", ".ppt", ".pptx", ".rar", ".tar", ".tgz", ".ttf", ".woff", ".woff2",
    ".xls", ".xlsx", ".xml", ".zip",
})
_JUNK_PATH_SEGMENTS = frozenset({
    "archive", "archives", "author", "authors", "cart", "categories", "category",
    "checkout", "comments", "feed", "login", "search", "signin", "signup", "tag",
    "tags", "wp-admin", "wp-json",
})

_PDF_INFO_REF_RE = re.compile(rb"/Info\s+(\d+)\s+(\d+)\s+R\b")
_PDF_OBJECT_RE_TEMPLATE = rb"\b%s\s+%s\s+obj\b(?P<body>.*?)\bendobj\b"
_PDF_INFO_ENTRY_RE = re.compile(
    rb"/(CreationDate|ModDate)\s+(\((?:\\.|[^)])*\)|<[0-9A-Fa-f\s]+>)"
)
_PDF_DATE_RE = re.compile(
    r"^D:(?P<year>\d{4})(?P<month>\d{2})?(?P<day>\d{2})?"
    r"(?P<hour>\d{2})?(?P<minute>\d{2})?(?P<second>\d{2})?"
    r"(?P<zone>Z|[+-]\d{2}'?\d{2}'?)?$",
    re.IGNORECASE,
)
_XMP_PACKET_RE = re.compile(
    rb"<(?:[A-Za-z_][\w.-]*:)?xmpmeta\b[^>]*>.*?"
    rb"</(?:[A-Za-z_][\w.-]*:)?xmpmeta\s*>",
    re.IGNORECASE | re.DOTALL,
)
_XMP_DATE_TAG_RE = re.compile(
    rb"<(?P<qname>(?P<prefix>[A-Za-z_][\w.-]*):(?P<local>"
    rb"CreateDate|ModifyDate|MetadataDate|CreationDate|ModDate|DateCreated|date))"
    rb"\b[^>]*>(?P<value>.*?)</(?P=qname)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_XMP_DATE_ATTRIBUTE_RE = re.compile(
    rb"(?P<qname>(?P<prefix>xmp|pdf|photoshop|dc):(?P<local>"
    rb"CreateDate|ModifyDate|MetadataDate|CreationDate|ModDate|DateCreated|date))"
    rb"\s*=\s*([\"'])(?P<value>.*?)(?:\4)",
    re.IGNORECASE | re.DOTALL,
)
_XMP_TAG_STRIP_RE = re.compile(rb"<[^>]+>")


@dataclass(frozen=True, slots=True)
class LiveCrawlOptions:
    site: str = ""
    domain: str = ""
    path: str = ""
    seeds: tuple[str, ...] = ()
    depth: int = 2
    max_pages: int = 30
    recent_days: int | None = None
    include_pdf: bool = False
    exact: bool = False
    contains: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    same_site: bool = False
    outbound: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.depth <= 8:
            raise ValueError("depth must be in 0..8")
        if not 1 <= self.max_pages <= 200:
            raise ValueError("max-pages must be in 1..200")
        if self.recent_days is not None and self.recent_days < 0:
            raise ValueError("recent must be non-negative")
        if self.same_site and self.outbound:
            raise ValueError("--same-site and --outbound are mutually exclusive")


@dataclass(frozen=True, slots=True)
class LiveResult:
    url: str
    title: str
    content_date: str
    age_days: int | None
    evidence: str
    snippet: str
    source: str
    is_pdf: bool = False
    media: str = "Unknown"
    size_bytes: int | None = None
    size_note: str = ""


@dataclass(frozen=True, slots=True)
class LiveCrawlReport:
    results: tuple[LiveResult, ...]
    fetched: int
    rejected_age: int
    rejected_filter: int
    rejected_robots: int = 0
    rejected_dns: int = 0
    notice: str = ""


@dataclass(slots=True)
class _RobotsPolicy:
    parser: RobotFileParser | None = None
    allow_all: bool = False
    disallow_all: bool = False
    crawl_delay: float = 0.0
    sitemaps: tuple[str, ...] = ()

    def allows(self, url: str) -> bool:
        if self.disallow_all:
            return False
        if self.allow_all or self.parser is None:
            return True
        return self.parser.can_fetch(CRAWLER_USER_AGENT, url)


class _RobotsDenied(WPETransportError):
    pass


class _DNSRejected(WPETransportError):
    pass


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.media_links: list[str] = []
        self.feeds: list[str] = []
        self._in_title = False
        self._hidden = 0
        self.media_types: set[str] = set()
        self.media_unknown = False

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.casefold()
        amap = {str(k).casefold(): "" if v is None else str(v) for k, v in attrs}
        if not self._hidden:
            if tag in {'video','audio','img','picture'}:
                self.media_types.add({'video':'Video','audio':'Audio','img':'Images','picture':'Images'}[tag])
            if tag in {'source','embed','object','iframe'}:
                kind = media_from_mime(amap.get('type','')) or media_from_url(amap.get('src',amap.get('data','')))
                if kind:self.media_types.add(kind)
                elif tag in {'embed','object','iframe'}:self.media_unknown = True
            if tag == 'script':self.media_unknown = True
        if tag == "title":
            self._in_title = True
        if tag in {"script", "style", "noscript", "template"}:
            self._hidden += 1
        if tag == "a" and amap.get("href"):
            self.links.append(amap["href"])
        if tag in {"audio", "video", "source", "img", "embed", "iframe"} and amap.get("src"):
            self.media_links.append(amap["src"])
        if tag == "object" and amap.get("data"):
            self.media_links.append(amap["data"])
        if tag in {"img", "source"} and amap.get("srcset"):
            for item in amap["srcset"].split(","):
                candidate = item.strip().split(None, 1)[0]
                if candidate:
                    self.media_links.append(candidate)
        if tag == "link" and amap.get("href"):
            rel = {item.casefold() for item in amap.get("rel", "").split()}
            mime = amap.get("type", "").split(";", 1)[0].strip().casefold()
            if "alternate" in rel and mime in {"application/rss+xml", "application/atom+xml"}:
                self.feeds.append(amap["href"])

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "title":
            self._in_title = False
        if tag in {"script", "style", "noscript", "template"} and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if not self._hidden:
            self.text_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(" ".join(self.title_parts).split())[:240]

    @property
    def text(self) -> str:
        return " ".join(" ".join(self.text_parts).split())

    @property
    def snippet(self) -> str:
        return self.text[:420]


def _canonical_http_url(value: str, *, base: str = "") -> str:
    candidate = urljoin(base, str(value).strip())
    parsed = urlsplit(candidate)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("live crawler requires an HTTP/HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("userinfo is not accepted")
    host = parsed.hostname.casefold().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(_LOCAL_HOST_SUFFIXES):
        raise ValueError("local hostnames are not crawl targets")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("non-public IP addresses are not crawl targets")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))


def _header_map(document: WPEFetchedDocument) -> dict[str, str]:
    return {str(name): str(value) for name, value in document.headers}


def _decode(document: WPEFetchedDocument) -> str:
    encoding = document.encoding or "utf-8"
    try:
        return document.body.decode(encoding, errors="replace")
    except LookupError:
        return document.body.decode("utf-8", errors="replace")


def _is_pdf(document: WPEFetchedDocument) -> bool:
    mime = document.mime_type.split(";", 1)[0].strip().casefold()
    return mime == "application/pdf" or document.body.startswith(b"%PDF-") or urlsplit(document.url).path.casefold().endswith(".pdf")


def _bounded_pdf_payload(payload: bytes) -> bytes:
    if len(payload) <= MAX_PDF_METADATA_BYTES:
        return payload
    half = MAX_PDF_METADATA_BYTES // 2
    return payload[:half] + b"\n" + payload[-half:]


def _decode_pdf_string(token: bytes) -> str:
    if token.startswith(b"<"):
        try:
            return bytes.fromhex(re.sub(rb"\s+", b"", token[1:-1]).decode("ascii")).decode(
                "latin-1"
            )
        except (ValueError, UnicodeError):
            return ""
    value = token[1:-1] if token.startswith(b"(") and token.endswith(b")") else token
    decoded = bytearray()
    index = 0
    escapes = {
        ord("n"): b"\n",
        ord("r"): b"\r",
        ord("t"): b"\t",
        ord("b"): b"\b",
        ord("f"): b"\f",
    }
    while index < len(value):
        byte = value[index]
        index += 1
        if byte != ord("\\") or index >= len(value):
            decoded.append(byte)
            continue
        escaped = value[index]
        index += 1
        replacement = escapes.get(escaped)
        if replacement is not None:
            decoded.extend(replacement)
            continue
        if escaped in b"\\()":
            decoded.append(escaped)
            continue
        if escaped in b"\r\n":
            if escaped == ord("\r") and index < len(value) and value[index] == ord("\n"):
                index += 1
            continue
        if 48 <= escaped <= 55:
            digits = bytes((escaped,))
            while len(digits) < 3 and index < len(value) and 48 <= value[index] <= 55:
                digits += bytes((value[index],))
                index += 1
            decoded.append(int(digits, 8))
            continue
        decoded.append(escaped)
    return bytes(decoded).decode("latin-1", errors="replace")


def _pdf_info_values(payload: bytes) -> tuple[tuple[str, str], ...]:
    bounded = _bounded_pdf_payload(payload)
    references = list(_PDF_INFO_REF_RE.finditer(bounded))
    bodies: list[bytes] = []
    if references:
        reference = references[-1]
        object_number = reference.group(1)
        generation = reference.group(2)
        pattern = re.compile(
            _PDF_OBJECT_RE_TEMPLATE % (re.escape(object_number), re.escape(generation)),
            re.DOTALL,
        )
        match = pattern.search(bounded)
        if match:
            bodies.append(match.group("body"))
    else:
        bodies.append(bounded)
    values: list[tuple[str, str]] = []
    for body in bodies:
        for match in _PDF_INFO_ENTRY_RE.finditer(body):
            key = match.group(1).decode("ascii", errors="ignore")
            raw = _decode_pdf_string(match.group(2)).strip()
            if raw:
                values.append((key, raw))
    return tuple(values)


def _normalise_pdf_date(raw: str) -> str | None:
    value = unescape(str(raw or "")).strip()
    match = _PDF_DATE_RE.fullmatch(value)
    if match is None:
        return None
    groups = match.groupdict()
    if not groups["month"] or not groups["day"]:
        return None
    year = int(groups["year"])
    month = int(groups["month"])
    day = int(groups["day"])
    hour = groups["hour"]
    minute = groups["minute"]
    second = groups["second"]
    if not any((hour, minute, second)):
        try:
            datetime(year, month, day)
        except ValueError:
            return None
        return f"{year:04d}-{month:02d}-{day:02d}"
    if not all((hour, minute, second)):
        return None
    zone = groups["zone"]
    if not zone:
        return None
    try:
        naive = datetime(year, month, day, int(hour), int(minute), int(second))
    except ValueError:
        return None
    if zone.casefold() == "z":
        return naive.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
    sign = 1 if zone[0] == "+" else -1
    offset_digits = zone[1:].replace("'", "")
    offset_hours = int(offset_digits[:2])
    offset_minutes = int(offset_digits[2:])
    if offset_hours > 23 or offset_minutes > 59:
        return None
    offset = timezone(sign * timedelta(hours=offset_hours, minutes=offset_minutes))
    return naive.replace(tzinfo=offset).astimezone(UTC).isoformat().replace("+00:00", "Z")


def _normalise_xmp_date(raw: str) -> str | None:
    value = unescape(str(raw or "")).strip()
    if value.startswith("D:"):
        return _normalise_pdf_date(value)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            return None
        return value
    iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _xmp_packets(payload: bytes) -> tuple[bytes, ...]:
    bounded = _bounded_pdf_payload(payload)
    packets = tuple(match.group(0) for match in _XMP_PACKET_RE.finditer(bounded))
    if packets:
        return packets
    if b"<rdf:RDF" in bounded or b"<rdf:rdf" in bounded:
        return (bounded,)
    return ()


def _xmp_values(raw: bytes) -> tuple[str, ...]:
    clean = _XMP_TAG_STRIP_RE.sub(b" ", raw)
    values = [part.decode("utf-8", errors="replace").strip() for part in clean.split()]
    return tuple(value for value in values if value)


def extract_pdf_date_candidates(pdf_bytes: bytes) -> tuple[DateCandidate, ...]:
    """Extract only source-native PDF date metadata as STRUCTURED AGE evidence.

    PDF Info creation/modification fields and XMP date fields are normalized to
    the existing AGE parser's date forms. No filename, URL, filesystem time, or
    crawl time is used.
    """
    candidates: list[DateCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add(raw: str, source: str, normalizer) -> None:
        normalized = normalizer(raw)
        if normalized is None:
            return
        key = (normalized, source)
        if key in seen:
            return
        seen.add(key)
        candidates.append(DateCandidate(normalized, Qualifier.STRUCTURED, source))

    for field, raw in _pdf_info_values(pdf_bytes):
        add(raw, f"PDF Info /{field}", _normalise_pdf_date)

    for packet in _xmp_packets(pdf_bytes):
        for match in _XMP_DATE_TAG_RE.finditer(packet):
            qname = match.group("qname").decode("ascii", errors="ignore")
            for value in _xmp_values(match.group("value")):
                add(value, f"PDF XMP {qname}", _normalise_xmp_date)
        for match in _XMP_DATE_ATTRIBUTE_RE.finditer(packet):
            qname = match.group("qname").decode("ascii", errors="ignore")
            for value in _xmp_values(match.group("value")):
                add(value, f"PDF XMP {qname}", _normalise_xmp_date)
    return tuple(candidates)


def _decision_allowed(decision: AgeDecision, now: datetime, recent_days: int | None) -> bool:
    if recent_days is None:
        return True
    if not decision.accepted or decision.selected is None:
        return False
    return now - decision.selected.comparison_instant() <= timedelta(days=recent_days)


def _result_date(decision: AgeDecision, now: datetime) -> tuple[str, int | None, str, datetime]:
    selected = decision.selected if decision.accepted else None
    if selected is None:
        return "", None, "Date unavailable", datetime.min.replace(tzinfo=UTC)
    instant = selected.comparison_instant()
    return (selected.iso_content_date(), max(0, int((now - instant).total_seconds()) // 86400),
            f"{selected.qualifier.value} · {selected.source}", instant)


def _clean_candidate_url(value: str, *, base: str = "") -> str:
    url = _canonical_http_url(value, base=base)
    parsed = urlsplit(url)
    kept = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lower = name.casefold()
        if lower.startswith("utm_") or lower in _TRACKING_QUERY_KEYS:
            continue
        kept.append((name, value))
    query = urlencode(kept, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _media_suffix(url: str) -> str:
    path = unquote(urlsplit(url).path or "/")
    return PurePosixPath(path).suffix.casefold()


def _is_media_url(url: str) -> bool:
    return _media_suffix(url) in _MEDIA_SUFFIXES


def _is_media_document(document: WPEFetchedDocument) -> bool:
    mime = document.mime_type.split(";", 1)[0].strip().casefold()
    if mime.startswith(_MEDIA_MIME_PREFIXES) or mime in _MEDIA_MIME_TYPES:
        return True
    if mime in {"text/html", "application/xhtml+xml"}:
        return False
    return _is_media_url(document.url)


def _query_matches(query: str, text: str, url: str = "") -> bool:
    terms = [item.casefold() for item in str(query).split() if item.strip()]
    if not terms:
        return True
    decoded_url = unquote(str(url)).casefold()
    path = unquote(urlsplit(str(url)).path or "").casefold() if url else ""
    basename = PurePosixPath(path).name
    haystack = f"{text} {decoded_url}".casefold()
    words = tuple(re.findall(r"[^\s<>\"']+", haystack))
    glob_terms = [term for term in terms if any(ch in term for ch in "*?[]")]
    plain_terms = [term for term in terms if term not in glob_terms]

    for term in plain_terms:
        if term not in haystack:
            return False

    if glob_terms:
        candidates = (decoded_url, path, basename, *words)
        if not any(fnmatchcase(candidate, pattern) for pattern in glob_terms for candidate in candidates):
            return False
    return True


def _looks_like_content_candidate(url: str, *, include_pdf: bool) -> bool:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix == ".pdf":
        return include_pdf
    if suffix in _MEDIA_SUFFIXES:
        return True
    if suffix in _NON_DOCUMENT_SUFFIXES:
        return False
    segments = {segment.casefold() for segment in path.split("/") if segment}
    if segments & _JUNK_PATH_SEGMENTS:
        return False
    query = {name.casefold() for name, _value in parse_qsl(parsed.query, keep_blank_values=True)}
    if query & {"s", "search", "query"}:
        return False
    return True


def _date_hint_allowed(value: str, now: datetime, recent_days: int | None) -> bool:
    if recent_days is None:
        return True
    raw = str(value or "").strip()
    if not raw:
        return True
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    if parsed > now:
        return False
    if recent_days is not None and now - parsed > timedelta(days=recent_days):
        return False
    return True


def _xml_name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1].casefold()


def _structured_xml_payload(document: WPEFetchedDocument) -> bytes:
    payload = document.body
    path = urlsplit(document.url).path.casefold()
    mime = document.mime_type.split(";", 1)[0].strip().casefold()
    encoding = ""
    for name, value in document.headers:
        if str(name).casefold() == "content-encoding":
            encoding = str(value).casefold().strip()
            break
    compressed = path.endswith(".gz") or mime in {"application/gzip", "application/x-gzip"} or encoding == "gzip"
    if compressed:
        try:
            with gzip.GzipFile(fileobj=BytesIO(payload)) as stream:
                payload = stream.read(MAX_STRUCTURED_XML_BYTES + 1)
        except (OSError, EOFError):
            return b""
    if len(payload) > MAX_STRUCTURED_XML_BYTES:
        return b""
    return payload


def _scope_seed(value: str) -> str:
    """Turn an explicit site/domain control into a crawl root."""
    target = str(value or "").strip()
    if not target:
        raise ValueError("empty spider seed")
    if "://" not in target:
        target = "https://" + target
    return _clean_candidate_url(target)


class LiveWebCrawler:
    """Foreground-only crawler. Frontier, pages, and results exist only in memory."""

    def __init__(
        self,
        transport: WPEAllowedDataTransport | None = None,
        *,
        now: datetime | None = None,
        resolver=None,
        progress=None,
    ):
        self.transport = transport or WPEAllowedDataTransport(timeout=12.0)
        self.progress = progress or (lambda message: None)
        self.now = (now or datetime.now(UTC)).astimezone(UTC)
        self._resolver = resolver or getattr(self.transport, "resolve_host", socket.getaddrinfo)
        self._robots: dict[str, _RobotsPolicy] = {}
        self._robots_guard = Lock()
        self._robots_origin_locks: dict[str, Lock] = {}
        self._schedule_guard = Lock()
        self._next_request: dict[str, float] = {}
        self._sitemap_cache: dict[tuple[str, LiveCrawlOptions], tuple[str, ...]] = {}
        self._feed_seen: set[str] = set()

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlsplit(_canonical_http_url(url))
        host = parsed.hostname or ""
        netloc = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, "", "", ""))

    def _resolve_public_addresses(self, url: str) -> tuple[str, ...]:
        parsed = urlsplit(_canonical_http_url(url))
        host = parsed.hostname or ""
        try:
            numeric = ipaddress.ip_address(host)
        except ValueError:
            numeric = None
        if numeric is not None:
            if not numeric.is_global:
                raise _DNSRejected(f"DNS target is not globally routable: {host}")
            return (str(numeric),)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            answers = self._resolver(host, port, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror) as exc:
            raise _DNSRejected(f"DNS resolution failed for {host}") from exc
        approved: list[str] = []
        for answer in answers:
            try:
                family, _socktype, _proto, _canonname, sockaddr = answer
                raw_address = str(sockaddr[0]).split("%", 1)[0]
            except (IndexError, TypeError, ValueError):
                raise _DNSRejected(f"DNS returned malformed address data for {host}")
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise _DNSRejected(f"DNS returned invalid address for {host}") from exc
            if not address.is_global:
                raise _DNSRejected(
                    f"DNS returned non-public address {address} for {host}"
                )
            canonical = str(address)
            if canonical not in approved:
                approved.append(canonical)
                if len(approved) > MAX_DNS_ADDRESSES:
                    raise _DNSRejected(f"DNS address set exceeds trusted bound for {host}")
        if not approved:
            raise _DNSRejected(f"DNS returned no usable public addresses for {host}")
        return tuple(approved)

    def _fetch(self, url: str) -> WPEFetchedDocument:
        """Fetch trusted data without robots gating; used for discovery and robots.txt."""
        target = _canonical_http_url(url)
        for _ in range(MAX_REDIRECTS + 1):
            approved = self._resolve_public_addresses(target)
            try:
                return self.transport.fetch_once(target, _resolved_addresses=approved)
            except WPERedirectRequired as redirect:
                target = _canonical_http_url(redirect.target, base=target)
        raise WPETransportError("live crawler redirect limit exceeded")

    def _robots_policy(self, url: str) -> _RobotsPolicy:
        origin = self._origin(url)
        with self._robots_guard:
            cached = self._robots.get(origin)
            if cached is not None:
                return cached
            origin_lock = self._robots_origin_locks.setdefault(origin, Lock())
        with origin_lock:
            with self._robots_guard:
                cached = self._robots.get(origin)
                if cached is not None:
                    return cached
            robots_url = origin + "/robots.txt"
            try:
                document = self._fetch(robots_url)
            except _DNSRejected:
                raise
            except (ValueError, WPETransportError):
                policy = _RobotsPolicy(disallow_all=True)
            else:
                if document.status in {404, 410}:
                    policy = _RobotsPolicy(allow_all=True)
                elif document.status in {401, 403} or document.status >= 500:
                    policy = _RobotsPolicy(disallow_all=True)
                elif 200 <= document.status < 300:
                    lines = _decode(document).splitlines()
                    parser = RobotFileParser()
                    parser.set_url(robots_url)
                    parser.parse(lines)
                    delay = parser.crawl_delay(CRAWLER_USER_AGENT)
                    if delay is None:
                        delay = parser.crawl_delay("*")
                    sitemaps: list[str] = []
                    for raw_line in lines:
                        clean = raw_line.split("#", 1)[0].strip()
                        if not clean.casefold().startswith("sitemap:"):
                            continue
                        try:
                            sitemap = _clean_candidate_url(clean.split(":", 1)[1].strip())
                        except ValueError:
                            continue
                        if sitemap not in sitemaps:
                            sitemaps.append(sitemap)
                    policy = _RobotsPolicy(
                        parser=parser, crawl_delay=float(delay or 0.0),
                        sitemaps=tuple(sitemaps),
                    )
                else:
                    policy = _RobotsPolicy(allow_all=True)
            with self._robots_guard:
                self._robots[origin] = policy
            return policy

    def _wait_for_origin(self, url: str, delay: float) -> None:
        if delay <= 0:
            return
        origin = self._origin(url)
        now = monotonic()
        with self._schedule_guard:
            slot = max(now, self._next_request.get(origin, now))
            self._next_request[origin] = slot + delay
        remaining = slot - monotonic()
        if remaining > 0:
            sleep(remaining)

    def _fetch_crawl(self, url: str, *, method: str = "GET") -> WPEFetchedDocument:
        """Fetch one crawl candidate with robots, DNS, and redirect checks at every hop."""
        target = _canonical_http_url(url)
        for _ in range(MAX_REDIRECTS + 1):
            policy = self._robots_policy(target)
            if not policy.allows(target):
                raise _RobotsDenied(f"robots.txt disallows crawl target: {target}")
            approved = self._resolve_public_addresses(target)
            self._wait_for_origin(target, policy.crawl_delay)
            try:
                return self.transport.fetch_once(
                    target, method=method, _resolved_addresses=approved
                )
            except WPERedirectRequired as redirect:
                target = _canonical_http_url(redirect.target, base=target)
        raise WPETransportError("live crawler redirect limit exceeded")

    def _fetch_candidate(self, url: str) -> WPEFetchedDocument:
        """Probe requested media by HEAD so the spider never buffers the media body."""
        if not _is_media_url(url):
            return self._fetch_crawl(url)
        metadata = self._fetch_crawl(url, method="HEAD")
        mime = metadata.mime_type.split(";", 1)[0].strip().casefold()
        if mime in {"text/html", "application/xhtml+xml"}:
            return self._fetch_crawl(url)
        return metadata

    @staticmethod
    def _scope_allows(url: str, options: LiveCrawlOptions) -> bool:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold()
        if options.domain:
            domain = options.domain.casefold().lstrip(".")
            if host != domain and not host.endswith("." + domain):
                return False
        if options.site:
            site = options.site.strip()
            if "://" in site:
                site_parsed = urlsplit(site)
                site_host = (site_parsed.hostname or "").casefold()
                if site_host and host != site_host:
                    return False
                if site_parsed.path and site_parsed.path != "/" and not parsed.path.startswith(site_parsed.path):
                    return False
            else:
                site_host = site.casefold().lstrip(".")
                if host != site_host and not host.endswith("." + site_host):
                    return False
        if options.path and not parsed.path.startswith(options.path):
            return False
        return True

    @staticmethod
    def _same_site_host(candidate: str, root: str) -> bool:
        candidate = candidate.casefold().rstrip(".")
        root = root.casefold().rstrip(".")
        anchor = root[4:] if root.startswith("www.") else root
        return candidate in {root, anchor} or candidate.endswith("." + anchor)

    @classmethod
    def _host_allows(cls, candidate: str, root: str, options: LiveCrawlOptions) -> bool:
        if options.outbound:
            return True
        if options.same_site:
            return cls._same_site_host(candidate, root)
        return candidate.casefold().rstrip(".") == root.casefold().rstrip(".")

    @staticmethod
    def _text_allows(text: str, query: str, options: LiveCrawlOptions, *, url: str = "") -> bool:
        haystack = f"{text} {unquote(url)}".casefold()
        if options.exact and query.casefold() not in haystack:
            return False
        if not _query_matches(query, text, url):
            return False
        if any(item.casefold() not in haystack for item in options.contains):
            return False
        if any(item.casefold() in haystack for item in options.exclude):
            return False
        return True


    def _sitemap_candidates(
        self, root_url: str, root_host: str, options: LiveCrawlOptions
    ) -> tuple[str, ...]:
        if options.depth <= 0:
            return ()
        origin = self._origin(root_url)
        cache_key = (origin, options)
        cached = self._sitemap_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            policy = self._robots_policy(root_url)
        except _DNSRejected:
            self._sitemap_cache[cache_key] = ()
            return ()
        if policy.disallow_all:
            self._sitemap_cache[cache_key] = ()
            return ()
        starts = list(policy.sitemaps)
        fallback_starts = not starts
        conventional = [origin + "/sitemap.xml", origin + "/sitemap_index.xml", origin + "/wp-sitemap.xml"]
        if fallback_starts:
            starts = list(conventional)
        pending = deque(starts)
        seen_docs: set[str] = set()
        candidates: list[str] = []
        candidate_limit = min(options.max_pages * _DISCOVERY_MULTIPLIER, 800)

        def child_text(node, name: str) -> str:
            for child in list(node):
                if _xml_name(child.tag) == name:
                    return (child.text or "").strip()
            return ""

        while pending and len(seen_docs) < MAX_SITEMAP_DOCUMENTS and len(candidates) < candidate_limit:
            raw_sitemap = pending.popleft()
            try:
                sitemap_url = _clean_candidate_url(raw_sitemap, base=origin + "/")
            except ValueError:
                continue
            if sitemap_url in seen_docs:
                continue
            sitemap_host = (urlsplit(sitemap_url).hostname or "").casefold()
            if not self._host_allows(sitemap_host, root_host, options):
                continue
            seen_docs.add(sitemap_url)
            try:
                document = self._fetch(sitemap_url)
            except (ValueError, WPETransportError):
                continue
            if not 200 <= document.status < 300:
                continue
            try:
                xml_root = ElementTree.fromstring(_structured_xml_payload(document))
            except ElementTree.ParseError:
                continue
            root_name = _xml_name(xml_root.tag)
            if root_name not in {"sitemapindex", "urlset"}:
                continue
            if fallback_starts and sitemap_url in conventional:
                pending = deque(item for item in pending if item not in conventional)
            if root_name == "sitemapindex":
                for node in list(xml_root):
                    if _xml_name(node.tag) != "sitemap":
                        continue
                    loc = child_text(node, "loc")
                    lastmod = child_text(node, "lastmod")
                    if not loc or not _date_hint_allowed(lastmod, self.now, options.recent_days):
                        continue
                    pending.append(loc)
                continue
            for node in list(xml_root):
                if _xml_name(node.tag) != "url":
                    continue
                loc = child_text(node, "loc")
                lastmod = child_text(node, "lastmod")
                if not loc or not _date_hint_allowed(lastmod, self.now, options.recent_days):
                    continue
                try:
                    candidate = _clean_candidate_url(loc, base=sitemap_url)
                except ValueError:
                    continue
                candidate_host = (urlsplit(candidate).hostname or "").casefold()
                if not self._host_allows(candidate_host, root_host, options):
                    continue
                if not self._scope_allows(candidate, options):
                    continue
                if not _looks_like_content_candidate(candidate, include_pdf=options.include_pdf):
                    continue
                if candidate not in candidates:
                    candidates.append(candidate)
                    if len(candidates) >= candidate_limit:
                        break
        result = tuple(candidates)
        self._sitemap_cache[cache_key] = result
        return result

    def _feed_candidates(
        self, feed_url: str, base_url: str, root_host: str, options: LiveCrawlOptions
    ) -> tuple[str, ...]:
        if options.depth <= 0 or len(self._feed_seen) >= MAX_FEED_DOCUMENTS:
            return ()
        try:
            feed = _clean_candidate_url(feed_url, base=base_url)
        except ValueError:
            return ()
        if feed in self._feed_seen:
            return ()
        feed_host = (urlsplit(feed).hostname or "").casefold()
        if not self._host_allows(feed_host, root_host, options):
            return ()
        self._feed_seen.add(feed)
        try:
            document = self._fetch_crawl(feed)
        except (ValueError, WPETransportError):
            return ()
        if not 200 <= document.status < 300:
            return ()
        try:
            xml_root = ElementTree.fromstring(_structured_xml_payload(document))
        except ElementTree.ParseError:
            return ()
        candidates: list[str] = []
        candidate_limit = min(options.max_pages * _DISCOVERY_MULTIPLIER, 800)
        for entry in xml_root.iter():
            if _xml_name(entry.tag) not in {"item", "entry"}:
                continue
            link = ""
            date_hint = ""
            guid = ""
            for child in list(entry):
                name = _xml_name(child.tag)
                if name == "link":
                    rel = str(child.attrib.get("rel", "alternate")).casefold()
                    href = str(child.attrib.get("href", "")).strip()
                    if href and rel in {"", "alternate"}:
                        link = href
                    elif not link and (child.text or "").strip():
                        link = (child.text or "").strip()
                elif name in {"published", "updated", "pubdate", "date"} and not date_hint:
                    date_hint = (child.text or "").strip()
                elif name == "guid" and not guid:
                    if str(child.attrib.get("ispermalink", "true")).casefold() != "false":
                        guid = (child.text or "").strip()
            target = link or guid
            if not target or not _date_hint_allowed(date_hint, self.now, options.recent_days):
                continue
            try:
                candidate = _clean_candidate_url(target, base=feed)
            except ValueError:
                continue
            candidate_host = (urlsplit(candidate).hostname or "").casefold()
            if not self._host_allows(candidate_host, root_host, options):
                continue
            if not self._scope_allows(candidate, options):
                continue
            if not _looks_like_content_candidate(candidate, include_pdf=options.include_pdf):
                continue
            if candidate not in candidates:
                candidates.append(candidate)
                if len(candidates) >= candidate_limit:
                    break
        return tuple(candidates)

    def _spider_roots(self, options: LiveCrawlOptions) -> list[str]:
        """Build roots only from operator-supplied site/domain/seed controls."""
        roots: list[str] = []
        for seed in options.seeds:
            target = _clean_candidate_url(seed)
            if self._scope_allows(target, options) and target not in roots:
                roots.append(target)
        for scope in (options.site, options.domain):
            if not scope:
                continue
            target = _scope_seed(scope)
            if self._scope_allows(target, options) and target not in roots:
                roots.append(target)
        if not roots:
            raise ValueError("spider search requires --site, --domain, or --seed")
        return roots

    def _fetch_catalog_page(self, url: str):
        """Retry one transient network timeout; keep every crawl trust check."""
        for attempt in range(2):
            try:
                return self._fetch_crawl(url)
            except WPETransportError as exc:
                cause = exc
                seen = set()
                timed_out = False
                while cause is not None and id(cause) not in seen:
                    seen.add(id(cause))
                    timed_out = timed_out or isinstance(cause, TimeoutError)
                    cause = cause.__cause__ or cause.__context__
                if not timed_out or attempt:
                    raise
                self.progress("Catalog request timed out; retrying once…")

    def _archive_catalog_search(self, query: str, options: LiveCrawlOptions) -> LiveCrawlReport:
        from .catalog import (ARCHIVE_PAGE_SIZE, ARCHIVE_RESULT_LIMIT,
                              archive_query_url, parse_archive_page,
                              archive_item_url, metadata_text)
        results = []
        seen = set()
        fetched = rejected_age = rejected_filter = 0
        total = 0
        examined = 0
        interrupted = False
        for page_number in range(1, min(options.max_pages, ARCHIVE_RESULT_LIMIT // ARCHIVE_PAGE_SIZE) + 1):
            url = archive_query_url(query, page_number, exact=options.exact)
            self.progress(f"Searching catalog page {page_number}; {len(results)} results collected…")
            try:
                document = self._fetch_catalog_page(url)
            except _DNSRejected:
                return LiveCrawlReport((), fetched, 0, 0, rejected_dns=1,
                                       notice="Internet Archive search could not reach a public server.")
            except _RobotsDenied:
                return LiveCrawlReport((), fetched, 0, 0, rejected_robots=1,
                                       notice="Internet Archive does not permit this search request.")
            except WPETransportError as exc:
                if results:
                    interrupted = True
                    break
                raise ValueError("Internet Archive search could not finish: network request failed; try again.") from exc
            fetched += 1
            if not 200 <= document.status < 300 or urlsplit(document.url).hostname != 'archive.org':
                raise ValueError("Internet Archive search returned an unsuccessful response")
            catalog = parse_archive_page(document.body)
            if catalog.start != (page_number - 1) * ARCHIVE_PAGE_SIZE:
                raise ValueError("Internet Archive search returned an unexpected result page")
            total = catalog.total
            examined = catalog.start + len(catalog.items)
            for item in catalog.items:
                item_url = archive_item_url(item)
                if item_url is None or item_url in seen or not self._scope_allows(item_url, options):
                    continue
                seen.add(item_url)
                title = metadata_text(item.get('title'), 240) or item_url
                description = metadata_text(item.get('description'))
                parser = _PageParser()
                parser.feed(description)
                snippet = parser.snippet
                text = ' '.join((title, parser.text, metadata_text(item.get('subject')),
                                 metadata_text(item.get('mediatype')), item_url))
                # The site's index performs query matching over its full metadata.
                # Local operator include/exclude controls still apply to returned fields.
                if not self._text_allows(text, '', options, url=item_url):
                    rejected_filter += 1
                    continue
                date = metadata_text(item.get('date'), 120)
                decision = decide_age([DateCandidate(date, Qualifier.STRUCTURED,
                                                     'Internet Archive item date')] if date else [],
                                      now=self.now)
                if not _decision_allowed(decision, self.now, options.recent_days):
                    rejected_age += 1
                    continue
                content_date, age_days, evidence, sort_date = _result_date(decision, self.now)
                results.append((sort_date, LiveResult(item_url, title, content_date, age_days,
                                                      evidence, snippet, 'archive.org',
                                                      media=archive_media(item),
                                                      size_bytes=reported_size(item.get("item_size")),
                                                      size_note="Archive item total (all files)")))
            if examined >= total:
                break
            if not catalog.items:
                raise ValueError("Internet Archive search stopped before all result pages arrived")
        results.sort(key=lambda item: item[1].url.casefold())
        results.sort(key=lambda item: item[0], reverse=True)
        notice = ""
        if interrupted:
            notice = "Search incomplete: a catalog request failed. Showing results already collected; try again for the remaining matches."
        elif examined < total:
            if examined >= ARCHIVE_RESULT_LIMIT:
                notice = "Internet Archive limits this search to 10,000 matches. Narrow the query to see more specific results."
            else:
                notice = (f"Search stopped after {fetched} result pages; more matches are available. "
                          "Increase --max-pages to load more.")
        return LiveCrawlReport(tuple(item[1] for item in results), fetched,
                               rejected_age, rejected_filter, notice=notice)

    def search(self, query: str, options: LiveCrawlOptions | None = None) -> LiveCrawlReport:
        options = options or LiveCrawlOptions()
        self._feed_seen.clear()
        query = str(query).strip()
        if not query:
            raise ValueError("spider search terms are required")
        roots = self._spider_roots(options)
        if (len(roots) == 1 and urlsplit(roots[0]).hostname == 'archive.org'
                and urlsplit(roots[0]).path in {'', '/'}):
            return self._archive_catalog_search(query, options)

        frontier = deque((url, 0, (urlsplit(url).hostname or "").casefold()) for url in roots)
        queued = set(roots)
        if options.depth > 0:
            structured_origins: set[str] = set()
            for root in roots:
                origin = self._origin(root)
                if origin not in structured_origins:
                    if len(structured_origins) >= MAX_STRUCTURED_ORIGINS:
                        continue
                    structured_origins.add(origin)
                root_host = (urlsplit(root).hostname or "").casefold()
                for candidate in self._sitemap_candidates(root, root_host, options):
                    if candidate in queued:
                        continue
                    if _is_media_url(candidate) and not self._text_allows(
                        candidate, query, options, url=candidate
                    ):
                        continue
                    queued.add(candidate)
                    frontier.append((candidate, 1, root_host))
        fetched_urls: set[str] = set()
        results: list[tuple[datetime, LiveResult]] = []
        fetched = rejected_age = rejected_filter = rejected_robots = rejected_dns = 0

        with ThreadPoolExecutor(
            max_workers=MAX_CONCURRENT_FETCHES,
            thread_name_prefix="bojangles-live-crawl",
        ) as pool:
            while frontier and fetched < options.max_pages:
                batch = []
                available = min(MAX_CONCURRENT_FETCHES, options.max_pages - fetched)
                while frontier and len(batch) < available:
                    item = frontier.popleft()
                    url, depth, root_host = item
                    if url in fetched_urls:
                        continue
                    fetched_urls.add(url)
                    batch.append((item, pool.submit(self._fetch_candidate, url)))
                if not batch:
                    continue

                for (url, depth, root_host), future in batch:
                    try:
                        document = future.result()
                    except _DNSRejected:
                        rejected_dns += 1
                        continue
                    except _RobotsDenied:
                        rejected_robots += 1
                        continue
                    except (ValueError, WPETransportError):
                        continue
                    fetched += 1
                    if document.status < 200 or document.status >= 300:
                        continue
                    try:
                        final_url = _canonical_http_url(document.url)
                    except ValueError:
                        continue
                    if not self._scope_allows(final_url, options):
                        continue
                    root_host = (urlsplit(final_url).hostname or root_host).casefold()

                    headers = _header_map(document)
                    media = _is_media_document(document)
                    if media:
                        media_candidates = list(extract_html_candidates("", headers=headers))
                        decision = decide_age(media_candidates, now=self.now)
                        if not _decision_allowed(decision, self.now, options.recent_days):
                            rejected_age += 1
                            continue
                        title = PurePosixPath(unquote(urlsplit(document.url).path)).name or document.url
                        text = f"{title} {document.url} {document.mime_type}"
                        if not self._text_allows(text, query, options, url=document.url):
                            rejected_filter += 1
                            continue
                        content_date, age_days, evidence, sort_date = _result_date(decision, self.now)
                        result = LiveResult(
                            document.url,
                            title,
                            content_date,
                            age_days,
                            evidence,
                            "",
                            urlsplit(document.url).hostname or "",
                            False,
                            media=media_from_mime(document.mime_type) or media_from_url(document.url) or "Unknown",
                            size_bytes=content_length(document.headers),
                            size_note="Reported file size",
                        )
                        results.append((sort_date, result))
                        continue

                    pdf = _is_pdf(document)
                    if pdf:
                        if not options.include_pdf:
                            continue
                        pdf_candidates = list(extract_pdf_date_candidates(document.body))
                        pdf_candidates.extend(extract_html_candidates("", headers=headers))
                        decision = decide_age(pdf_candidates, now=self.now)
                        if not _decision_allowed(decision, self.now, options.recent_days):
                            rejected_age += 1
                            continue
                        title = PurePosixPath(urlsplit(document.url).path).name or document.url
                        text = f"{title} {document.url}"
                        if not self._text_allows(text, query, options):
                            rejected_filter += 1
                            continue
                        content_date, age_days, evidence, sort_date = _result_date(decision, self.now)
                        result = LiveResult(
                            document.url,
                            title,
                            content_date,
                            age_days,
                            evidence,
                            "",
                            urlsplit(document.url).hostname or "",
                            True,
                            media="PDF",
                            size_bytes=content_length(document.headers),
                            size_note="Reported file size",
                        )
                        results.append((sort_date, result))
                        continue

                    mime = document.mime_type.split(";", 1)[0].strip().casefold()
                    if mime not in {"text/html", "application/xhtml+xml"}:
                        continue
                    html = _decode(document)
                    parser = _PageParser()
                    parser.feed(html)
                    decision = evaluate_html(html, headers=headers, now=self.now)
                    if not _decision_allowed(decision, self.now, options.recent_days):
                        rejected_age += 1
                    else:
                        text = f"{parser.title} {parser.text} {document.url}"
                        if self._text_allows(text, query, options):
                            content_date, age_days, evidence, sort_date = _result_date(decision, self.now)
                            result = LiveResult(
                                document.url,
                                parser.title or document.url,
                                content_date,
                                age_days,
                                evidence,
                                parser.snippet,
                                urlsplit(document.url).hostname or "",
                                media=media_summary(parser.media_types, unknown=parser.media_unknown),
                            )
                            results.append((sort_date, result))
                        else:
                            rejected_filter += 1

                    if depth >= options.depth:
                        continue
                    base = document.url
                    for feed_href in parser.feeds:
                        for child in self._feed_candidates(feed_href, base, root_host, options):
                            if child in queued:
                                continue
                            queued.add(child)
                            frontier.append((child, depth + 1, root_host))
                    for href in (*parser.links, *parser.media_links):
                        try:
                            child = _clean_candidate_url(href, base=base)
                        except ValueError:
                            continue
                        if child in queued or not self._scope_allows(child, options):
                            continue
                        if not _looks_like_content_candidate(
                            child, include_pdf=options.include_pdf
                        ):
                            continue
                        if _is_media_url(child) and not self._text_allows(
                            child, query, options, url=child
                        ):
                            continue
                        child_host = (urlsplit(child).hostname or "").casefold()
                        if not self._host_allows(child_host, root_host, options):
                            continue
                        queued.add(child)
                        frontier.append((child, depth + 1, root_host))

        results.sort(key=lambda item: item[1].url.casefold())
        results.sort(key=lambda item: item[0], reverse=True)
        return LiveCrawlReport(
            tuple(item[1] for item in results), fetched, rejected_age,
            rejected_filter, rejected_robots, rejected_dns,
        )


__all__ = [
    "LiveCrawlOptions",
    "LiveCrawlReport",
    "LiveResult",
    "LiveWebCrawler",
    "extract_pdf_date_candidates",
]
