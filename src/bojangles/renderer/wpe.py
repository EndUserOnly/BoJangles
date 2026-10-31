"""WPE 2.52.6 renderer backend behind the stable BoJangles RendererBackend API.

The native WPE process runs forward in the already-certified outer DMZ.  This
adapter owns only lifecycle IPC and the frontend-owned framebuffer descriptor.
The trusted RequestChannel remains inside the BoJangles frontend and is not
serialized into the WPE process family. Browser-compatible HTTP cookie state is
owned by the trusted transport: WPE never receives cookie authority, while
brokered first-party/session requests can carry correctly scoped cookies.
Stage 7 optionally binds a
trusted, user-owned persistent WPE data/cache profile into the outer DMZ while
keeping HTTP-auth secrets and the trusted top-level cookie jar nonpersistent.
WPE retains no origin socket authority.
"""
from __future__ import annotations

from collections import deque
import os
import mmap
import hmac
import re
import fcntl
from pathlib import Path
import shutil
import secrets
import socket
import selectors
import struct
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor

from .api import (
    FormStateEntry,
    NavigationRequest,
    RendererBackend,
    RendererCapabilities,
    RendererEvent,
    RendererEventKind,
    RendererLifecycle,
    RendererSnapshot,
    RendererStartContext,
    Viewport,
    ResourceType,
)
from bojangles.media.candidates import (
    MediaCandidateCatalog, MediaKind, classify, hls_manifest_references,
    hls_protection, dash_protection, html_media_hints, manifest_captions,
)
from bojangles.media.pdf_inline import inline_pdf_embeds
from .host_network_state import HostNetworkState
from .wpe_gateway import WPEGatewayRenderer, WPERequestIntent
from .wpe_transport import (
    MAX_HEADER_BYTES,
    MAX_RESPONSE_HEADER_BYTES,
    MAX_HEADER_COUNT,
    MAX_REQUEST_BODY_BYTES,
    MAX_MEMORY_REQUEST_BODY_BYTES,
    MAX_CROSS_ORIGIN_POST_BYTES,
    WPEAllowedDataTransport,
    WPERedirectRequired,
    WPEDownloadOffered,
    WPETransportError,
)

from .native_protocol import (
    NativeMessage,
    RESOURCE_MESSAGES,
    NativePacket,
    pack_strings,
    recv_packet_with_fd,
    send_packet,
    send_packet_with_fd,
    unpack_strings,
)


_NAVIGATION_STATE_KEY = secrets.token_bytes(32)



def _renderer_environment(environment=None):
    """Admit locale settings only before entering the native sandbox.

    Do not inherit sandbox markers, loader overrides, credentials, or
    caller-selected executable search paths. Validated renderer paths
    are supplied explicitly by start().
    """
    source = os.environ if environment is None else environment
    allowed = {
        "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
        "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
        "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE",
        "LC_MEASUREMENT", "LC_IDENTIFICATION",
    }
    result = {key: value for key, value in source.items() if key in allowed}
    result["PATH"] = "/usr/bin:/bin"
    return result

class WPEProtocolError(RuntimeError):
    pass


class _Reply:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.packet: NativePacket | None = None


def _snapshot_payload(snapshot: RendererSnapshot) -> bytes:
    values = [
        snapshot.document_id,
        snapshot.uri,
        str(snapshot.scroll_x),
        str(snapshot.scroll_y),
        str(len(snapshot.form_state)),
    ]
    for entry in snapshot.form_state:
        values.extend((entry.name, entry.value))
    return pack_strings(*values)


def _snapshot_from_payload(payload: bytes) -> RendererSnapshot:
    if not payload.endswith(b"\0"):
        raise WPEProtocolError("WPE snapshot payload is not terminated")
    raw = payload[:-1].split(b"\0")
    if len(raw) < 5:
        raise WPEProtocolError("WPE snapshot payload is truncated")
    try:
        values = [part.decode("utf-8", errors="strict") for part in raw]
        scroll_x = int(values[2])
        scroll_y = int(values[3])
        count = int(values[4])
    except (UnicodeDecodeError, ValueError) as exc:
        raise WPEProtocolError("WPE snapshot payload is invalid") from exc
    if count < 0 or len(values) != 5 + count * 2:
        raise WPEProtocolError("WPE snapshot form-state count mismatch")
    forms = tuple(
        FormStateEntry(values[5 + index * 2], values[6 + index * 2])
        for index in range(count)
    )
    return RendererSnapshot(values[0], values[1], scroll_x, scroll_y, forms)


def _decode_string_list(payload: bytes) -> tuple[str, ...]:
    if not payload.endswith(b"\0"):
        raise WPEProtocolError("WPE string-list payload is not terminated")
    parts = payload[:-1].split(b"\0") if payload[:-1] else []
    try:
        return tuple(part.decode("utf-8", errors="strict") for part in parts)
    except UnicodeDecodeError as exc:
        raise WPEProtocolError("WPE string-list payload is not UTF-8") from exc


def _resource_request_from_payload(payload: bytes, *, with_statistics=False):
    values = _decode_string_list(payload)
    group = None
    if len(values) >= 9 and values[5] == "stage5d-stats":
        try:
            if not values[-1].isascii() or not values[-1].isdigit() or len(values[-1]) > 10:
                raise ValueError()
            group = int(values[-1])
            if not 0 <= group <= 0xFFFFFFFF:raise ValueError()
        except ValueError as exc:raise WPEProtocolError("invalid resource statistics group") from exc
        values = values[:5] + ("stage5d",) + values[6:-1]
    def result(*parts):
        return parts + (group,) if with_statistics else parts
    # Stage 5B compatibility for focused fake-native/project tests.
    if len(values) == 4:
        return result(values[0], values[1], values[2], values[3], "GET", (), 0)
    # Stage 5D envelope: document, URL, type, initiator, method, marker,
    # body length, header count, then name/value pairs.
    if len(values) >= 8 and values[5] == "stage5d":
        try:
            body_length = int(values[6])
            count = int(values[7])
        except ValueError as exc:
            raise WPEProtocolError("WPE Stage 5D resource metadata is invalid") from exc
        if body_length < 0 or body_length > MAX_REQUEST_BODY_BYTES:
            raise WPEProtocolError("WPE request body length exceeds protocol bound")
        if count < 0 or count > MAX_HEADER_COUNT or len(values) != 8 + count * 2:
            raise WPEProtocolError("WPE resource header count mismatch")
        headers = tuple(
            (values[8 + index * 2], values[9 + index * 2])
            for index in range(count)
        )
        total = sum(len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4 for name, value in headers)
        if total > MAX_HEADER_BYTES:
            raise WPEProtocolError("WPE resource headers exceed protocol bound")
        return result(values[0], values[1], values[2], values[3], values[4], headers, body_length)
    # Stage 5C compatibility: method followed directly by header count.
    if len(values) < 6:
        raise WPEProtocolError("WPE resource request metadata is truncated")
    try:
        count = int(values[5])
    except ValueError as exc:
        raise WPEProtocolError("WPE resource header count is invalid") from exc
    if count < 0 or count > MAX_HEADER_COUNT or len(values) != 6 + count * 2:
        raise WPEProtocolError("WPE resource header count mismatch")
    headers = tuple(
        (values[6 + index * 2], values[7 + index * 2])
        for index in range(count)
    )
    total = sum(len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4 for name, value in headers)
    if total > MAX_HEADER_BYTES:
        raise WPEProtocolError("WPE resource headers exceed protocol bound")
    return result(values[0], values[1], values[2], values[3], values[4], headers, 0)


class WPEBackend(RendererBackend):
    backend_id = "wpe"

    def __init__(
        self,
        executable: str | os.PathLike[str],
        *,
        prefix: str | os.PathLike[str],
        extension_dir: str | os.PathLike[str],
        transport: WPEAllowedDataTransport | None = None,
        profile_data_dir: str | os.PathLike[str] | None = None,
        profile_cache_dir: str | os.PathLike[str] | None = None,
        backend_id: str = "wpe",
        drm_mode: bool = False,
        resource_redirect_handoff: bool = False,
        native_pdf_viewer: bool = False,
    ) -> None:
        if not backend_id:
            raise ValueError("WPE backend_id required")
        self.backend_id = str(backend_id)
        self._drm_mode = bool(drm_mode)
        self._resource_redirect_handoff = bool(resource_redirect_handoff)
        self._native_pdf_viewer = bool(native_pdf_viewer)
        self.executable = os.fspath(executable)
        self.prefix = os.fspath(prefix)
        self.extension_dir = os.fspath(extension_dir)
        self._transport = transport or WPEAllowedDataTransport()
        from uuid import uuid4
        self._statistics_nonce = uuid4().hex
        self._statistics_highwater = 0
        if (profile_data_dir is None) != (profile_cache_dir is None):
            raise ValueError("WPE persistent profile requires both data and cache directories")
        self.profile_data_dir = os.fspath(profile_data_dir) if profile_data_dir is not None else None
        self.profile_cache_dir = os.fspath(profile_cache_dir) if profile_cache_dir is not None else None
        self._lifecycle = RendererLifecycle.STOPPED
        lease = getattr(self, "_profile_lease", None)
        if lease is not None:
            lease.release()
            self._profile_lease = None
        self._failure_lock = threading.Lock()
        self._context: RendererStartContext | None = None
        self._request: NavigationRequest | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._native_diagnostics = None
        self._upload_staging_dir: str | None = None
        self._host_network_state: HostNetworkState | None = None
        self._sock: socket.socket | None = None
        self._resource_sock: socket.socket | None = None
        self._reader: threading.Thread | None = None
        self._resources: ThreadPoolExecutor | None = None
        self._resource_slots = threading.BoundedSemaphore(256)
        self._reader_stop = threading.Event()
        self._ready = threading.Event()
        self._events: deque[RendererEvent] = deque()
        self._events_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._resource_send_lock = threading.Lock()
        self._reply_lock = threading.Lock()
        self._replies: dict[int, _Reply] = {}
        self._next_request_id = 1
        self.media_candidates = MediaCandidateCatalog()
        self._drm_enabled = False
        self._navigation_lock = threading.RLock()
        self._navigation_cancel = threading.Event()
        self._navigation_local = threading.local()

    @property
    def lifecycle(self) -> RendererLifecycle:
        return self._lifecycle

    def capabilities(self) -> RendererCapabilities:
        # Conservative: Stage 5D certifies relative same-origin GET/POST
        # XHR/Fetch through the trusted data plane. EME is exposed only by
        # the separately selected wpe-drm backend after trusted UI consent.
        return RendererCapabilities(
            html5=True,
            javascript=True,
            css=True,
            forms=True,
            canvas=True,
            webaudio=True,
            mse=False,
            eme=self._drm_enabled,
            websocket=False,
            media_elements=True,
        )

    @staticmethod
    def _prepare_profile_directory(value: str, label: str) -> str:
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError(f"{label} must be an absolute path")
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"{label} may not be a symlink")
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ValueError(f"{label} may not traverse symlinks")
        if st.st_uid != os.getuid():
            raise PermissionError(f"{label} must be owned by the current user")
        os.chmod(path, 0o700)
        return str(path)

    def _resolve_executable(self) -> str:
        path = Path(self.executable)
        if path.parent != Path(".") or path.is_absolute():
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            raise FileNotFoundError(self.executable)
        found = shutil.which(self.executable)
        if found is None:
            raise FileNotFoundError(self.executable)
        return found

    def _fail(self, detail: str) -> None:
        """Publish one terminal event and retire both halves of this IPC generation."""
        with self._failure_lock:
            if self._lifecycle not in {RendererLifecycle.STARTING, RendererLifecycle.RUNNING}:
                return
            self._lifecycle = RendererLifecycle.FAILED
            self._navigation_cancel.set()
            self._reader_stop.set()
            process = self._process
            code = process.poll() if process is not None else None
            if code is not None:
                detail += f" (native exit {code})"
            diagnostics = self._native_diagnostics
            if diagnostics is not None:
                try:
                    length = os.fstat(diagnostics.fileno()).st_size
                    tail = os.pread(diagnostics.fileno(), min(length, 8192), max(0, length - 8192))
                    reasons = re.findall(rb"web-process-terminated reason=([0-9]+)", tail)
                    if reasons:
                        detail += " (WebProcess termination reason " + reasons[-1].decode("ascii") + ")"
                except (OSError, ValueError):
                    pass
            context = self._context
            event = RendererEvent(RendererEventKind.RENDERER_CRASHED,
                context.document.document_id if context else "",
                uri=self._request.uri if self._request else "", detail=detail)
            # Failure cannot be suppressed by a cancelled navigation worker.
            with self._events_lock:
                self._events.append(event)
            for channel in (self._sock, self._resource_sock):
                if channel is not None:
                    try:
                        channel.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            with self._reply_lock:
                for reply in self._replies.values():
                    reply.event.set()
            self._ready.set()

    def _check_process(self) -> None:
        process = self._process
        if process is not None and process.poll() is not None:
            self._fail("native WPE process exited")

    def _send(self, packet: NativePacket, fd: int | None = None) -> None:
        resource = packet.kind in RESOURCE_MESSAGES
        sock = self._resource_sock if resource else self._sock
        lock = self._resource_send_lock if resource else self._send_lock
        if sock is None:
            raise RuntimeError("WPE IPC channel is not open")
        if fd is not None and not resource and packet.kind not in {NativeMessage.CLIPBOARD_PASTE_PNG, NativeMessage.IMAGE_DATA_REQUEST, NativeMessage.PRINT_PDF_REQUEST, NativeMessage.PAGE_EXPORT_REQUEST, NativeMessage.RESIZE}:
            raise WPEProtocolError("control channel cannot carry descriptors")
        try:
            # Input and cancellation must not queue behind a stalled sender.
            if not lock.acquire(timeout=0.1):
                raise TimeoutError("WPE IPC sender is busy")
            try:
                cancelled = getattr(self._navigation_local, "cancelled", None)
                if cancelled is not None and cancelled.is_set():
                    return
                if fd is None:
                    send_packet(sock, packet)
                else:
                    send_packet_with_fd(sock, packet, fd)
            finally:
                lock.release()
        except OSError as exc:
            self._fail(f"WPE {'resource' if resource else 'control'} send failed: {type(exc).__name__}")
            raise

    def _new_request_id(self) -> int:
        with self._reply_lock:
            value = self._next_request_id
            self._next_request_id = 1 if value == 0xFFFFFFFF else value + 1
            return value

    def _request_reply(
        self,
        kind: NativeMessage,
        payload: bytes = b"",
        *,
        timeout: float = 2.0,
        fd: int | None = None,
    ) -> NativePacket:
        request_id = self._new_request_id()
        reply = _Reply()
        with self._reply_lock:
            self._replies[request_id] = reply
        try:
            if fd is None:
                self._send(NativePacket(kind, request_id, payload))
            else:
                self._send(NativePacket(kind, request_id, payload), fd)
            if not reply.event.wait(timeout):
                raise TimeoutError(f"WPE did not answer {kind.name}")
            if reply.packet is None:
                raise WPEProtocolError("WPE reply channel closed")
            return reply.packet
        finally:
            with self._reply_lock:
                self._replies.pop(request_id, None)

    def _deliver_reply(self, packet: NativePacket) -> bool:
        if packet.kind not in {NativeMessage.SNAPSHOT_RESULT, NativeMessage.RESTORE_RESULT,
                NativeMessage.STATE_RESULT, NativeMessage.CREDENTIAL_FILL_RESULT,
                NativeMessage.CLIPBOARD_COPY_RESULT, NativeMessage.CLIPBOARD_COPY_RICH_RESULT, NativeMessage.CLIPBOARD_PASTE_RESULT,
                NativeMessage.PAGE_EXPORT_RESULT, NativeMessage.PRINT_PDF_RESULT, NativeMessage.IMAGE_DATA_RESULT, NativeMessage.TRANSLATION_RESULT, NativeMessage.ERROR}:
            return False
        if packet.request_id == 0:
            return False
        with self._reply_lock:
            reply = self._replies.get(packet.request_id)
            if reply is None:
                return False
            reply.packet = packet
            reply.event.set()
            return True

    def start(self, context: RendererStartContext) -> None:
        if self._lifecycle is RendererLifecycle.RUNNING:
            return
        if self._process is not None or self._reader is not None:
            self.stop()
        with self._events_lock:
            self._events.clear()
        fb = context.framebuffer
        if fb.buffer_fd is None or fb.stride is None or fb.byte_length is None:
            raise ValueError("WPE requires a frontend-owned shared framebuffer target")
        executable = self._resolve_executable()
        prefix = Path(self.prefix)
        extension_dir = Path(self.extension_dir)
        if not prefix.is_dir():
            raise FileNotFoundError(self.prefix)
        if not extension_dir.is_dir():
            raise FileNotFoundError(self.extension_dir)

        self._lifecycle = RendererLifecycle.STARTING
        self._context = context
        self._reader_stop.clear()
        self._ready.clear()

        from bojangles.maintenance.lease import ProfileLease
        self._profile_lease = ProfileLease().acquire() if self.profile_data_dir is not None else None
        parent = child = resource_parent = resource_child = None
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            resource_parent, resource_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            # Bound stalled resource writes without sharing the control send lock.
            resource_parent.settimeout(1.0)
            parent.settimeout(1.0)
            argv = [
                executable,
                "--control-fd", str(child.fileno()),
                "--resource-fd", str(resource_child.fileno()),
            ]
            argv.extend([
                "--fb-fd", str(fb.buffer_fd),
                "--width", str(fb.width),
                "--height", str(fb.height),
                "--stride", str(fb.stride),
                "--format", fb.pixel_format,
            ])
            env = _renderer_environment()
            env["BOJANGLES_WPE_PREFIX"] = str(prefix)
            env["BOJANGLES_WPE_EXTENSION_DIR"] = str(extension_dir)
            self._upload_staging_dir = tempfile.mkdtemp(prefix="bojangles-upload-")
            os.chmod(self._upload_staging_dir, 0o700)
            env["BOJANGLES_WPE_UPLOAD_DIR"] = self._upload_staging_dir
            self._host_network_state = HostNetworkState(Path(self._upload_staging_dir) / ".network-state")
            if self.profile_data_dir is not None:
                data_dir = self._prepare_profile_directory(
                    self.profile_data_dir, "WPE profile data directory"
                )
                cache_dir = self._prepare_profile_directory(
                    self.profile_cache_dir, "WPE profile cache directory"
                )
                if data_dir == cache_dir:
                    raise ValueError("WPE profile data and cache directories must be distinct")
                env["BOJANGLES_WPE_DATA_DIR"] = data_dir
                env["BOJANGLES_WPE_CACHE_DIR"] = cache_dir
            else:
                env.pop("BOJANGLES_WPE_DATA_DIR", None)
                env.pop("BOJANGLES_WPE_CACHE_DIR", None)
            # An interactive VT belongs to the trusted control panel. Keep
            # native/WebProcess diagnostics in a session-scoped temporary file
            # so child warnings cannot overwrite the operator's input.
            if sys.stdin.isatty() and sys.stdout.isatty():
                self._native_diagnostics = tempfile.TemporaryFile()
            pass_fds = [child.fileno(), resource_child.fileno(), fb.buffer_fd]
            self._process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self._native_diagnostics,
                close_fds=True,
                pass_fds=tuple(pass_fds),
                env=env,
            )
        except Exception:
            if self._native_diagnostics is not None:
                self._native_diagnostics.close()
                self._native_diagnostics = None
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()
            if resource_parent is not None:
                resource_parent.close()
            if resource_child is not None:
                resource_child.close()
            self._context = None
            self._lifecycle = RendererLifecycle.FAILED
            if self._profile_lease is not None:
                self._profile_lease.release()
                self._profile_lease = None
            raise
        child.close()
        resource_child.close()
        self._resource_sock = resource_parent
        self._sock = parent
        try:
            self._resources = ThreadPoolExecutor(max_workers=8, thread_name_prefix="bojangles-resource")
            self._reader = threading.Thread(
                target=self._reader_loop,
                name="bojangles-wpe-ipc",
                daemon=False,
            )
            self._reader.start()
        except Exception:
            self._reader = None
            self.stop()
            self._lifecycle = RendererLifecycle.FAILED
            raise
        if not self._ready.wait(15.0):
            self.stop()
            self._lifecycle = RendererLifecycle.FAILED
            raise TimeoutError("native WPE frontend did not become ready")
        if self._lifecycle is RendererLifecycle.FAILED:
            self.stop()
            self._lifecycle = RendererLifecycle.FAILED
            raise WPEProtocolError("native WPE channels failed during startup")
        self._lifecycle = RendererLifecycle.RUNNING
        from bojangles.diagnostics import record
        record("wpe_start", document_id=context.document.document_id)
        if self._drm_mode:
            self._set_drm(True)

    def _queue_navigation_failure(self, uri: str, detail: str, *, navigation_cause: str = "", target: str = "") -> None:
        from bojangles.diagnostics import record
        document_id = self._context.document.document_id if self._context else ""
        with self._navigation_lock:
            cancelled = getattr(self._navigation_local, "cancelled", None)
            if cancelled is not None and cancelled.is_set():
                return
            self._queue(RendererEvent(
                RendererEventKind.NAVIGATION_FAILED,
                document_id,
                uri=uri,
                detail=detail, navigation_cause=navigation_cause, link_uri=target,
            ))
            if cancelled is not None:
                cancelled.set()
        record("navigation_failure", url=uri, document_id=document_id, detail=detail)

    def _authorize_document(self, url: str, *, initiator_url: str) -> tuple[bool, str]:
        assert self._context is not None
        gateway = WPEGatewayRenderer(
            self._context.document.document_id,
            self._context.request_channel,
        )
        decision = gateway.authorize(WPERequestIntent(
            request_id=self._new_request_id(),
            document_id=self._context.document.document_id,
            url=url,
            resource_type=ResourceType.DOCUMENT.value,
            initiator_url=initiator_url,
        ))
        return decision.allow, decision.reason

    def _report_media(self, document_id: str, fetched, *, source: str) -> None:
        """Turn trusted fetched bytes into hints, never playback authority."""
        kind = classify(fetched.url, fetched.mime_type, fetched.body)
        mime = fetched.mime_type.split(";", 1)[0].strip().lower()
        if kind is MediaKind.PDF or mime.startswith(("text/javascript", "application/javascript", "image/", "font/", "text/css")):
            kind = None
        if kind is MediaKind.FILE and (
            mime in {"video/mp2t", "video/iso.segment"}
            or urlsplit(fetched.url).path.lower().rsplit(".", 1)[-1]
            in {"ts", "m4s", "cmfv", "cmfa"}
        ):
            # These belong to a manifest, not the page-media picker/player.
            kind = None
        if kind is not None:
            protection = ""
            if kind is MediaKind.HLS:
                child_playlists = hls_manifest_references(fetched.url, fetched.body)
                if child_playlists:
                    self.media_candidates.suppress(document_id, child_playlists)
                protection = hls_protection(fetched.body)
            elif kind is MediaKind.DASH:
                protection = dash_protection(fetched.body)
            candidate = self.media_candidates.report(
                document_id, fetched.url, kind, mime_type=fetched.mime_type,
                source=source, activated=source == "document",
                captions=manifest_captions(fetched.url, kind, fetched.body),
                protection=protection,
            )
            if candidate is not None:
                from bojangles.diagnostics import record
                record("media", url=candidate.uri, kind=candidate.kind.value,
                       mime_type=candidate.mime_type, source=source)
                self._queue(RendererEvent(
                    RendererEventKind.MEDIA_CANDIDATE, document_id,
                    uri=candidate.uri, detail=candidate.kind.value,
                    protected_media=bool(candidate.protection),
                    drm_scheme=candidate.protection or None,
                    mime_type=candidate.mime_type,
                ))
        if source == "document" and fetched.mime_type.split(";", 1)[0].strip().lower() in {
            "text/html", "application/xhtml+xml",
        }:
            for uri, hint_kind, hint_mime, tracks in html_media_hints(fetched.url, fetched.body):
                candidate = self.media_candidates.report(
                    document_id, uri, hint_kind, mime_type=hint_mime,
                    source="html_hint", captions=tracks,
                )
                if candidate is not None:
                    from bojangles.diagnostics import record
                    record("media", url=candidate.uri, kind=candidate.kind.value,
                           mime_type=candidate.mime_type, source="html_hint")
                    self._queue(RendererEvent(
                        RendererEventKind.MEDIA_CANDIDATE, document_id,
                        uri=candidate.uri, detail=candidate.kind.value,
                        mime_type=candidate.mime_type,
                    ))

    def fetch_pdf(self, uri: str) -> bytes:
        """Fetch one broker-authorized PDF through the existing trusted transport."""
        cookie_options = {}
        if self._request is not None and getattr(self._transport, "allow_first_party_cookies", False):
            cookie_options = {
                "send_session_cookies": True,
                "store_session_cookies": True,
                "cookie_site_url": self._request.uri,
            }
        fetched = self._transport.fetch_once(uri, **cookie_options)
        if fetched.status < 200 or fetched.status >= 300:
            raise WPETransportError(f"PDF HTTP status denied: {fetched.status}")
        if classify(fetched.url, fetched.mime_type, fetched.body) is not MediaKind.PDF:
            raise WPETransportError("authorized PDF response did not contain a PDF")
        return fetched.body

    def _inline_embedded_pdfs(self, request: NavigationRequest, fetched):
        if self._native_pdf_viewer:
            return fetched
        mime = fetched.mime_type.split(";", 1)[0].strip().lower()
        if mime not in {"text/html", "application/xhtml+xml"}:
            return fetched

        gateway = WPEGatewayRenderer(
            request.document_id,
            self._context.request_channel,
        )

        def fetch_inline_pdf(uri: str) -> bytes:
            decision = gateway.authorize(WPERequestIntent(
                request_id=self._new_request_id(),
                document_id=request.document_id,
                url=uri,
                resource_type=ResourceType.OTHER.value,
                initiator_url=request.uri,
            ))
            if not decision.allow:
                raise WPETransportError(
                    f"inline PDF denied by resource policy: {decision.reason}"
                )
            return self.fetch_pdf(uri)

        body, count = inline_pdf_embeds(fetched.url, fetched.body, fetch_inline_pdf)
        if count == 0 or body == fetched.body:
            return fetched
        return type(fetched)(
            fetched.url,
            fetched.status,
            fetched.mime_type,
            fetched.encoding,
            body,
            fetched.headers,
        )

    def _send_fetched_document(self, request: NavigationRequest, fetched) -> None:
        required = (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_SEAL",
            "F_SEAL_SHRINK",
            "F_SEAL_GROW",
            "F_SEAL_WRITE",
        )
        if not hasattr(os, "MFD_ALLOW_SEALING") or any(
            not hasattr(fcntl, name) for name in required
        ):
            raise RuntimeError("sealed memfd support is required for WPE")
        flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        fd = os.memfd_create("bojangles-wpe-document", flags)
        try:
            view = memoryview(fetched.body)
            written = 0
            while written < len(view):
                count = os.write(fd, view[written:])
                if count <= 0:
                    raise OSError("short write to WPE document memfd")
                written += count
            seals = (
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE
            )
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            applied = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            if applied & seals != seals:
                raise RuntimeError("WPE document memfd seal verification failed")
            response_headers = tuple(getattr(fetched, "headers", ()) or ())
            if response_headers:
                if len(response_headers) > MAX_HEADER_COUNT:
                    raise RuntimeError("WPE document response header count exceeds protocol bound")
                header_bytes = sum(
                    len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
                    for name, value in response_headers
                )
                if header_bytes > MAX_RESPONSE_HEADER_BYTES:
                    raise RuntimeError("WPE document response headers exceed protocol bound")
                fields = [
                    request.document_id,
                    request.uri,
                    fetched.mime_type,
                    fetched.encoding,
                    str(len(fetched.body)),
                    str(int(fetched.status)),
                    str(len(response_headers)),
                ]
                for name, value in response_headers:
                    fields.extend((str(name), str(value)))
                payload = pack_strings(*fields)
                kind = NativeMessage.LOAD_DATA_HEADERS
            else:
                payload = pack_strings(
                    request.document_id,
                    request.uri,
                    fetched.mime_type,
                    fetched.encoding,
                    str(len(fetched.body)),
                )
                kind = NativeMessage.LOAD_DATA
            from bojangles.popup_rules import stylesheet
            css = stylesheet(request.uri)
            self._send(NativePacket(NativeMessage.SITE_RULES,
                payload=pack_strings(request.document_id, request.uri, css)))
            self._send(NativePacket(kind, payload=payload), fd)
        finally:
            os.close(fd)

    def _set_drm(self, enabled: bool) -> None:
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        self._send(NativePacket(
            NativeMessage.SET_DRM,
            payload=b"1" if enabled else b"0",
        ))
        self._drm_enabled = bool(enabled)

    def navigation_state(self, url: str, method: str = "GET") -> bytes | None:
        """Opaque, process-local state of cookies the trusted GET will send."""
        from .browser_cookies import BrowserSessionCookieJar
        jar = getattr(self._transport, "session_cookies", None)
        if method != "GET" or not isinstance(jar, BrowserSessionCookieJar):
            return None
        # Match fetch_top_level's actual request scope. This digest stays on the
        # trusted side, has no persistent identity, and carries no cookie values.
        try:
            header = jar.cookie_header(url, site_for_cookies=url,
                                       top_level_navigation=True, method=method)
            return hmac.digest(_NAVIGATION_STATE_KEY, header.encode("utf-8"), "sha256")
        except Exception:
            return None

    def load(self, request: NavigationRequest) -> None:
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        if self._context is None or request.document_id != self._context.document.document_id:
            raise RuntimeError("navigation request crossed frontend document boundary")
        if self._drm_enabled and not self._drm_mode:
            self._set_drm(False)
        self._request = request
        self.initial_navigation_state = (request.uri, request.method,
                                         self.navigation_state(request.uri, request.method))
        if request.method == "POST" and len(request.body) > MAX_REQUEST_BODY_BYTES:
            self._queue_navigation_failure(request.uri, "top-level POST body exceeds trusted bound")
            return

        allowed, reason = self._authorize_document(
            request.uri,
            initiator_url=self._context.document.uri,
        )
        if not allowed:
            self._queue_navigation_failure(request.uri, f"WPE gateway denied document: {reason}")
            return

        # Network I/O must never occupy the frontend input thread. Each load
        # has its own cancellation token so Stop/Back and replacement loads
        # cannot be undone by a late response from the trusted transport.
        self._cancel_navigation()
        cancelled = threading.Event()
        with self._navigation_lock:
            self._navigation_cancel = cancelled
        context = self._context
        budget = float(getattr(self._transport, "timeout", 15.0))
        request_timeout = getattr(self._transport, "request_timeout", None)
        if request.method == "POST" and callable(request_timeout):
            budget = float(request_timeout(request.body))

        def expired():
            with self._navigation_lock:
                if cancelled.is_set():
                    return
                self._queue(RendererEvent(
                    RendererEventKind.NAVIGATION_FAILED, request.document_id,
                    uri=request.uri, detail="Page load timed out; use Back or try another address"))
                cancelled.set()
            from bojangles.diagnostics import record
            record("navigation_failure", url=request.uri)

        timer = threading.Timer(budget, expired)
        timer.daemon = True

        def fetch():
            self._navigation_local.cancelled = cancelled
            try:
                self._load_document(request, context, cancelled)
            except Exception as exc:
                self._queue_navigation_failure(request.uri, str(exc))
            finally:
                cancelled.set()
                timer.cancel()

        worker = threading.Thread(target=fetch, name="bojangles-navigation", daemon=True)
        timer.start()
        worker.start()

    def _cancel_navigation(self) -> None:
        with self._navigation_lock:
            self._navigation_cancel.set()

    def _load_document(self, request, context, cancelled) -> None:
        try:
            fetch_top_level = getattr(self._transport, "fetch_top_level", None)
            if request.method == "POST":
                trusted_headers = self._transport.sanitize_request_headers(request.headers)
                initiator = request.initiator_url
                if initiator:
                    trusted_headers = tuple(
                        (name, value) for name, value in trusted_headers
                        if name.casefold() != "origin"
                    ) + (("Origin", self._transport.trusted_origin_header(initiator)),)
                fetched = self._transport.fetch_once(
                    request.uri, method="POST", body=request.body,
                    request_headers=trusted_headers,
                    send_session_cookies=True, store_session_cookies=True,
                    cookie_site_url=initiator or request.uri,
                    top_level_navigation=True,
                    **({"_trusted_referer": initiator} if initiator else {}),
                    **({"_cancelled": cancelled} if getattr(self._transport, "supports_upload_cancellation", False) else {}),
                )
            else:
                fetched = (
                    fetch_top_level(request.uri)
                    if callable(fetch_top_level)
                    else self._transport.fetch_once(
                        request.uri,
                        **({"offer_download": True} if isinstance(self._transport, WPEAllowedDataTransport) else {}),
                    )
                )
        except WPEDownloadOffered as offer:
            self._queue(RendererEvent(
                RendererEventKind.DOWNLOAD_REQUESTED, request.document_id,
                uri=offer.url, detail=offer.suggested_filename,
            ))
            return
        except WPERedirectRequired as redirect:
            if cancelled.is_set():
                return
            redirect_allowed, redirect_reason = self._authorize_document(
                redirect.target,
                initiator_url=context.document.uri,
            )
            if redirect_allowed and request.method == "POST":
                if redirect.status in {307, 308}:
                    self._queue(RendererEvent(
                        RendererEventKind.POST_NAVIGATION_REQUESTED,
                        request.document_id, uri=redirect.target,
                        body=request.body, headers=request.headers, navigation_cause="server",
                    ))
                    return
                if redirect.status in {301, 302, 303}:
                    self._queue_navigation_failure(
                        request.uri,
                        f"redirect requires new frontend document authority: {redirect.target}", navigation_cause="server", target=redirect.target,
                    )
                    return
            if redirect_allowed:
                detail = f"redirect requires new frontend document authority: {redirect.target}"
            else:
                detail = f"redirect denied by WPE gateway: {redirect_reason}"
            self._queue_navigation_failure(request.uri, detail, navigation_cause="server" if redirect_allowed else "", target=redirect.target if redirect_allowed else "")
            return
        except WPETransportError as exc:
            self._queue_navigation_failure(request.uri, str(exc))
            return

        if cancelled.is_set():
            return
        if not fetched.body:
            self._queue_navigation_failure(request.uri, f"Server returned an empty document (HTTP {fetched.status})")
            return
        fetched = self._inline_embedded_pdfs(request, fetched)
        with self._navigation_lock:
            if cancelled.is_set():
                return
        self._report_media(request.document_id, fetched, source="document")
        self._send_fetched_document(request, fetched)
        cancelled.set()

    def resize(self, viewport: Viewport) -> None:
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        self._send(NativePacket(
            NativeMessage.RESIZE,
            payload=struct.pack("!II", viewport.width, viewport.height),
        ))

    def resize_framebuffer(self, viewport: Viewport, framebuffer) -> None:
        """Replace the frontend-owned pixel plane without restarting the page."""
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        if (framebuffer.width, framebuffer.height) != (viewport.width, viewport.height):
            raise ValueError("viewport and framebuffer dimensions must match")
        if (framebuffer.pixel_format != self._context.framebuffer.pixel_format
                or framebuffer.buffer_fd is None or framebuffer.stride != viewport.width * 4
                or framebuffer.byte_length != framebuffer.stride * viewport.height
                or viewport.width > 16384 or viewport.height > 16384
                or framebuffer.byte_length > 512 * 1024 * 1024):
            raise ValueError("invalid resize framebuffer")
        self._send(NativePacket(
            NativeMessage.RESIZE,
            payload=struct.pack("!III", viewport.width, viewport.height, framebuffer.stride),
        ), fd=framebuffer.buffer_fd)

    def set_focused(self, focused: bool) -> None:
        """Hand native keyboard focus to or from the WPE view."""
        if self._lifecycle is not RendererLifecycle.RUNNING:
            return
        try:
            self.input({"kind": "focus", "focused": bool(focused)})
        except (OSError, RuntimeError):
            # A reader failure may race the lifecycle check above.
            # _send/reader has already published the failure for recovery.
            return

    def input(self, event: Any) -> None:
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        if isinstance(event, str):
            payload = pack_strings("text", event)
        elif isinstance(event, dict):
            kind = str(event.get("kind", ""))
            if kind not in {"key", "text", "pointer", "button", "scroll", "focus"}:
                raise ValueError("unsupported WPE input event kind")
            fields = [kind] + [
                f"{key}={value}"
                for key, value in sorted(event.items())
                if key != "kind"
            ]
            payload = pack_strings(*fields)
        else:
            raise TypeError("WPE input must be text or a typed mapping")
        # Only physical frontend input can grant one short-lived form intent.
        if isinstance(event, dict) and event.get("pressed") is True and (
            (event.get("kind") == "key" and event.get("key") in {"Enter", "Return", "KP_Enter"})
            or (event.get("kind") == "button" and event.get("button") == 1)
        ):
            self._form_gesture = (self._context.document.document_id, time.monotonic())
        self._send(NativePacket(NativeMessage.INPUT, payload=payload))

    def _form_navigation_cause(self, url, initiator):
        """Consume one document-bound gesture; cross-origin actions still prompt."""
        gesture = getattr(self, "_form_gesture", None)
        self._form_gesture = None
        if not gesture or self._context is None or self._request is None:
            return ""
        document_id, timestamp = gesture
        if document_id != self._context.document.document_id or not 0 <= time.monotonic() - timestamp <= 2:
            return ""
        from bojangles.popup_rules import origin, RuleError
        try:
            if initiator == self._request.uri and origin(url) == origin(initiator):
                return "user-form"
        except RuleError:
            pass
        return ""

    def _translation_request(self, kind, values):
        """Fixed operations on CONTROL; never send JavaScript from the host."""
        import json
        if self._context is None or self._lifecycle is not RendererLifecycle.RUNNING:
            raise WPEProtocolError("page is not ready")
        if b"WPE_TRANSLATION_REJECTED" not in Path(self._resolve_executable()).read_bytes():
            raise WPEProtocolError("This runtime needs the in-page translation update")
        document_id = self._context.document.document_id
        encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 196608:
            raise WPEProtocolError("translation exceeds the page text limit")
        packet = self._request_reply(kind, pack_strings(document_id, encoded), timeout=10)
        if packet.kind is not NativeMessage.TRANSLATION_RESULT:
            raise WPEProtocolError("invalid translation reply")
        fields = unpack_strings(packet.payload, 2)
        if len(fields) != 2 or fields[0] != document_id or len(fields[1].encode("utf-8")) > 196608:
            raise WPEProtocolError("invalid translation document reply")
        try:
            result = json.loads(fields[1])
        except (ValueError, TypeError) as exc:
            raise WPEProtocolError("invalid translation data") from exc
        if not isinstance(result, dict):
            raise WPEProtocolError("invalid translation data")
        if "error" in result:
            raise WPEProtocolError(str(result["error"])[:256])
        return result

    def extract_translation(self, token):
        result = self._translation_request(NativeMessage.TRANSLATION_EXTRACT, {"token": token})
        texts, languages = result.get("texts"), result.get("languages")
        if (result.get("token") != token or not isinstance(texts, list) or
                not isinstance(languages, list) or len(texts) != len(languages) or len(texts) > 2000 or
                any(not isinstance(t, str) or "\0" in t or len(t.encode("utf-8")) > 4096 for t in texts) or
                sum(len(t.encode("utf-8")) for t in texts) > 65536 or
                any(not isinstance(lang, str) or len(lang) > 64 for lang in languages)):
            try:
                self.restore_translation(token)
            except (RuntimeError, ValueError, TimeoutError):
                pass
            raise WPEProtocolError("invalid or oversized page text")
        return tuple(texts), tuple(languages)

    def apply_translation(self, token, texts):
        return self._translation_request(NativeMessage.TRANSLATION_APPLY, {"token": token, "texts": texts})

    def restore_translation(self, token):
        return self._translation_request(NativeMessage.TRANSLATION_RESTORE, {"token": token})

    def image_data(self, menu_id: int, document_id: str) -> bytes:
        """Read the selected loaded resource without re-fetching or re-encoding it."""
        if self._context is None or self._context.document.document_id != document_id:
            raise ValueError("The image page has changed")
        fd = os.memfd_create("bojangles-save-image", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            packet = self._request_reply(NativeMessage.IMAGE_DATA_REQUEST,
                pack_strings(document_id, str(menu_id)), timeout=15.0, fd=fd)
            fields = unpack_strings(packet.payload, 2)
            if packet.kind is not NativeMessage.IMAGE_DATA_RESULT or len(fields) != 2 or fields[0] != document_id:
                raise WPEProtocolError("The original image data is unavailable")
            size = int(fields[1])
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            if not 8 <= size <= 64 * 1024 * 1024 or os.fstat(fd).st_size != size or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
                raise WPEProtocolError("The original image data is unavailable or exceeds 64 MiB")
            data = os.pread(fd, size, 0)
            if len(data) != size:
                raise WPEProtocolError("The original image data is incomplete")
            return data
        finally:
            os.close(fd)

    def print_pdf(self, paper: str = "letter") -> bytes:
        import fcntl
        if paper not in {"letter", "a4"} or self._context is None:
            raise ValueError("invalid print request")
        if b"WPE_PRINT_PDF_REJECTED" not in Path(self._resolve_executable()).read_bytes():
            raise WPEProtocolError("Restart BoJangles to load printing support")
        document_id = self._context.document.document_id
        fd = os.memfd_create("bojangles-print", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            packet = self._request_reply(NativeMessage.PRINT_PDF_REQUEST,
                                         pack_strings(document_id, paper), timeout=60.0, fd=fd)
            if packet.kind is not NativeMessage.PRINT_PDF_RESULT:
                raise WPEProtocolError("invalid print reply")
            fields = unpack_strings(packet.payload, 2)
            if len(fields) != 2 or fields[0] != document_id:
                raise WPEProtocolError("page changed or print failed")
            size = int(fields[1])
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            if not 8 <= size <= 64 * 1024 * 1024 or os.fstat(fd).st_size != size or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
                raise WPEProtocolError("invalid or incomplete print data")
            chunks = []
            offset = 0
            while offset < size:
                chunk = os.pread(fd, min(65536, size - offset), offset)
                if not chunk:
                    raise WPEProtocolError("incomplete print data")
                chunks.append(chunk)
                offset += len(chunk)
            pdf = b"".join(chunks)
            if not pdf.startswith(b"%PDF-"):
                raise WPEProtocolError("print output was not PDF")
            return pdf
        finally:
            os.close(fd)

    def export_page(self, format: str) -> bytes:
        import fcntl
        if format not in {"png", "mhtml"} or self._context is None:
            raise ValueError("invalid print request")
        if b"WPE_PAGE_EXPORT_REJECTED" not in Path(self._resolve_executable()).read_bytes():
            raise WPEProtocolError("Snapshot support requires a rebuilt WPE broker")
        document_id = self._context.document.document_id
        fd = os.memfd_create("bojangles-print", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            packet = self._request_reply(NativeMessage.PAGE_EXPORT_REQUEST,
                                         pack_strings(document_id, format), timeout=60.0, fd=fd)
            if packet.kind is not NativeMessage.PAGE_EXPORT_RESULT:
                raise WPEProtocolError("invalid print reply")
            fields = unpack_strings(packet.payload, 2)
            if len(fields) != 2 or fields[0] != document_id:
                raise WPEProtocolError("page changed or print failed")
            size = int(fields[1])
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            if not 8 <= size <= 64 * 1024 * 1024 or os.fstat(fd).st_size != size or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
                raise WPEProtocolError("invalid or incomplete print data")
            chunks = []
            offset = 0
            while offset < size:
                chunk = os.pread(fd, min(65536, size - offset), offset)
                if not chunk:
                    raise WPEProtocolError("incomplete print data")
                chunks.append(chunk)
                offset += len(chunk)
            pdf = b"".join(chunks)
            return pdf
        finally:
            os.close(fd)

    def copy_selection(self) -> str:
        """Return the current page selection after a trusted frontend gesture."""
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        packet = self._request_reply(
            NativeMessage.CLIPBOARD_COPY_REQUEST,
            timeout=2.0,
        )
        if packet.kind is NativeMessage.ERROR:
            raise WPEProtocolError(
                packet.payload.decode("utf-8", errors="replace")
                or "WPE clipboard copy failed"
            )
        if packet.kind is not NativeMessage.CLIPBOARD_COPY_RESULT:
            raise WPEProtocolError("unexpected WPE clipboard response")
        if len(packet.payload) > 65536:
            raise WPEProtocolError("WPE clipboard response exceeds trusted bound")
        try:
            return packet.payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise WPEProtocolError("WPE clipboard response is not UTF-8") from exc

    def cut_rich_selection(self) -> tuple[str, str]:
        return self._copy_or_cut_rich_selection(cut=True)

    def copy_rich_selection(self) -> tuple[str, str]:
        return self._copy_or_cut_rich_selection(cut=False)

    def _copy_or_cut_rich_selection(self, *, cut: bool) -> tuple[str, str]:
        """Copy WebKit's own plain-text and HTML representations."""
        packet = self._request_reply(NativeMessage.CLIPBOARD_CUT_RICH if cut else NativeMessage.CLIPBOARD_COPY_RICH, timeout=2.0)
        if packet.kind is not NativeMessage.CLIPBOARD_COPY_RICH_RESULT:
            raise WPEProtocolError("rich clipboard copy failed")
        fields = packet.payload.split(b"\0")
        if len(fields) != 3 or fields[-1] or len(fields[0]) > 65536 or len(fields[1]) > 524288:
            raise WPEProtocolError("invalid rich clipboard response")
        return fields[0].decode("utf-8"), fields[1].decode("utf-8")

    def paste_rich(self, text: str, html: str) -> None:
        """Offer standard text and HTML through the local native clipboard."""
        if self._lifecycle is not RendererLifecycle.RUNNING or self._context is None:
            raise RuntimeError("renderer is not running")
        if len(text.encode("utf-8")) > 65536 or len(html.encode("utf-8")) > 524288 or "\0" in text + html:
            raise ValueError("invalid or oversized rich clipboard")
        if not text and not html:
            return
        packet = self._request_reply(NativeMessage.CLIPBOARD_PASTE_RICH,
            pack_strings(self._context.document.document_id, text, html))
        if packet.kind is not NativeMessage.CLIPBOARD_PASTE_RESULT or packet.payload != b"1":
            raise WPEProtocolError("rich clipboard paste rejected")

    def paste_png(self, png: bytes) -> None:
        """Send one explicit operator clipboard image through sealed CONTROL data."""
        if self._lifecycle is not RendererLifecycle.RUNNING or self._context is None:
            raise RuntimeError("renderer is not running")
        png = bytes(png)
        if not png.startswith(b"\x89PNG\r\n\x1a\n") or not 24 <= len(png) <= 16 * 1024 * 1024:
            raise ValueError("invalid or oversized clipboard PNG")
        if b"WPE_CLIPBOARD_PASTE_PNG_REJECTED" not in Path(self._resolve_executable()).read_bytes():
            raise RuntimeError("this runtime does not yet support picture paste")
        fd = os.memfd_create("bojangles-clipboard-png", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            offset = 0
            while offset < len(png):
                written = os.write(fd, png[offset:])
                if written <= 0:
                    raise OSError("short clipboard image write")
                offset += written
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            result = self._request_reply(
                NativeMessage.CLIPBOARD_PASTE_PNG,
                pack_strings(self._context.document.document_id, str(len(png))), fd=fd)
            if result.kind is not NativeMessage.CLIPBOARD_PASTE_RESULT or result.payload != b"1":
                raise WPEProtocolError("picture paste rejected by renderer")
        finally:
            os.close(fd)

    def paste_text(self, text: str) -> None:
        """Paste trusted frontend plain text into the focused page target."""
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        payload = str(text).encode("utf-8", errors="strict")
        if not payload:
            return
        if len(payload) > 65536:
            raise ValueError("system clipboard text exceeds trusted bound")
        if b"\0" in payload:
            raise ValueError("system clipboard text contains NUL")
        self._send(NativePacket(NativeMessage.CLIPBOARD_PASTE_TEXT, payload=payload))

    def fill_credentials(self, document_id: str, origin: str,
                         username: str, password: str) -> bool:
        """Fill one unambiguous HTTPS login form through named CONTROL IPC."""
        if self._lifecycle is not RendererLifecycle.RUNNING or self._context is None:
            raise RuntimeError("renderer is not running")
        if document_id != self._context.document.document_id:
            raise WPEProtocolError("credential fill crossed frontend document boundary")
        values = (document_id, origin, username, password)
        encoded = [str(value).encode("utf-8", errors="strict") for value in values]
        if any(not value or b"\0" in value for value in encoded):
            raise ValueError("credential fill field exceeds trusted bound")
        if (
            len(encoded[0]) > 4096
            or len(encoded[1]) > 2048
            or len(encoded[2]) > 1024
            or len(encoded[3]) > 4096
        ):
            raise ValueError("credential fill field exceeds trusted bound")
        packet = self._request_reply(
            NativeMessage.CREDENTIAL_FILL,
            pack_strings(*values),
            timeout=3.0,
        )
        if packet.kind is not NativeMessage.CREDENTIAL_FILL_RESULT or packet.payload not in {b"0", b"1"}:
            raise WPEProtocolError("unexpected WPE credential-fill response")
        return packet.payload == b"1"

    def snapshot(self) -> RendererSnapshot:
        if self._context is None or self._request is None:
            return RendererSnapshot(document_id="", uri="")
        packet = self._request_reply(NativeMessage.SNAPSHOT)
        if packet.kind is not NativeMessage.SNAPSHOT_RESULT:
            raise WPEProtocolError("unexpected WPE snapshot response")
        snapshot = _snapshot_from_payload(packet.payload)
        if (
            snapshot.document_id != self._context.document.document_id
            or snapshot.uri != self._request.uri
        ):
            raise WPEProtocolError("WPE snapshot crossed frontend document boundary")
        return snapshot

    def cli_control(self, kind: NativeMessage, url: str = "") -> str | None:
        """Trusted operator control; replies are delivered by the sole IPC reader."""
        allowed = {NativeMessage.NAV_BACK, NativeMessage.NAV_FORWARD,
                   NativeMessage.NAV_RELOAD, NativeMessage.NAV_STOP,
                   NativeMessage.NAVIGATE, NativeMessage.STATE_REQUEST,
                   NativeMessage.TERMINATE}
        if kind not in allowed:
            raise ValueError("unsupported CLI control message")
        if self._lifecycle is not RendererLifecycle.RUNNING:
            raise RuntimeError("renderer is not running")
        if kind in {NativeMessage.NAV_STOP, NativeMessage.NAV_BACK,
                    NativeMessage.NAV_FORWARD, NativeMessage.NAV_RELOAD,
                    NativeMessage.NAVIGATE, NativeMessage.TERMINATE}:
            self._cancel_navigation()
        payload = url.encode("utf-8") if kind is NativeMessage.NAVIGATE else b""
        if kind is NativeMessage.NAVIGATE and (not payload or len(payload) > 8192 or b"\0" in payload):
            raise ValueError("CLI navigation URL exceeds control bound")
        if kind is NativeMessage.STATE_REQUEST:
            reply = self._request_reply(kind)
            if reply.kind is not NativeMessage.STATE_RESULT:
                raise WPEProtocolError("unexpected WPE state response")
            return reply.payload.decode("utf-8", errors="replace")
        self._send(NativePacket(kind, payload=payload))
        return None

    def restore(self, snapshot: RendererSnapshot) -> bool:
        if self._context is None or self._request is None:
            return False
        if (
            snapshot.document_id != self._context.document.document_id
            or snapshot.uri != self._request.uri
        ):
            return False
        packet = self._request_reply(NativeMessage.RESTORE, _snapshot_payload(snapshot))
        if packet.kind is not NativeMessage.RESTORE_RESULT:
            raise WPEProtocolError("unexpected WPE restore response")
        return packet.payload == b"1"

    def _resource_gateway(self) -> WPEGatewayRenderer:
        if self._context is None:
            raise RuntimeError("WPE resource request has no frontend context")
        return WPEGatewayRenderer(
            self._context.document.document_id,
            self._context.request_channel,
        )

    def _send_resource_denial(self, request_id: int, category: str, reason: str) -> None:
        from bojangles.diagnostics import record
        record("resource_denied", request_id=request_id, category=category,
               reason=reason if "://" not in reason else "[redacted]")
        self._send(NativePacket(
            NativeMessage.RESOURCE_DECISION,
            request_id,
            pack_strings("0", category, reason),
        ))

    def _send_fetched_resource(self, request_id: int, fetched) -> None:
        required = (
            "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_SEAL",
            "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE",
        )
        if not hasattr(os, "MFD_ALLOW_SEALING") or any(
            not hasattr(fcntl, name) for name in required
        ):
            self._send_resource_denial(request_id, "security", "sealed memfd unavailable")
            return
        fd = os.memfd_create(
            "bojangles-wpe-resource",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        try:
            view = memoryview(fetched.body)
            offset = 0
            while offset < len(view):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OSError("short write to WPE resource memfd")
                offset += written
            seals = (
                fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            )
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
                raise RuntimeError("WPE resource memfd seal verification failed")

            response_headers = tuple(getattr(fetched, "headers", ()) or ())
            if len(response_headers) > MAX_HEADER_COUNT:
                raise RuntimeError("WPE response header count exceeds protocol bound")
            header_bytes = sum(
                len(str(name).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
                for name, value in response_headers
            )
            if header_bytes > MAX_RESPONSE_HEADER_BYTES:
                raise RuntimeError("WPE response headers exceed protocol bound")
            fields = [
                fetched.url,
                fetched.mime_type,
                fetched.encoding,
                str(fetched.status),
                str(len(fetched.body)),
            ]
            # Keep the Stage 5B five-field envelope for test transports that do
            # not provide response headers. Real trusted transport uses Stage 5C.
            if response_headers:
                fields.append(str(len(response_headers)))
                for name, value in response_headers:
                    fields.extend((str(name), str(value)))
            payload = pack_strings(*fields)
            self._send(NativePacket(NativeMessage.RESOURCE_DATA, request_id, payload), fd)
        except Exception as exc:
            self._send_resource_denial(request_id, "transport", str(exc))
        finally:
            os.close(fd)

    def _read_request_body(self, fd: int | None, expected_length: int, method: str) -> bytes:
        if method in {"GET", "OPTIONS"}:
            if expected_length != 0 or fd is not None:
                if fd is not None:
                    os.close(fd)
                raise WPEProtocolError("GET resource carried a request body descriptor")
            return b""
        if method != "POST":
            if fd is not None:
                os.close(fd)
            raise WPEProtocolError("unsupported WPE resource method")
        if fd is None:
            raise WPEProtocolError("POST resource body descriptor is missing")
        required = (
            "F_GET_SEALS", "F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE",
        )
        try:
            if any(not hasattr(fcntl, name) for name in required):
                raise WPEProtocolError("request-body seal verification unavailable")
            seals = (
                fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            )
            actual = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            if actual & seals != seals:
                raise WPEProtocolError("WPE request body memfd is not immutable")
            size = os.fstat(fd).st_size
            if expected_length < 0 or expected_length > MAX_REQUEST_BODY_BYTES or size != expected_length:
                raise WPEProtocolError("WPE request body length mismatch")
            if expected_length > MAX_MEMORY_REQUEST_BODY_BYTES:
                return mmap.mmap(fd, expected_length, access=mmap.ACCESS_READ)
            chunks = bytearray()
            offset = 0
            while offset < expected_length:
                block = os.pread(fd, min(65536, expected_length - offset), offset)
                if not block:
                    raise WPEProtocolError("short read from WPE request body memfd")
                chunks.extend(block)
                offset += len(block)
            return bytes(chunks)
        finally:
            os.close(fd)

    def _dispatch_resource_request(self, packet: NativePacket, received_fd: int | None) -> None:
        pool = self._resources
        if pool is None or not self._resource_slots.acquire(blocking=False):
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "resource", "bounded resource queue is full")
            return
        try:
            pool.submit(self._run_resource_request, packet, received_fd)
        except Exception:
            self._resource_slots.release()
            if received_fd is not None:
                os.close(received_fd)
            raise

    def _run_resource_request(self, packet: NativePacket, received_fd: int | None) -> None:
        try:
            if self._reader_stop.is_set():
                if received_fd is not None:
                    os.close(received_fd)
                return
            self._handle_resource_request(packet, received_fd)
        except Exception:
            if not self._reader_stop.is_set():
                try:
                    self._send_resource_denial(packet.request_id, "transport", "resource transport failed")
                except (OSError, RuntimeError):
                    pass
        finally:
            self._resource_slots.release()

    def _handle_resource_request(self, packet: NativePacket, received_fd: int | None) -> None:
        if packet.request_id <= 0 or self._context is None or self._request is None:
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "security", "resource request has no active document")
            return
        try:
            document_id, url, resource_type, initiator_url, method, request_headers, body_length, statistics_group = (
                _resource_request_from_payload(packet.payload, with_statistics=True)
            )
        except Exception:
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "security", "malformed WPE resource request")
            return
        if document_id != self._context.document.document_id:
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "security", "resource document authority mismatch")
            return
        if initiator_url != self._request.uri:
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "security", "resource initiator authority mismatch")
            return
        if method not in {"GET", "POST", "OPTIONS"}:
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "security", "WPE Stage 5D allows GET/POST resources only")
            return
        try:
            body_fd = received_fd
            received_fd = None
            request_body = self._read_request_body(body_fd, body_length, method)
            from .wpe_transport import sanitize_application_headers
            trusted_headers = sanitize_application_headers(request_headers)
            network_initiator = dict((str(k).casefold(), str(v)) for k, v in request_headers).get("sec-bojangles-initiator", initiator_url)
            if network_initiator != initiator_url:
                origin = self._transport.trusted_origin_header(network_initiator)
                if network_initiator.rstrip("/") != origin:
                    raise WPETransportError("invalid native subframe origin metadata")
            options_preflight = False
            if method == "OPTIONS":
                from .wpe_transport import classify_options_request
                options_preflight = classify_options_request(url, network_initiator, request_headers)

            target_parts = WPEAllowedDataTransport._parts(url)
            initiator_parts = WPEAllowedDataTransport._parts(network_initiator)
            cross_origin = (
                target_parts[1],
                target_parts[0].hostname.casefold(),
                target_parts[2],
            ) != (
                initiator_parts[1],
                initiator_parts[0].hostname.casefold(),
                initiator_parts[2],
            )
            if method == "POST" and cross_origin and body_length > MAX_CROSS_ORIGIN_POST_BYTES:
                if received_fd is not None:
                    os.close(received_fd)
                    received_fd = None
                self._send_resource_denial(
                    packet.request_id, "security",
                    "cross-origin POST body exceeds trusted inline bound",
                )
                return
            # BoJangles WebKit overwrites this reserved private metadata from
            # the loader's FetchOptions; never infer authority from jar contents.
            modes = [value for name, value in request_headers
                     if str(name).casefold() == "sec-bojangles-credentials"]
            if len(modes) > 1 or (modes and modes[0] not in {"omit", "same-origin", "include"}):
                raise WPEProtocolError("invalid native credentials metadata")
            credentials_mode = modes[0] if modes else "omit"
            raw_headers = {
                str(name).casefold(): str(value).strip().casefold()
                for name, value in request_headers
            }
            raw_header_names = set(raw_headers)

            if (
                raw_headers.get("sec-fetch-dest") == "document"
                and raw_headers.get("sec-fetch-mode") == "navigate"
            ):
                if method == "POST":
                    self._queue(RendererEvent(
                        RendererEventKind.POST_NAVIGATION_REQUESTED,
                        document_id,
                        uri=url,
                        body=request_body,
                        headers=trusted_headers,
                        navigation_cause=self._form_navigation_cause(url, network_initiator),
                    ))
                else:
                    self._queue(RendererEvent(
                        RendererEventKind.NAVIGATION_FAILED,
                        document_id,
                        uri=url,
                        detail=f"redirect requires new frontend document authority: {url}",
                    ))
                return

            if (
                cross_origin
                and method == "GET"
                and "origin" in raw_header_names
                and "sec-fetch-mode" not in raw_header_names
            ):
                self._send_resource_denial(
                    packet.request_id,
                    "security",
                    "ambiguous cross-origin GET without Fetch metadata is denied",
                )
                return
        except (AttributeError, WPEProtocolError, WPETransportError) as exc:
            if received_fd is not None:
                os.close(received_fd)
            self._send_resource_denial(packet.request_id, "security", str(exc))
            return

        if resource_type == "DOCUMENT":
            if method != "POST" or not url.startswith(("https://", "http://")):
                self._send_resource_denial(packet.request_id, "security", "invalid top-level POST navigation")
                return
            self._queue(RendererEvent(
                RendererEventKind.POST_NAVIGATION_REQUESTED,
                document_id, uri=url, body=request_body, headers=trusted_headers,
                navigation_cause=self._form_navigation_cause(url, network_initiator),
            ))
            return

        if statistics_group is not None:
            with self._events_lock:
                self._statistics_highwater = max(self._statistics_highwater, statistics_group)
        def operation():
            if statistics_group is None:
                return self._statistics_nonce + ":legacy:" + str(packet.request_id)
            with self._events_lock:
                stale = not statistics_group or statistics_group + 256 < self._statistics_highwater
            if stale:
                return "" # Incomplete statistics, never a transport/authority decision.
            return self._statistics_nonce + ":resource:" + str(statistics_group)
        current = url
        gateway = self._resource_gateway()
        for hop in range(6):
            decision = gateway.authorize(WPERequestIntent(
                request_id=packet.request_id,
                document_id=document_id,
                url=current, operation_id=operation(),
                resource_type=resource_type,
                initiator_url=initiator_url,
            ))
            if not decision.allow:
                self._send_resource_denial(packet.request_id, decision.category, decision.reason)
                return
            try:
                cookie_options = {}
                current_origin = WPEAllowedDataTransport.trusted_origin_header(current)
                initiator_origin = WPEAllowedDataTransport.trusted_origin_header(network_initiator)
                hop_cross_origin = current_origin != initiator_origin
                credentials_allowed = (credentials_mode == "include" or
                    (credentials_mode == "same-origin" and not hop_cross_origin))
                # Missing metadata is anonymous. Preflights are always anonymous;
                # cookie send/store are decided again for each redirect hop.
                if (not options_preflight and credentials_allowed and
                        getattr(self._transport, "allow_first_party_cookies", False)):
                    cookie_options = {
                        "send_session_cookies": True,
                        "store_session_cookies": True,
                        # Cookie SameSite/CHIPS context is the top-level page,
                        # not the immediate script/frame initiator.
                        "cookie_site_url": (
                            self._request.uri
                            if self._request is not None
                            else initiator_url
                        ),
                    }
                referer_options = (
                    {"_trusted_referer": network_initiator}
                    if isinstance(self._transport, WPEAllowedDataTransport)
                    else {}
                )
                if getattr(self._transport, "supports_upload_cancellation", False):
                    referer_options["_cancelled"] = self._reader_stop
                if (hop_cross_origin and method in {"GET", "POST"}
                        and raw_headers.get("sec-fetch-mode") not in {"navigate", "no-cors"}):
                    from .wpe_transport import preflight_resource_request
                    preflight_resource_request(
                        self._transport, current, network_initiator, method,
                        request_headers, credentialed=credentials_mode == "include")
                if method == "GET" and not trusted_headers and not cookie_options:
                    # Preserve the established test/adapter transport contract for
                    # transports that do not opt into trusted browser cookies.
                    fetched = self._transport.fetch_once(
                        current, **referer_options
                    )
                else:
                    fetched = self._transport.fetch_once(
                        current,
                        method=method,
                        request_headers=trusted_headers,
                        body=(request_body if method == "POST" else None),
                        **referer_options,
                        **({"_cors_preflight": True} if options_preflight else
                           {"_application_request": True} if isinstance(self._transport, WPEAllowedDataTransport) else {}),
                        **cookie_options,
                    )
            except WPEDownloadOffered as offer:
                self._queue(RendererEvent(
                    RendererEventKind.DOWNLOAD_REQUESTED, document_id,
                    uri=offer.url, detail=offer.suggested_filename,
                ))
                self._send_resource_denial(packet.request_id, "download", "trusted download authorization required")
                return
            except WPERedirectRequired as redirect:
                if self._resource_redirect_handoff:
                    try:
                        self._transport._parts(redirect.target)
                        target_decision = gateway.authorize(WPERequestIntent(
                            request_id=packet.request_id, document_id=document_id,
                            url=redirect.target, resource_type=resource_type,
                            initiator_url=initiator_url, operation_id=operation(), phase="preflight"))
                        if not target_decision.allow:
                            self._send_resource_denial(packet.request_id, target_decision.category, target_decision.reason)
                            return
                        if redirect.status not in {301, 302, 303, 307, 308}:
                            raise WPETransportError("unsupported resource redirect status")
                        headers = self._transport.sanitize_response_headers(redirect.headers)
                        # Only trusted-jar accepted cookies may reach WebCore.
                        # Redirects update document.cookie before dependent work,
                        # just like ordinary resource responses.
                        headers += tuple(("Set-Cookie", value) for value in
                                         redirect.accepted_cookie_headers[:16])
                        fields = [current, redirect.target, str(redirect.status), str(len(headers))]
                        for name, value in headers:
                            fields.extend((name, value))
                        self._send(NativePacket(NativeMessage.RESOURCE_REDIRECT,
                                                packet.request_id, pack_strings(*fields)))
                    except WPETransportError as exc:
                        self._send_resource_denial(packet.request_id, "transport", str(exc))
                    return
                before = self._transport._parts(current)
                after = self._transport._parts(redirect.target)
                if (before[1], before[0].hostname, before[2]) != (after[1], after[0].hostname, after[2]):
                    self._send_resource_denial(packet.request_id, "security", "cross-origin resource redirect requires origin-aware handoff")
                    return
                if hop == 5:
                    self._send_resource_denial(packet.request_id, "transport", "WPE subresource redirect limit exceeded")
                    return
                if method == "POST":
                    if redirect.status in {301, 302, 303}:
                        method = "GET"
                        request_body = b""
                        trusted_headers = tuple(
                            (name, value)
                            for name, value in trusted_headers
                            if str(name).casefold() != "content-type"
                        )
                    elif redirect.status not in {307, 308}:
                        self._send_resource_denial(
                            packet.request_id,
                            "transport",
                            "unsupported POST redirect status",
                        )
                        return
                current = redirect.target
                continue
            except WPETransportError as exc:
                self._send_resource_denial(packet.request_id, "transport", str(exc))
                return
            if (
                fetched.status < 200
                or fetched.status >= 600
                or 300 <= fetched.status < 400
            ):
                self._send_resource_denial(
                    packet.request_id,
                    "transport",
                    f"WPE resource HTTP status denied: {fetched.status}",
                )
                return

            response_headers = {
                str(name).casefold(): str(value).strip().casefold()
                for name, value in fetched.headers
            }
            corp = response_headers.get("cross-origin-resource-policy", "")
            if cross_origin and corp == "same-origin":
                self._send_resource_denial(
                    packet.request_id,
                    "security",
                    "Cross-Origin-Resource-Policy same-origin denied cross-origin resource",
                )
                return
            if method == "GET":
                self._report_media(document_id, fetched, source="resource")
            self._send_fetched_resource(packet.request_id, fetched)
            return

    def respond_file_chooser(self, request_id: int, paths: tuple[str, ...] = ()) -> None:
        if request_id <= 0:
            raise ValueError("file chooser request id must be positive")
        if not paths:
            self._send(NativePacket(NativeMessage.FILE_CHOOSER_RESULT, request_id=request_id, payload=b""))
            return
        if self._upload_staging_dir is None:
            raise RuntimeError("trusted upload staging is unavailable")
        request_dir = Path(self._upload_staging_dir) / f"{request_id}-{secrets.token_hex(8)}"
        request_dir.mkdir(mode=0o700)
        sandbox_paths: list[str] = []
        for index, raw_path in enumerate(paths):
            source = Path(raw_path).expanduser().resolve(strict=True)
            if not source.is_file():
                raise ValueError(f"upload selection is not a regular file: {source}")
            safe_name = source.name.replace("/", "_").replace("\\", "_") or f"upload-{index}"
            destination = request_dir / safe_name
            if destination.exists():
                destination = request_dir / f"{index}-{safe_name}"
            with source.open("rb") as src, destination.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            os.chmod(destination, 0o400)
            sandbox_paths.append(f"/state/uploads/{request_dir.name}/{destination.name}")
        payload = pack_strings(*sandbox_paths)
        self._send(NativePacket(NativeMessage.FILE_CHOOSER_RESULT, request_id=request_id, payload=payload))

    def respond_script_dialog(self, request_id: int, accepted: bool, text: str = "") -> None:
        if request_id <= 0:
            raise ValueError("script dialog request id must be positive")
        payload = pack_strings("1" if accepted else "0", text)
        self._send(NativePacket(NativeMessage.SCRIPT_DIALOG_RESULT, request_id=request_id, payload=payload))

    def respond_spelling_choice(self, request_id: int, index: int | None) -> None:
        if request_id <= 0 or (index is not None and not 0 <= index < 8):
            raise ValueError("invalid spelling selection")
        self._send(NativePacket(NativeMessage.SPELLING_MENU_RESULT, request_id=request_id,
                                payload=pack_strings("" if index is None else str(index))))

    def respond_context_choice(self, request_id: int, index: int | None) -> None:
        if request_id <= 0 or (index is not None and not 0 <= index < 48):
            raise ValueError("invalid context selection")
        self._send(NativePacket(NativeMessage.SPELLING_MENU_RESULT, request_id=request_id,
                                payload=pack_strings("" if index is None else str(index))))

    def poll_events(self) -> list[RendererEvent]:
        self._check_process()
        if self._host_network_state is not None:
            self._host_network_state.refresh()
        with self._events_lock:
            events = list(self._events)
            self._events.clear()
            return events

    def _queue(self, event: RendererEvent) -> None:
        with self._navigation_lock:
            cancelled = getattr(self._navigation_local, "cancelled", None)
            if cancelled is not None and cancelled.is_set():
                return
            with self._events_lock:
                self._events.append(event)

    def _event_from_packet(self, packet: NativePacket) -> RendererEvent | None:
        document_id = self._context.document.document_id if self._context else ""
        uri = self._request.uri if self._request else ""
        mapping = {
            NativeMessage.NAVIGATION_STARTED: RendererEventKind.NAVIGATION_STARTED,
            NativeMessage.NAVIGATION_COMMITTED: RendererEventKind.NAVIGATION_COMMITTED,
            NativeMessage.NAVIGATION_FINISHED: RendererEventKind.NAVIGATION_FINISHED,
            NativeMessage.NAVIGATION_FAILED: RendererEventKind.NAVIGATION_FAILED,
            NativeMessage.TITLE_CHANGED: RendererEventKind.TITLE_CHANGED,
            NativeMessage.URL_CHANGED: RendererEventKind.URL_CHANGED,
            NativeMessage.DOWNLOAD_OFFER: RendererEventKind.DOWNLOAD_REQUESTED,
            NativeMessage.NEW_WINDOW_REQUESTED: RendererEventKind.NEW_WINDOW_REQUESTED,
            NativeMessage.FILE_CHOOSER_REQUEST: RendererEventKind.FILE_CHOOSER_REQUESTED,
            NativeMessage.SCRIPT_DIALOG_REQUEST: RendererEventKind.SCRIPT_DIALOG_REQUESTED,
            NativeMessage.SPELLING_MENU_REQUEST: RendererEventKind.SPELLING_MENU_REQUESTED,
            NativeMessage.LINK_CONTEXT_MENU_REQUEST: RendererEventKind.SPELLING_MENU_REQUESTED,
            NativeMessage.IMAGE_CONTEXT_MENU_REQUEST: RendererEventKind.SPELLING_MENU_REQUESTED,
            NativeMessage.EDIT_CONTEXT_MENU_REQUEST: RendererEventKind.SPELLING_MENU_REQUESTED,
            NativeMessage.REGION_CONTEXT_MENU_REQUEST: RendererEventKind.SPELLING_MENU_REQUESTED,
        }
        if packet.kind is NativeMessage.RESOURCE_STOPPED:
            source, group, reason, host = unpack_strings(packet.payload, 4)
            if source != document_id or not group.isdigit() or len(group) > 10 or not 0 <= int(group) <= 0xFFFFFFFF or reason not in {"redirect-limit","redirect-loop"} or len(host) > 255:
                raise WPEProtocolError("invalid resource stop metadata")
            operation = self._statistics_nonce + ":resource:" + group if int(group) and int(group) + 256 >= self._statistics_highwater else ""
            return RendererEvent(RendererEventKind.RESOURCE_BLOCKED,document_id,uri=uri,
                                 detail=reason,link_uri=host,operation_id=operation)
        if packet.kind is NativeMessage.STYLE_APPLIED:
            source, target, count = unpack_strings(packet.payload, 3)
            if source != document_id or target != uri or not count.isdigit() or not 0 <= int(count) <= 64:
                raise WPEProtocolError("invalid style acknowledgement")
            return RendererEvent(RendererEventKind.COSMETIC_RULES_APPLIED, document_id, uri=uri, detail=count)
        if packet.kind is NativeMessage.NAVIGATION_INTENT:
            values = unpack_strings(packet.payload, 3)
            if values[0] != document_id or len(values[1]) > 8192 or values[2] not in {"operator", "automatic", "cross-origin"}:
                raise WPEProtocolError("invalid navigation intent")
            WPEAllowedDataTransport._parts(values[1])
            prefixes = {"operator": "page navigation requires new frontend document authority: ",
                        "automatic": "automatic same-origin navigation requires new frontend document authority: ",
                        "cross-origin": "automatic cross-origin navigation requires frontend decision: "}
            return RendererEvent(RendererEventKind.NAVIGATION_FAILED, document_id, uri=uri,
                                 detail=prefixes[values[2]] + values[1], navigation_cause=values[2],
                                 link_uri=values[1], operation_id=self._statistics_nonce + ":ui:" + str(packet.request_id))
        if packet.kind not in mapping:
            return None
        detail = packet.payload.decode("utf-8", errors="replace")
        if packet.kind is NativeMessage.FILE_CHOOSER_REQUEST:
            try:
                values = _decode_string_list(packet.payload)
                if not values or values[0] not in {"0", "1"}:
                    return None
                detail = "\0".join(values)
            except (ValueError, UnicodeError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                                 detail=detail, body=str(packet.request_id).encode("ascii"))
        if packet.kind is NativeMessage.REGION_CONTEXT_MENU_REQUEST:
            try:
                values = _decode_string_list(packet.payload)
                if not 7 <= len(values) <= 55 or packet.request_id <= 0:
                    return None
                source_document, link, image, mime, cut, flags, media, *entries = values
                if (source_document != document_id or cut not in {"0", "1"}
                        or flags not in {str(n) for n in range(8)}
                        or any(len(v.encode("utf-8")) > 8192 for v in (link, media))
                        or len(image.encode("utf-8")) >= 512 * 1024 or len(mime) > 128
                        or any("\r" in v or "\n" in v for v in (link, image, mime, media))):
                    return None
                actions = []
                for entry in entries:
                    stock, enabled, label = entry.split(":", 2)
                    if (not stock.isascii() or not stock.isdigit() or not 1 <= int(stock) <= 38
                            or int(stock) in {7, 8, 17, 26} or enabled not in {"0", "1"}
                            or not label or len(label.encode("utf-8")) > 96
                            or any(c in label for c in "\r\n")):
                        return None
                    actions.append((int(stock), enabled == "1", label))
            except (ValueError, UnicodeError, WPEProtocolError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                detail="\0".join(label for stock, enabled, label in actions if stock in {16,18,19}),
                body=str(packet.request_id).encode("ascii"), link_uri=link, image_uri=image,
                mime_type=mime, can_cut=cut == "1", context_flags=int(flags),
                context_actions=tuple(actions), media_uri=media, region_context=True)
        if packet.kind is NativeMessage.EDIT_CONTEXT_MENU_REQUEST:
            try:
                values = _decode_string_list(packet.payload)
                if not 5 <= len(values) <= 13 or packet.request_id <= 0:
                    return None
                source_document, link, image, mime, can_cut, *labels = values
                if (source_document != document_id or can_cut not in {"0", "1"}
                        or len(link.encode("utf-8")) > 8192 or len(image.encode("utf-8")) >= 512 * 1024
                        or len(mime) > 128 or any("\r" in v or "\n" in v for v in (link, image, mime))
                        or any(not label or len(label) > 96 for label in labels)):
                    return None
            except (ValueError, UnicodeError, WPEProtocolError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                detail="\0".join(labels), body=str(packet.request_id).encode("ascii"),
                link_uri=link, image_uri=image, mime_type=mime, can_cut=can_cut == "1")
        if packet.kind is NativeMessage.IMAGE_CONTEXT_MENU_REQUEST:
            try:
                values = _decode_string_list(packet.payload)
                if not 4 <= len(values) <= 12 or packet.request_id <= 0:
                    return None
                source_document, link, image, mime, *labels = values
                if (source_document != document_id or not image or len(image.encode("utf-8")) >= 512 * 1024
                        or len(link.encode("utf-8")) > 8192 or len(mime) > 128
                        or any("\r" in value or "\n" in value for value in (image, link, mime))
                        or any(not label or len(label) > 96 for label in labels)):
                    return None
            except (ValueError, UnicodeError, WPEProtocolError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                detail="\0".join(labels), body=str(packet.request_id).encode("ascii"),
                link_uri=link, image_uri=image, mime_type=mime)
        if packet.kind is NativeMessage.LINK_CONTEXT_MENU_REQUEST:
            try:
                values = _decode_string_list(packet.payload)
                if not 2 <= len(values) <= 10 or packet.request_id <= 0:
                    return None
                source_document, link, *labels = values
                if source_document != document_id or not link or len(link.encode("utf-8")) > 8192:
                    return None
                if "\n" in link or "\r" in link or any(not label or len(label) > 96 for label in labels):
                    return None
            except (ValueError, UnicodeError, WPEProtocolError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                                 detail="\0".join(labels), body=str(packet.request_id).encode("ascii"),
                                 link_uri=link)
        if packet.kind is NativeMessage.SPELLING_MENU_REQUEST:
            try:
                values = _decode_string_list(packet.payload)
                if not 0 <= len(values) <= 8 or any(not value or len(value) > 96 for value in values):
                    return None
            except (ValueError, UnicodeError, WPEProtocolError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                                 detail="\0".join(values), body=str(packet.request_id).encode("ascii"))
        if packet.kind is NativeMessage.SCRIPT_DIALOG_REQUEST:
            try:
                dialog_type, message, default_text = unpack_strings(packet.payload, 3)
                detail = "\0".join((dialog_type, message, default_text))
            except (ValueError, UnicodeError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=uri,
                                 detail=detail, body=str(packet.request_id).encode("ascii"))
        if packet.kind is NativeMessage.NEW_WINDOW_REQUESTED:
            target = detail.strip()
            try:
                WPEAllowedDataTransport._parts(target)
            except WPETransportError:
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=target, detail=target, operation_id=self._statistics_nonce + ":ui:" + str(packet.request_id))
        if packet.kind is NativeMessage.DOWNLOAD_OFFER:
            try:
                offered_url, suggested = unpack_strings(packet.payload, 2)
                target, target_scheme, target_port, _ = WPEAllowedDataTransport._parts(offered_url)
                origin, origin_scheme, origin_port, _ = WPEAllowedDataTransport._parts(uri)
                if (target_scheme, target.hostname.casefold(), target_port) != (
                    origin_scheme, origin.hostname.casefold(), origin_port
                ):
                    return None
            except (ValueError, UnicodeError, WPETransportError):
                return None
            return RendererEvent(mapping[packet.kind], document_id, uri=offered_url,
                                 detail=suggested)
        return RendererEvent(mapping[packet.kind], document_id, uri=uri, detail=detail,
            operation_id=self._statistics_nonce + ":ui:" + str(packet.request_id) if packet.kind is NativeMessage.NAVIGATION_FAILED and packet.request_id else "")

    def _handle_cookie_sync(self, packet: NativePacket) -> None:
        if self._context is None or self._request is None:
            return
        if not getattr(self._transport, "allow_first_party_cookies", False):
            return
        try:
            document_id, source_url, set_cookie = unpack_strings(packet.payload, 3)
        except (ValueError, UnicodeError):
            return
        if document_id != self._context.document.document_id:
            return
        try:
            current = WPEAllowedDataTransport._parts(self._request.uri)
            source = WPEAllowedDataTransport._parts(source_url)
        except WPETransportError:
            return
        if (current[1], current[0].hostname.casefold(), current[2]) != (
            source[1], source[0].hostname.casefold(), source[2]
        ):
            return
        try:
            self._transport.session_cookies.store_set_cookie(source_url, set_cookie)
        except WPETransportError:
            return

    def _reader_loop(self) -> None:
        sock = self._sock
        assert sock is not None and self._resource_sock is not None
        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ, False)
        selector.register(self._resource_sock, selectors.EVENT_READ, True)
        resource_paused = False
        try:
            while not self._reader_stop.is_set():
                # Resource bursts wait in their bounded socket rather than
                # becoming permanent script/image denials. Control remains
                # registered and responsive throughout saturation.
                available = self._resource_slots.acquire(blocking=False)
                if available:
                    self._resource_slots.release()
                if resource_paused and available:
                    selector.register(self._resource_sock, selectors.EVENT_READ, True)
                    resource_paused = False
                elif not resource_paused and not available:
                    selector.unregister(self._resource_sock)
                    resource_paused = True
                ready = selector.select(timeout=0.05 if resource_paused else 0.5)
                if not ready:
                    self._check_process()
                    continue
                # One bounded packet per iteration; control wins simultaneous readiness.
                key, _ = min(ready, key=lambda item: item[0].data)
                packet, received_fd = recv_packet_with_fd(key.fileobj)
                if (packet.kind in RESOURCE_MESSAGES) != key.data or (key.data and packet.kind not in {NativeMessage.RESOURCE_REQUEST, NativeMessage.DOWNLOAD_OFFER}):
                    if received_fd is not None:
                        os.close(received_fd)
                    raise WPEProtocolError("message received on wrong WPE channel")
                if packet.kind is NativeMessage.READY:
                    if received_fd is not None:
                        os.close(received_fd)
                        raise WPEProtocolError("READY packet carried an unexpected descriptor")
                    self._ready.set()
                    continue
                if packet.kind is NativeMessage.RESOURCE_REQUEST:
                    self._dispatch_resource_request(packet, received_fd)
                    continue
                if packet.kind is NativeMessage.COOKIE_SYNC:
                    if received_fd is not None:
                        os.close(received_fd)
                        raise WPEProtocolError("COOKIE_SYNC carried an unexpected descriptor")
                    self._handle_cookie_sync(packet)
                    continue
                if received_fd is not None:
                    os.close(received_fd)
                    raise WPEProtocolError("unexpected descriptor on WPE lifecycle packet")
                if self._deliver_reply(packet):
                    continue
                event = self._event_from_packet(packet)
                if event is not None:
                    self._queue(event)
        except (EOFError, OSError) as exc:
            self._fail(f"WPE IPC disconnected: {type(exc).__name__}")
        except Exception as exc:
            self._fail(f"WPE IPC protocol failure: {type(exc).__name__}: {exc}")
        finally:
            selector.close()
            if self._lifecycle is RendererLifecycle.FAILED:
                self._reader_stop.set()
                for channel in (self._sock, self._resource_sock):
                    if channel is not None:
                        try:
                            channel.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        channel.close()
                with self._reply_lock:
                    for reply in self._replies.values():
                        reply.event.set()
                self._ready.set()


    def begin_stop(self) -> None:
        """Stop renderer command traffic immediately without waiting for drain."""
        if self._lifecycle is RendererLifecycle.STOPPED:
            return
        self._cancel_navigation()
        self._lifecycle = RendererLifecycle.STOPPING
        self._reader_stop.set()
        try:
            if self._sock is not None:
                # Closing the channel also wakes blocked sends. Do not wait
                # for a command lock merely to stop an obsolete renderer.
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self._sock.close()
        finally:
            self._sock = None
        resource_sock, self._resource_sock = self._resource_sock, None
        if resource_sock is not None:
            try:
                resource_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            resource_sock.close()

    def stop(self) -> None:
        if self._lifecycle is RendererLifecycle.STOPPED:
            return
        self.begin_stop()
        process = self._process
        if process is not None and process.poll() is None:
            try:
                # Native teardown has two bounded eight-second child-drain phases.
                process.wait(timeout=18.0)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)
        self._process = None
        if self._native_diagnostics is not None:
            self._native_diagnostics.close()
            self._native_diagnostics = None
        if self._upload_staging_dir is not None:
            self._host_network_state = None
            shutil.rmtree(self._upload_staging_dir, ignore_errors=True)
            self._upload_staging_dir = None
        reader = self._reader
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=3.0)
        self._reader = None
        resources, self._resources = self._resources, None
        if resources is not None:
            # Queued jobs close their descriptors without fetching once stopped.
            # Running bounded transports complete before document authority is cleared.
            resources.shutdown(wait=True)
        with self._reply_lock:
            for reply in self._replies.values():
                reply.event.set()
            self._replies.clear()
        self._context = None
        self._request = None
        self.media_candidates.clear()
        self._lifecycle = RendererLifecycle.STOPPED
        lease = getattr(self, "_profile_lease", None)
        if lease is not None:
            lease.release()
            self._profile_lease = None
