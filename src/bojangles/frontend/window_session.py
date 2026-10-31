"""Foreground windowed BoJangles browser session.

The rendering engine still writes only to the frontend-owned memfd framebuffer.
This module presents that framebuffer in an ordinary X11 window and translates
physical window input into the typed renderer-input API.
"""
from __future__ import annotations

from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from time import monotonic
from urllib.parse import parse_qs, urlsplit
import re
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog
from .file_selection import choose_files, choose_save_path
from PIL import Image, ImageOps, ImageTk
from tkinter import ttk
from bojangles import __version__
from bojangles.bookmarks.html_store import Bookmark, BookmarkFolder, SandboxBookmarkStore
from bojangles.downloads import trusted_session_headers

from bojangles.filter.engine import ContentFilter
from bojangles.frontend.framebuffer import SharedFramebuffer
from bojangles.frontend.home_surface import HOME_URI, HomeSurface
from bojangles.frontend.window_coordinator import WindowCoordinator, WindowLimitReached
from bojangles.frontend.input import GestureAuthority
from bojangles.media.broker import MediaBroker
from bojangles.media.candidates import MediaKind
from bojangles.media.tk_window import MediaWindow
from bojangles.passwords import PasswordVault, canonical_https_origin
from bojangles.frontend.gtk_input import surface_point
from bojangles.frontend.open_target import (
    OpenTargetPlan,
    fallback_notice,
    http_fallback_allowed,
    plan_open_target,
)
from bojangles.frontend.search_handoff import BrowserSearchListener
from bojangles.frontend.state import SessionHistory
from bojangles.frontend.terminal_control import TerminalControlPanel
from bojangles.internal.pages import DEFAULT_PAGES
from bojangles.renderer.api import RendererEventKind, RendererLifecycle, Viewport, ResourceRequest, ResourceType
from bojangles.renderer.installed import installed_renderer_factories
from bojangles.renderer.manager import RendererManager
from bojangles.renderer.native_protocol import NativeMessage
from bojangles.renderer.network import RendererRequestBroker
from bojangles.security.context import DocumentRegistry
from bojangles.security.navigation import NavigationBroker, NavigationSource


_REDIRECT_PREFIX = (
    "redirect requires new frontend document authority: "
)
_PAGE_NAV_PREFIX = "page navigation requires new frontend document authority: "
_AUTO_NAV_PREFIX = (
    "automatic same-origin navigation requires new frontend document authority: "
)
_CROSS_NAV_PREFIX = "automatic cross-origin navigation requires frontend decision: "
_MAGNET_PREFIX = "magnet link requires frontend decision: "

_HISTORY_LIMIT = 100
APP_TITLE = f"BoJangles {__version__}"


def _mascot_window_icons(root: tk.Misc) -> tuple[ImageTk.PhotoImage, ...]:
    """Use the trusted landing character for X11 window and desktop tabs."""
    artwork = Path(__file__).resolve().parents[1] / "assets" / "mascot.png"
    with Image.open(artwork) as image:
        mascot = image.convert("RGBA")
    photos = []
    for size in (16, 32, 48, 128):
        scaled = ImageOps.contain(mascot, (size, size), Image.Resampling.LANCZOS)
        square = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        square.alpha_composite(scaled, ((size - scaled.width) // 2,
                                        (size - scaled.height) // 2))
        photos.append(ImageTk.PhotoImage(square, master=root))
    return tuple(photos)


def _case_patterns(*extensions: str) -> str:
    patterns = []
    for extension in extensions:
        clean = extension.lstrip(".")
        patterns.extend((f"*.{clean.lower()}", f"*.{clean.upper()}"))
    return " ".join(dict.fromkeys(patterns))


def _wpe_key_modifiers(state: int) -> int:
    """Translate X11/Tk modifier state into the bounded WPE keyboard mask."""
    result = 0
    if state & 0x0004:  # Control
        result |= 1
    if state & 0x0001:  # Shift
        result |= 2
    if state & 0x0008:  # Mod1 / Alt
        result |= 4
    if state & 0x0040:  # Mod4 / Meta
        result |= 8
    if state & 0x0002:  # Caps Lock
        result |= 16
    return result


def upload_filetypes(mimes: tuple[str, ...]) -> list[tuple[str, str]]:
    """Translate WebKit accept MIME hints into Linux case-safe chooser filters."""
    filetypes: list[tuple[str, str]] = []
    for mime in mimes:
        normalized = mime.split(";", 1)[0].strip().lower()
        if normalized.startswith("image/"):
            filetypes.append(("Images", _case_patterns(
                "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "heic", "heif")))
        elif normalized.startswith("video/"):
            filetypes.append(("Video", _case_patterns(
                "mp4", "mkv", "webm", "mov", "avi", "m4v")))
        elif normalized.startswith("audio/"):
            filetypes.append(("Audio", _case_patterns(
                "mp3", "m4a", "wav", "flac", "ogg", "opus")))
        elif normalized == "application/pdf":
            filetypes.append(("PDF", _case_patterns("pdf")))
    filetypes.append(("All files", "*"))
    return filetypes


def automatic_navigation_target(detail: str) -> str | None:
    text = str(detail or "")
    if not text.startswith(_AUTO_NAV_PREFIX):
        return None
    return text[len(_AUTO_NAV_PREFIX):].strip() or None


def cross_origin_navigation_target(detail: str) -> str | None:
    text = str(detail or "")
    if not text.startswith(_CROSS_NAV_PREFIX):
        return None
    return text[len(_CROSS_NAV_PREFIX):].strip() or None


def redirect_target(detail: str) -> str | None:
    text = str(detail or "")
    if not text.startswith(_REDIRECT_PREFIX):
        return None

    target = text[len(_REDIRECT_PREFIX):].strip()
    return target or None


def magnet_navigation_target(detail: str) -> str | None:
    text = str(detail or "")
    if not text.startswith(_MAGNET_PREFIX):
        return None
    return text[len(_MAGNET_PREFIX):].strip() or None


def _validated_magnet(uri: str) -> str:
    value = str(uri or "").strip()
    if len(value) > 8192 or any(ch in value for ch in "\r\n\0"):
        raise ValueError("invalid magnet URI")
    parsed = urlsplit(value)
    if parsed.scheme.casefold() != "magnet" or not parsed.query:
        raise ValueError("torrent handoff requires a magnet URI")
    values = parse_qs(parsed.query, keep_blank_values=True)
    btih = ""
    for xt in values.get("xt", ()):
        if xt.casefold().startswith("urn:btih:"):
            btih = xt[9:]
            break
    if not (
        re.fullmatch(r"[0-9A-Fa-f]{40}", btih)
        or re.fullmatch(r"[A-Za-z2-7]{32}", btih)
    ):
        raise ValueError("magnet URI requires a valid BitTorrent info hash")
    return value


def abgr_to_rgb(raw: bytes) -> bytes:
    """Convert little-endian ABGR8888 framebuffer bytes to RGB."""

    if len(raw) % 4:
        raise ValueError("ABGR framebuffer length is not pixel aligned")

    rgb = bytearray((len(raw) // 4) * 3)

    # ABGR8888 integer layout on little-endian Linux is R,G,B,A bytes.
    rgb[0::3] = raw[0::4]
    rgb[1::3] = raw[1::4]
    rgb[2::3] = raw[2::4]

    return bytes(rgb)


from .context_menu import RegionMenus
from .update_panel import UpdateControls

class WindowSession(RegionMenus, UpdateControls):
    WIDTH = 1024
    HEIGHT = 640

    def __init__(
        self,
        target: str | None,
        *,
        renderer_factories=None,
        renderer_name: str = "wpe",
        multi_window: bool = False,
        owner: WindowSession | None = None,
    ) -> None:
        self.plan = (OpenTargetPlan(HOME_URI, None, False)
                     if target is None else plan_open_target(target))
        self.renderer_factories = renderer_factories
        self.renderer_name = renderer_name
        # WPE supports several independently sandboxed live browser windows.
        self.multi_window = multi_window or renderer_name == "wpe"
        self.owner = owner
        self.coordinator = owner.coordinator if owner is not None else WindowCoordinator(self)
        if owner is None:
            self._password_session_entries = None
            self._password_session_prompted = False
        self.search_listener: BrowserSearchListener | None = None

        self.documents = DocumentRegistry(DEFAULT_PAGES)
        self.navigation = NavigationBroker(self.documents)
        from bojangles.config import load
        self.filter = ContentFilter(load().filter.level)
        self.channel = RendererRequestBroker(
            self.documents,
            self.filter,
        )
        self.gestures = GestureAuthority()
        self.media_broker = MediaBroker(self.documents, self.gestures)

        self.project_root = Path(__file__).resolve().parents[3]

        self.manager: RendererManager | None = None
        # Retired renderers drain outside Tk's input/event thread.  Navigation
        # must never freeze the primary browser while an old WPE process or
        # resource pool completes bounded shutdown.
        self._retire_threads: set[Thread] = set()
        self.current_document_id: str | None = None
        self.current_url = ""
        self.page_title = ""
        self._spelling_point = None
        self._surface_buttons_down = set()
        self._recent_page_click = None
        # (document_id, expiry_monotonic, source_url, crossed_navigation)
        # A real left-click may authorize one subsequent live HLS/DASH handoff.
        self._pending_stream_selection = None
        self._bridge_origin: tuple[str, str | None, int | None] | None = None
        self._bridge_document_id = None
        # One physical page click authorizes one continuation in this exact
        # document. Navigation or consumption revokes it; elapsed time does not.
        self._click_bridge_origin: tuple[str, str | None, int | None] | None = None
        self._click_bridge_document_id = None
        self._drm_prompted_documents: set[str] = set()
        self._password_autofill_documents: set[str] = set()
        self.control_panel = TerminalControlPanel(self.plan.primary_url)

        self.history = SessionHistory()

        self.plane = SharedFramebuffer.create(
            self.WIDTH,
            self.HEIGHT,
            pixel_format="ABGR8888",
        )

        self.root = tk.Tk() if owner is None else tk.Toplevel(owner.root)
        self.root.overrideredirect(False)
        self._window_icons = (_mascot_window_icons(self.root) if owner is None
                              else owner._window_icons)
        self.root.iconphoto(owner is None, *self._window_icons)
        self.root.title(APP_TITLE)
        self.root.resizable(True, True)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        display_width = min(self.WIDTH, max(1, screen_width - 80))
        display_height = min(self.HEIGHT, max(1, screen_height - 140))
        self.root.geometry(f"{display_width}x{display_height + 32}")

        bar = tk.Frame(self.root)
        bar.pack(fill="x")
        tk.Button(bar, text="← Back", command=lambda: self._cli_command("back")).pack(side="left")
        tk.Button(bar, text="Home", command=lambda: self._navigate(HOME_URI)).pack(side="left")
        tk.Button(bar, text="Refresh", command=lambda: self._cli_command("refresh")).pack(side="left")
        tk.Button(bar, text="Stop", command=lambda: self._cli_command("stop")).pack(side="left")
        tk.Button(bar, text="Print…", command=self._print_page).pack(side="left")
        self.translate_button = tk.Button(bar, text="Translate…", command=self._translate_page)
        self.translate_button.pack(side="left")
        self._reset_translation()
        self.address = tk.StringVar(value=self.plan.primary_url)
        self.address_entry = tk.Entry(bar, textvariable=self.address)
        self.address_entry.pack(side="left", fill="x", expand=True)
        self.blocking_button = tk.Button(bar,text="Blocking · 0",command=self._toggle_blocking)
        self.blocking_button.pack(side="left",before=self.address_entry)
        self._blocking_panel = None
        self._blocking_revision = -1
        self.address_entry.bind("<Return>", lambda event: self._go_address())
        self.address_entry.bind("<ButtonPress-1>", self._claim_address_focus, add="+")
        self.address_entry.bind("<FocusIn>", lambda event: self._surface_focus(False), add="+")
        from .context_menu import bind_text_regions, field_menu
        bind_text_regions(self.root)
        self.address_entry.bind("<Button-3>", self._show_address_context_menu)
        tk.Button(bar, text="Go", command=self._go_address).pack(side="left")
        tk.Button(bar, text="+", command=self._add_bookmark).pack(side="left")
        self.password_button = tk.Button(
            bar, text="Fill saved login", command=self._fill_saved_login
        )
        tk.Button(bar, text="Exit", command=self.coordinator.primary.close).pack(side="right")
        if self.multi_window:
            tk.Button(bar, text="New Browser", command=self._open_browser_window).pack(side="left")
        self.window_tabs = tk.Frame(self.root)
        self.window_tabs.pack(fill="x")
        # Root ownership keeps this control alive when tab buttons are rebuilt.
        self.update_button = tk.Button(self.root, text='Updates', command=self._show_update_panel)
        self.update_button.pack(in_=self.window_tabs, side='right')
        self.bookmarks_visible = False
        self.downloads = self.coordinator.downloads
        self.downloads_visible = False
        self.downloads_shown = False
        tk.Button(bar, text="Popups", command=self._show_popup_policy).pack(side="left")
        self.bookmark_store = SandboxBookmarkStore()
        self.password_vault = PasswordVault()
        self.media_button = tk.Button(self.root, text="Open page media…", command=self._choose_media, state="disabled")
        self.media_button.pack(fill="x")

        self.status = tk.StringVar(value="BoJangles")
        self.status_label = tk.Label(
            self.root,
            textvariable=self.status,
            anchor="w",
            padx=6,
        )
        self.status_label.pack(side="bottom", fill="x")
        self.content_frame = tk.Frame(self.root)
        self.content_frame.pack(fill="both", expand=True)

        self.image_label = tk.Label(
            self.content_frame,
            width=display_width,
            height=display_height,
            borderwidth=0,
            highlightthickness=0,
            takefocus=True,
        )
        self.image_label.pack(fill="both", expand=True)
        self.image_label.bind("<Configure>", self._queue_surface_resize)
        self._resize_timer = None
        self.home_surface = HomeSurface(self.content_frame)
        self.bookmarks_frame = tk.Frame(self.content_frame)
        self.bookmark_path = ()
        bookmark_actions = tk.Frame(self.bookmarks_frame)
        bookmark_actions.pack(side="top", fill="x")
        self.bookmark_open_button = tk.Button(
            bookmark_actions, text="Open", command=self._activate_bookmark
        )
        self.bookmark_open_button.pack(side="left")
        self.bookmark_find_button = tk.Button(
            bookmark_actions, text="Find", command=self._find_bookmark
        )
        self.bookmark_find_button.pack(side="left")
        self.bookmark_delete_button = tk.Button(
            bookmark_actions, text="Delete", command=self._delete_selected_bookmark
        )
        self.bookmark_delete_button.pack(side="left")
        self.bookmark_list = ttk.Treeview(self.bookmarks_frame, show="tree", selectmode="browse")
        self.bookmark_list.pack(fill="both", expand=True)
        self.bookmark_list.bind("<Double-Button-1>", self._double_click_bookmark)
        self.bookmark_list.bind("<Return>", lambda event: self._activate_bookmark())
        for sequence in ("<Button-3>", "<Menu>", "<Shift-F10>"):
            self.bookmark_list.bind(sequence, self._show_bookmark_context_menu)
        self._bookmark_folder_open = {}
        self._bookmark_folder_keys = {}
        self.bookmark_numbers = {}
        self.downloads_frame = tk.Frame(self.content_frame)
        download_table = tk.Frame(self.downloads_frame)
        download_table.pack(fill="both", expand=True)
        self.download_list = ttk.Treeview(
            download_table, columns=("file", "state", "progress", "size", "speed", "remaining"),
            show="headings", selectmode="browse",
        )
        for column, title, width in (("file", "File", 300), ("state", "Status", 110),
                ("progress", "Progress", 85), ("size", "Downloaded / Total", 185),
                ("speed", "Avg. speed", 105), ("remaining", "Time left", 110)):
            self.download_list.heading(column, text=title)
            self.download_list.column(column, width=width, minwidth=70,
                                      stretch=column == "file", anchor="w")
        scroll = ttk.Scrollbar(download_table, orient="vertical", command=self.download_list.yview)
        self.download_list.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        horizontal = ttk.Scrollbar(self.downloads_frame, orient="horizontal", command=self.download_list.xview)
        self.download_list.configure(xscrollcommand=horizontal.set)
        horizontal.pack(fill="x")
        self.download_list.pack(fill="both", expand=True)
        for sequence in ('<Button-3>', '<Menu>', '<Shift-F10>'):
            self.download_list.bind(sequence, self._region_download_menu)
        self.download_details = tk.Label(self.downloads_frame, text="No downloads this session",
                                         anchor="w", justify="left", wraplength=850)
        self.download_details.pack(fill="x", padx=8, pady=6)
        download_actions = tk.Frame(self.downloads_frame)
        download_actions.pack(fill="x")
        tk.Button(download_actions, text="Cancel", command=self._cancel_download).pack(side="left")
        tk.Button(download_actions, text="Retry", command=self._retry_download).pack(side="left")

        self.photo: tk.PhotoImage | None = None
        self.closed = False
        self.redirect_pending = False
        self._auto_nav_hops = 0
        self._auto_nav_started = 0.0
        self._cli_commands: Queue[str] = Queue()
        self._history_move = False
        self._cli_thread: Thread | None = None

        self._bind_input()
        self.root.bind("<FocusIn>", self._refresh_bookmark_view, add="+")

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close,
        )
        self.coordinator.refresh_tabs()

    def _reset_translation(self):
        cancellation = getattr(self, "_translation_cancel", None)
        if cancellation is not None:
            cancellation.set()
        self._translation_cancel = None
        self._translation_generation = getattr(self, "_translation_generation", 0) + 1
        self._translation_token = None
        self._translation_busy = False
        button = getattr(self, "translate_button", None)
        if button is not None:
            button.configure(text="Translate…", state="normal")

    def _translate_page(self):
        from tkinter import simpledialog
        from ..translation.service import translate_page_text
        import secrets
        from threading import Event
        if getattr(self, "_translation_busy", False):
            return
        manager = self.manager
        backend = getattr(manager, "backend", None)
        if backend is None or not hasattr(backend, "extract_translation") or not self.current_url.startswith(("http://", "https://")):
            self.status.set("Translate is available on loaded web pages")
            return
        token = getattr(self, "_translation_token", None)
        restore = token is not None
        target = None
        if not restore:
            target = simpledialog.askstring("Translate page", "Translate to language (name or code):",
                                            initialvalue=getattr(self, "_translation_target", "english"), parent=self.root)
            if target is None:
                return
            if self.manager is not manager or self.closed:
                return
            self._translation_target = target
            token = secrets.token_hex(16)
        generation = getattr(self, "_translation_generation", 0)
        self._translation_busy = True
        self.translate_button.configure(state="disabled")
        self.status.set("Restoring original text…" if restore else "Translating page text…")
        results = Queue()
        cancellation = Event()
        self._translation_cancel = cancellation
        def current():
            return (not self.closed and self.manager is manager and
                    getattr(self, "_translation_generation", 0) == generation)
        def run():
            extracted = False
            try:
                if restore:
                    result = backend.restore_translation(token)
                    warnings = ()
                else:
                    texts, languages = backend.extract_translation(token)
                    extracted = True
                    translated, warnings = translate_page_text(texts, languages, target)
                    if cancellation.is_set():
                        return
                    result = backend.apply_translation(token, translated)
                    if not result.get("changed"):
                        backend.restore_translation(token)
                results.put((result, warnings, None))
            except Exception as exc:
                # Discard extraction snapshots on failure, allowing a clean retry.
                if extracted and not cancellation.is_set():
                    try:
                        backend.restore_translation(token)
                    except Exception:
                        pass
                results.put((None, (), str(exc)))
        def ready():
            if not current():
                return
            try:
                result, warnings, error = results.get_nowait()
            except Empty:
                self.root.after(50, ready)
                return
            self._translation_busy = False
            self.translate_button.configure(state="normal")
            if error:
                self.status.set("Translation failed — " + error)
                return
            if restore:
                self._translation_token = None
                self.translate_button.configure(text="Translate…")
                self.status.set(f"Original — restored {result.get('restored', 0)} text nodes; {result.get('skipped', 0)} page changes preserved")
            else:
                changed = result.get("changed", 0)
                self._translation_token = token if changed else None
                self.translate_button.configure(text="Original" if changed else "Translate…")
                message = f"Translated {changed} text nodes; {result.get('skipped', 0)} page changes preserved" if changed else "No page text changed"
                self.status.set(message + (" — " + "; ".join(warnings) if warnings else ""))
        Thread(target=run, daemon=True, name="bojangles-page-translation").start()
        self.root.after(50, ready)

    def _refresh_password_button(self) -> None:
        vault = getattr(self, "password_vault", None)
        button = getattr(self, "password_button", None)
        if vault is None or button is None:
            return
        try:
            available = self.current_url.startswith("https://") and vault.has_origin(self.current_url)
        except (OSError, ValueError, PermissionError):
            available = False
        if available:
            if not button.winfo_ismapped():
                button.pack(side="left")
        else:
            button.pack_forget()

    def _session_password_entries(self, origin: str, *, force_prompt: bool = False):
        primary = self.coordinator.primary
        entries = getattr(primary, "_password_session_entries", None)
        if entries is not None:
            return entries
        if getattr(primary, "_password_session_prompted", False) and not force_prompt:
            return None
        primary._password_session_prompted = True
        master = simpledialog.askstring(
            "BoJangles password vault",
            f"Master password to unlock saved logins for this BoJangles session:\n{origin}",
            show="*",
            parent=self.root,
        )
        if master is None:
            return None
        try:
            entries = self.password_vault.unlock(master)
        except (OSError, ValueError, PermissionError) as exc:
            self.status.set(f"Password vault unlock failed — {exc}")
            if force_prompt:
                primary._password_session_prompted = False
            return None
        primary._password_session_entries = entries
        return entries

    def _fill_saved_login(self, *, automatic: bool = False) -> bool:
        manager = self.manager
        document_id = self.current_document_id
        if manager is None or document_id is None:
            return False
        try:
            origin = canonical_https_origin(self.current_url)
            if not self.password_vault.has_origin(origin):
                if not automatic:
                    self.status.set("No saved login for this HTTPS origin")
                    self._refresh_password_button()
                return False
            entries = self._session_password_entries(origin, force_prompt=not automatic)
            if entries is None:
                return False
            credentials = entries.get(origin)
            if credentials is None:
                return False
            username, password = credentials
            backend = manager.backend
            if not hasattr(backend, "fill_credentials"):
                raise RuntimeError("active renderer does not support trusted credential fill")
            if backend.fill_credentials(document_id, origin, username, password):
                self.status.set("Saved login pre-filled — submit remains under your control")
                self.control_panel.report("Saved login pre-filled for current HTTPS document")
                return True
            self.status.set("Saved login not filled — login form was not unambiguous")
            return False
        except (KeyError, OSError, ValueError, PermissionError, RuntimeError) as exc:
            self.status.set(f"Saved login unavailable — {exc}")
            return False
        finally:
            self._restore_surface_focus_if_current()

    def _schedule_autofill_saved_login(self) -> None:
        document_id = self.current_document_id
        if not document_id or document_id in self._password_autofill_documents:
            return
        for delay_ms in (150, 800, 2000):
            self.root.after(
                delay_ms,
                lambda expected=document_id: self._autofill_saved_login(expected),
            )

    def _autofill_saved_login(self, expected_document_id: str | None = None) -> None:
        document_id = self.current_document_id
        if not document_id:
            return
        if expected_document_id is not None and document_id != expected_document_id:
            return
        if document_id in self._password_autofill_documents:
            return
        try:
            if (
                self.current_url.startswith("https://")
                and self.password_vault.has_origin(self.current_url)
                and self._fill_saved_login(automatic=True)
            ):
                self._password_autofill_documents.add(document_id)
        except (OSError, ValueError, PermissionError):
            return

    def _retire_manager(self, manager: RendererManager) -> None:
        """Drain an obsolete renderer without blocking Tk input."""
        manager.begin_stop()
        holder: dict[str, Thread] = {}

        def retire() -> None:
            try:
                manager.stop()
            finally:
                thread = holder.get("thread")
                if thread is not None:
                    self._retire_threads.discard(thread)

        thread = Thread(target=retire, name="bojangles-renderer-retire", daemon=True)
        holder["thread"] = thread
        self._retire_threads.add(thread)
        thread.start()

    def _new_manager(self) -> RendererManager:
        factories = self.renderer_factories

        if factories is None:
            factories = installed_renderer_factories(
                root=self.project_root,
            )
            self.renderer_factories = factories

        renderer_name = getattr(self, "renderer_name", "wpe")
        manager_factories = factories
        if renderer_name == "wpe":
            wpe_factory = factories.get("wpe")
            private = (
                getattr(wpe_factory, "__dict__", {}).get("_bojangles_drm_factory")
                if wpe_factory is not None else None
            )
            if private is not None:
                manager_factories = dict(factories)
                manager_factories["wpe-drm"] = private

        return RendererManager(
            manager_factories,
            renderer_name,
        )

    def _record_history(self, url: str, *, replace: bool = False) -> None:
        if replace and 0 <= self.history.position < len(self.history.entries):
            self.history.entries[self.history.position] = url
            # A canonical address may already occupy the preceding slot.
            # Keeping both makes Back re-enter the same page through an alias.
            if (self.history.position > 0
                    and self.history.entries[self.history.position - 1] == url
                    and getattr(self, "_history_restore_document_id", None) != self.current_document_id):
                del self.history.entries[self.history.position]
                self.history.position -= 1
            return
        if (
            self.history.entries
            and self.history.position >= 0
            and self.history.entries[self.history.position] == url
        ):
            return

        self.history.visit(url)

        if len(self.history.entries) > _HISTORY_LIMIT:
            excess = len(self.history.entries) - _HISTORY_LIMIT
            del self.history.entries[:excess]
            self.history.position -= excess

    def _navigate(self, url: str, *, source: NavigationSource = NavigationSource.OPERATOR,
                  method: str = "GET", body: bytes = b"", headers=(),
                  replace_history: bool = False, operator_selected: bool = False) -> None:
        from bojangles.documentation import ROOT as DOCS_ROOT
        if url.startswith(DOCS_ROOT):
            from bojangles.security.navigation import NavigationDenied
            if source not in (NavigationSource.OPERATOR, NavigationSource.INTERNAL_ACTION):
                raise NavigationDenied("content cannot open local documentation")
            # A trusted route opens a side window without changing navigation state.
            try:
                self.home_surface.features.open_topic(url)
            except KeyError as exc:
                raise NavigationDenied("unknown documentation topic") from exc
            return
        from bojangles.frontend.navigation_chain import NavigationChain
        if not hasattr(self, "_navigation_chain"):
            self._navigation_chain = NavigationChain()
        if source is NavigationSource.OPERATOR and url.startswith(("http://", "https://")):
            self._navigation_chain.begin(url, method)
        if isinstance(getattr(self, "channel", None), RendererRequestBroker):
            self.channel.advertising.begin_document()
        previous_manager = self.manager
        previous_document_id = self.current_document_id
        # A continuation belongs to one user navigation transaction, not just
        # its first renderer document. Same-origin redirects/login steps may
        # replace that document before the client-side cross-origin handoff.
        previous = urlsplit(self.current_url)
        destination = urlsplit(url)
        previous_origin = (previous.scheme.lower(), previous.hostname, previous.port)
        destination_origin = (destination.scheme.lower(), destination.hostname, destination.port)
        selected = source is NavigationSource.OPERATOR or operator_selected
        inherited = previous_document_id is not None and any(
            getattr(self, prefix + "_origin", None) == previous_origin
            and getattr(self, prefix + "_document_id", None) == previous_document_id
            for prefix in ("_bridge", "_click_bridge")
        )
        continuation_origin = (
            destination_origin
            if destination.scheme.lower() in {"http", "https"}
            and (selected or (inherited and destination_origin == previous_origin))
            else None
        )
        pending_stream = getattr(self, "_pending_stream_selection", None)
        restoring_history = getattr(self, "_history_move", False) or (
            replace_history and previous_document_id is not None
            and getattr(self, "_history_restore_document_id", None) == previous_document_id
        )
        suppress_history_media = getattr(self, "_history_move", False) or (
            replace_history and previous_document_id is not None
            and getattr(self, "_history_media_suppressed_document_id", None) == previous_document_id
        )
        self._spelling_point = None
        self._reset_translation()

        document = self.navigation.navigate(
            url,
            source=source,
        )
        if (previous_document_id is None and getattr(self,"_bridge_origin",None) is not None
                and document.uri != HOME_URI):
            from bojangles.popup_rules import origin
            scheme,host,port=self._bridge_origin
            host=("["+host+"]") if host and ":" in host else host
            source_site=f"{scheme}://{host}"+(f":{port}" if port else "")
            self._navigation_chain.site=origin(source_site)
        if document.uri != HOME_URI and isinstance(getattr(self, "channel", None), RendererRequestBroker):
            self.channel.bind_advertising_site(document.document_id,
                getattr(self._navigation_chain, "site", document.uri))
            self.channel.bind_navigation_operation(document.document_id,
                getattr(self._navigation_chain,"operation_id",self.channel.statistics.operation()))
        decision = (self.channel.decide(ResourceRequest(document.document_id, document.uri,
                                                      ResourceType.DOCUMENT, document.uri, phase="preflight"))
                    if document.uri != HOME_URI else None)
        if decision is not None and not decision.allow:
            if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                self.channel.statistics.adopt(document.document_id, previous_document_id)
                self.channel.statistics.navigation(previous_document_id,
                    getattr(self._navigation_chain,"operation_id",""),"destination-denied")
            self.documents.close(document.document_id)
            raise ValueError("Navigation blocked: " + decision.reason)
        if source is NavigationSource.OPERATOR:
            self._auto_nav_hops = 0
            self._click_bridge_origin = None
            self._click_bridge_document_id = None
            if previous_document_id is not None:
                self._bridge_origin = None
                self._bridge_document_id = None

        if document.uri == HOME_URI:
            if previous_manager is not None:
                self._retire_manager(previous_manager)
            if previous_document_id is not None:
                if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                    self.channel.statistics.retire(previous_document_id)
                self.documents.close(previous_document_id)
            self.manager = None
            self.current_document_id = document.document_id
            if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                self.channel.statistics.begin_page(document.document_id)
                self.channel.advertising.set_page(document.document_id)
            self.redirect_pending = False
            self.current_url = document.uri
            self.page_title = ""
            self.address.set(document.uri)
            self._history_replace_document_id = document.document_id
            self._history_restore_document_id = document.document_id if restoring_history else None
            self._history_media_suppressed_document_id = document.document_id if suppress_history_media else None
            if replace_history or not self._history_move:
                self._record_history(document.uri, replace=replace_history)
            self._recent_page_click = None
            self._pending_stream_selection = None
            self._click_bridge_origin = None
            self._click_bridge_document_id = None
            self.media_button.configure(state="disabled")
            self.media_button.pack_forget()
            self.status.set("BoJangles home")
            self.control_panel.update(url=document.uri, state="CONNECTED", notice="Home opened")
            self.root.title(f"{APP_TITLE} — Home")
            self._refresh_password_button()
            self._show_browser()
            return

        manager = self._new_manager()
        # A retired process may still paint while draining. Never give two
        # documents the same pixel plane, including when the new load fails.
        replacement_plane = SharedFramebuffer.create(
            self.WIDTH, self.HEIGHT, pixel_format="ABGR8888")

        try:
            manager.open_context(
                document,
                request_channel=self.channel,
                framebuffer=replacement_plane.target(),
                viewport=Viewport(
                    self.WIDTH,
                    self.HEIGHT,
                ),
                method=method,
                body=body,
                headers=headers,
                initiator_url=(self.current_url if method == "POST" else ""),
            )
        except Exception:
            self._retire_manager(manager)
            replacement_plane.close()
            self.documents.close(document.document_id)
            raise

        previous_plane = self.plane
        self.plane = replacement_plane
        previous_plane.close()
        self._navigation_chain.record_request(manager.backend)

        # Commit only after the replacement renderer is live. A failed
        # site-owned form/search navigation must leave the initiating page usable.
        self.manager = manager
        self.current_document_id = document.document_id
        self._click_bridge_origin = None
        self._click_bridge_document_id = None
        self._bridge_origin = continuation_origin
        self._bridge_document_id = document.document_id if continuation_origin is not None else None
        if isinstance(getattr(self,"channel",None),RendererRequestBroker):
            self.channel.statistics.begin_page(document.document_id)
            self.channel.advertising.set_page(document.document_id)
        self.redirect_pending = False
        if previous_document_id is None and self._bridge_origin is not None:
            self._bridge_document_id = document.document_id
        if previous_manager is not None:
            self._retire_manager(previous_manager)
        if previous_document_id is not None:
            if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                self.channel.statistics.retire(previous_document_id)
            self.documents.close(previous_document_id)

        if self.root.focus_get() is self.image_label:
            self._surface_focus(True)
        self.current_url = document.uri
        self.page_title = ""
        self.address.set(document.uri)
        self._history_replace_document_id = document.document_id
        self._history_restore_document_id = document.document_id if restoring_history else None
        self._history_media_suppressed_document_id = document.document_id if suppress_history_media else None
        if replace_history or not self._history_move:
            self._record_history(document.uri, replace=replace_history)

        self._recent_page_click = None
        now = monotonic()
        if (
            source is not NavigationSource.OPERATOR
            and pending_stream is not None
            and previous_document_id is not None
            and pending_stream[0] == previous_document_id
            and pending_stream[1] >= now
        ):
            self._pending_stream_selection = (
                document.document_id, pending_stream[1], pending_stream[2], True
            )
        elif source is NavigationSource.OPERATOR:
            self._pending_stream_selection = None
        elif (
            pending_stream is None
            or pending_stream[1] < now
            or pending_stream[0] != document.document_id
        ):
            self._pending_stream_selection = None
        self.media_button.pack(fill="x", before=self.content_frame)
        self.media_button.configure(state="disabled")
        self.status.set(document.uri)
        self.control_panel.update(url=document.uri, state="CONNECTED", notice="Page opened")
        self.root.title(f"{APP_TITLE} — {document.uri}")
        self._refresh_password_button()
        self._show_browser()

    def _initial_navigation(self) -> None:
        try:
            self._navigate(self.plan.primary_url)
            return
        except Exception as exc:
            if (
                self.plan.fallback_url is None
                or not http_fallback_allowed(exc)
            ):
                raise

        notice = fallback_notice(self.plan.fallback_url)
        from bojangles.diagnostics import record
        record(
            "transport_fallback",
            url=self.plan.primary_url,
            fallback_url=self.plan.fallback_url,
            kind="https-to-http",
        )
        print(notice)
        self.status.set(notice.replace("\n", " — "))

        self._navigate(self.plan.fallback_url)

    def _verified_navigation_continuation(self, target: str, *, authorized: bool = False) -> bool:
        current = urlsplit(self.current_url)
        destination = urlsplit(target)
        if current.scheme.lower() != "https" or destination.scheme.lower() != "https":
            return False
        origin = (current.scheme.lower(), current.hostname, current.port)
        return authorized or any(
            getattr(self, prefix + "_origin", None) == origin
            and getattr(self, prefix + "_document_id", None) == self.current_document_id
            for prefix in ("_bridge", "_click_bridge")
        )

    def _follow_redirect(self, target: str, *, replace_history: bool = False,
                         initiating_document: str | None = None, fresh_operator: bool = False,
                         verified_continuation: bool = False) -> None:
        if initiating_document is not None and initiating_document != self.current_document_id:
            return
        if self.closed:
            return

        from bojangles.frontend.navigation_chain import NavigationChain
        if not hasattr(self, "_navigation_chain"):
            self._navigation_chain = NavigationChain()
            self._navigation_chain.begin(self.current_url)
        if fresh_operator:
            self._navigation_chain.begin(target, site=self.current_url)
            if isinstance(getattr(self, "channel", None), RendererRequestBroker):
                self.channel.bind_advertising_site(self.current_document_id, self.current_url)
                self.channel.bind_navigation_operation(self.current_document_id,self._navigation_chain.operation_id)
        self.redirect_pending = False
        if isinstance(getattr(self, "channel", None), RendererRequestBroker):
            decision = self.channel.decide(ResourceRequest(self.current_document_id, target,
                ResourceType.DOCUMENT, self.documents.require(self.current_document_id).uri, phase="preflight"))
            if not decision.allow:
                self.channel.statistics.navigation(self.current_document_id,
                    getattr(self._navigation_chain,"operation_id",""),"destination-denied")
                self.status.set("Navigation blocked: " + decision.reason)
                self.control_panel.report("Navigation blocked: " + decision.reason)
                return
        self.status.set(
            f"Authorizing redirect — {target}"
        )

        try:
            if (replace_history
                    and getattr(self, "_history_restore_document_id", None) == self.current_document_id
                    and getattr(self, "_history_direction", None) == "back"
                    and target == getattr(self, "_history_departure_url", None)):
                # A restored page must not turn one Back click into another
                # history step, or redirect straight back to the departure.
                self.status.set("Automatic return to the page you left was stopped")
                return
            verified_chain = self._verified_navigation_continuation(
                target, authorized=verified_continuation)
            if not fresh_operator:
                self._navigation_chain.follow(target, verified=verified_chain,
                    state=self._navigation_chain.request_state(
                        getattr(self.manager, "backend", None), target))
            options = {"operator_selected": True} if fresh_operator or verified_chain else {}
            if replace_history:
                self._navigate(target, source=NavigationSource.REDIRECT, replace_history=True, **options)
            else:
                self._navigate(target, source=NavigationSource.REDIRECT, **options)
            from bojangles.diagnostics import record
            record("recovery", url=target, kind="redirect")
        except Exception as exc:
            if isinstance(exc, ValueError):
                self._bridge_origin = None
                self._bridge_document_id = None
                self._click_bridge_origin = None
                self._click_bridge_document_id = None
            if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                self.channel.statistics.navigation(self.current_document_id,
                    getattr(self._navigation_chain,"operation_id",""),"redirect-stopped")
            self.status.set(f"Redirect failed — {exc}")

    def _submit_navigation(self, event):
        if self.closed or event.document_id != self.current_document_id:
            return
        from bojangles.frontend.navigation_chain import NavigationChain
        if event.navigation_cause != "server":
            self._navigation_chain = NavigationChain()
            self._navigation_chain.begin(event.uri, "POST", site=self.current_url)
        else:
            if not hasattr(self, "_navigation_chain"):
                self._navigation_chain = NavigationChain()
                self._navigation_chain.begin(self.current_url, "POST")
            try:
                self._navigation_chain.follow(event.uri, "POST",
                    verified=self._verified_navigation_continuation(event.uri))
            except ValueError as exc:
                self.status.set(str(exc))
                return
        self._navigate(event.uri, source=NavigationSource.CONTENT,
                       method="POST", body=event.body, headers=event.headers,
                       operator_selected=event.navigation_cause != "server")

    def _toggle_blocking(self):
        if self._blocking_panel is None:
            from bojangles.frontend.blocking_panel import BlockingPanel
            self._blocking_panel = BlockingPanel(self)
        frame=self._blocking_panel.frame
        if frame.winfo_ismapped():
            frame.pack_forget()
        else:
            frame.pack(fill="x",before=self.window_tabs)
            self._blocking_panel.refresh()

    def _blocking_allow(self,item,scope):
        from bojangles.filter.advertising import RULE_IDS,update
        if item.get("category") != "advertising" or item.get("rule") not in RULE_IDS or not item.get("site") or item.get("exception"):
            raise ValueError("This protection is not exception-eligible")
        policy=self.channel.advertising
        if scope=="page":
            if item["document"]!=self.current_document_id or item["resource"]=="DOCUMENT":
                raise ValueError("Use window/site scope for navigation; page scope is for this document's resources")
            policy.allow_page(self.current_document_id,item["site"],item["rule"])
        elif scope=="window":policy.allow_session(item["site"],item["rule"])
        elif scope=="site":
            update(item["site"],allow=item["rule"],path=policy.path);policy.refresh()
        else:raise ValueError("Invalid exception scope")

    def _update_blocking(self):
        channel=getattr(self,"channel",None)
        if not isinstance(channel,RendererRequestBroker) or not hasattr(self,"blocking_button"):return
        stats=channel.statistics
        if getattr(self,"_blocking_revision",-1)==stats.revision:return
        snapshot=stats.snapshot()
        self._blocking_revision=snapshot["revision"]
        self.blocking_button.configure(text="Blocking · "+str(snapshot["counts"]["requests_blocked"]))
        panel=getattr(self,"_blocking_panel",None)
        if panel is not None and panel.frame.winfo_ismapped():panel.refresh()

    def _pump_events(self) -> None:
        if self.closed:
            return
        try:
            self._drain_events()
            self._updates_tick()
        except Exception as exc:
            self.status.set(f"Browser event failed — {exc}; use Reload or another address")
        finally:
            # A malformed renderer event or optional panel failure must not
            # permanently remove this window's event pump.
            if not self.closed:
                self.root.after(40, self._pump_events)

    def _drain_events(self) -> None:
        manager = self.manager

        if manager is not None:
            try:
                events = manager.poll_events()
            except Exception as exc:
                self.status.set(f"Renderer event error — {exc}")
                events = []

            for event in events:
                # Navigation can replace the manager during this event batch.
                # Remaining events then belong to the retired document.
                if manager is not self.manager:
                    break
                if event.document_id and event.document_id != self.current_document_id:
                    continue
                if event.kind is RendererEventKind.RESOURCE_BLOCKED:
                    if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                        host=("["+event.link_uri+"]") if ":" in event.link_uri else event.link_uri
                        self.channel.statistics.decision(event.document_id,event.operation_id,
                            category="redirect",rule=event.detail,site=self.current_url,
                            url="https://"+host if host else "",resource="OTHER")
                elif event.kind is RendererEventKind.COSMETIC_RULES_APPLIED:
                    if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                        self.channel.statistics.styles(event.document_id,int(event.detail))
                elif event.kind is RendererEventKind.RENDERER_CRASHED:
                    self._renderer_failed(manager, event.document_id, event.detail)
                    break

                elif event.kind is RendererEventKind.NAVIGATION_STARTED:
                    self._reset_translation()

                elif event.kind is RendererEventKind.TITLE_CHANGED:
                    title = event.detail.strip()
                    if title:
                        self.page_title = title
                        self.root.title(
                            f"{APP_TITLE} — {title}"
                        )

                elif event.kind is RendererEventKind.URL_CHANGED:
                    # The event URI identifies the initiating document; detail
                    # carries the URL now shown by the renderer.
                    url = (event.detail or event.uri).strip()
                    if url:
                        self.current_url = url
                        self.address.set(url)
                        self.control_panel.update(url=url)
                        self._record_history(
                            url, replace=(getattr(self, "_history_replace_document_id", None) == self.current_document_id
                                          or getattr(self, "_history_restore_document_id", None) == self.current_document_id)
                        )
                        self.status.set(url)
                        self._refresh_password_button()

                elif event.kind is RendererEventKind.NAVIGATION_FINISHED:
                    self._history_replace_document_id = None
                    self._schedule_autofill_saved_login()

                elif event.kind is RendererEventKind.NAVIGATION_FAILED:
                    magnet = magnet_navigation_target(event.detail)
                    if magnet is not None:
                        self._offer_magnet(magnet, event.document_id)
                        continue
                    automatic = automatic_navigation_target(event.detail)
                    page_navigation = (event.detail[len(_PAGE_NAV_PREFIX):].strip()
                                       if event.detail.startswith(_PAGE_NAV_PREFIX) else None)
                    cross = cross_origin_navigation_target(event.detail)
                    verified_continuation = False
                    target = page_navigation or automatic or redirect_target(event.detail)
                    if event.navigation_cause:
                        page_navigation = event.link_uri if event.navigation_cause == "operator" else None
                        automatic = event.link_uri if event.navigation_cause == "automatic" else None
                        cross = event.link_uri if event.navigation_cause == "cross-origin" else None
                        target = (event.link_uri if event.navigation_cause == "server" else page_navigation or automatic)
                    if cross:
                        current = urlsplit(self.current_url)
                        origin = (current.scheme.lower(), current.hostname, current.port)
                        now = monotonic()
                        child_bridge = (
                            self._bridge_origin == origin
                            and self._bridge_document_id == self.current_document_id
                            and not self.redirect_pending
                        )
                        click_bridge = (
                            getattr(self, "_click_bridge_origin", None) == origin
                            and getattr(self, "_click_bridge_document_id", None) == self.current_document_id
                            and not self.redirect_pending
                        )
                        if ((child_bridge or click_bridge)
                                and not (current.scheme.lower() == "https" and urlsplit(cross).scheme.lower() != "https")):
                            target = cross
                            verified_continuation = (current.scheme.lower() == "https"
                                                     and urlsplit(cross).scheme.lower() == "https")
                            # Consume authority on this document to prevent
                            # replay. A verified successful replacement renews
                            # it for the same user-started navigation chain.
                            self._bridge_origin = None
                            self._bridge_document_id = None
                            self._click_bridge_origin = None
                            self._click_bridge_document_id = None
                            self._auto_nav_hops = 0
                        else:
                            self._bridge_origin = None
                            self._bridge_document_id = None
                            if (getattr(self, "_click_bridge_origin", None) != origin
                                    or getattr(self, "_click_bridge_document_id", None) != self.current_document_id):
                                self._click_bridge_origin = None
                                self._click_bridge_document_id = None
                    if cross and target is None:
                        if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                            self.channel.statistics.navigation(self.current_document_id,event.operation_id or self.channel.statistics.operation(),"cross-site-held")
                        self._held_advertising_navigation = (self.current_document_id, cross)
                        host = urlsplit(cross).hostname or "destination"
                        notice = "Automatic cross-site navigation held: " + host + ". Use advertising follow if intended."
                        self.status.set(notice)
                        self.control_panel.report(notice)
                        continue
                    if automatic and not self._verified_navigation_continuation(automatic):
                        now = monotonic()
                        if now - self._auto_nav_started > 10:
                            self._auto_nav_hops = 0
                            self._auto_nav_started = now
                        self._auto_nav_hops += 1
                        if self._auto_nav_hops > 4:
                            if isinstance(getattr(self,"channel",None),RendererRequestBroker):
                                self.channel.statistics.navigation(self.current_document_id,
                                    event.operation_id or self.channel.statistics.operation(),"automatic-hop-limit")
                            notice = "Automatic navigation stopped after four hops"
                            self.status.set(notice)
                            self.control_panel.report(notice)
                            continue
                    elif target:
                        self._auto_nav_hops = 0

                    if target is not None:
                        if not self.redirect_pending:
                            self.redirect_pending = True
                            self.root.after_idle(
                                lambda value=target, document=self.current_document_id,
                                       fresh=bool(page_navigation),
                                       verified=verified_continuation,
                                       replace=(redirect_target(event.detail) is not None
                                                or (not page_navigation and getattr(self, "_history_restore_document_id", None) == self.current_document_id)):
                                    self._follow_redirect(value, replace_history=replace,
                                                          initiating_document=document,
                                                          fresh_operator=fresh,
                                                          verified_continuation=verified)
                            )
                    else:
                        if (isinstance(getattr(self,"channel",None),RendererRequestBroker)
                                and event.detail in {"New-window navigation requires a user gesture",
                                 "Top-level navigation requires a user gesture",
                                 "New-window navigation requires an HTTP(S) destination",
                                 "Top-level navigation requires an HTTP(S) destination"}):
                            self.channel.statistics.navigation(self.current_document_id,
                                event.operation_id or self.channel.statistics.operation(),"navigation-authority-denied")
                        self.status.set(
                            f"Navigation failed — {event.detail}"
                        )
                        self.control_panel.report(f"Navigation failed — {event.detail}")

                elif event.kind is RendererEventKind.NEW_WINDOW_REQUESTED:
                    from bojangles.popup_policy import block_page_window
                    if block_page_window(self):
                        continue
                    target = (event.uri or event.detail).strip()
                    # A page's target does not request another browser window.
                    # Reuse same-window authority, history and document guards.
                    if target and not self.redirect_pending:
                        self.redirect_pending = True
                        self.root.after_idle(
                            lambda value=target, document=self.current_document_id:
                                self._follow_redirect(value, initiating_document=document,
                                                      fresh_operator=True)
                        )

                elif event.kind is RendererEventKind.MEDIA_CANDIDATE:
                    self.media_button.configure(state="normal")
                    self.status.set(f"Media candidate ({event.detail}) — {event.uri}")
                    self.control_panel.report(f"Media candidate ({event.detail}) — awaiting authorization")
                    if event.protected_media:
                        self._offer_drm_retry(event)
                    elif not self._offer_selected_live_stream(event):
                        self._attach_page_media(event)

                elif event.kind is RendererEventKind.MEDIA_REQUESTED:
                    self._offer_requested_media(event)

                elif event.kind is RendererEventKind.DOWNLOAD_REQUESTED:
                    self._offer_download(event.uri, event.detail)

                elif event.kind is RendererEventKind.FILE_CHOOSER_REQUESTED:
                    backend = self.manager.backend if self.manager else None
                    if backend is None or not hasattr(backend, "respond_file_chooser"):
                        continue
                    try:
                        request_id = int(event.body.decode("ascii"))
                        parts = event.detail.split("\0")
                        multiple = bool(parts and parts[0] == "1")
                        mimes = tuple(value for value in parts[1:] if value)
                        filetypes = upload_filetypes(mimes)
                        self.root.lift()
                        self.root.focus_force()
                        chosen = choose_files(parent=self.root, multiple=multiple,
                            title="Choose files for this website" if multiple else "Choose a file for this website",
                            filetypes=filetypes)
                        backend.respond_file_chooser(request_id, chosen)
                        self._restore_surface_focus_if_current()
                    except Exception as exc:
                        self.status.set(f"File chooser failed — {exc}")

                elif event.kind is RendererEventKind.SPELLING_MENU_REQUESTED:
                    if event.region_context:
                        point = self._spelling_point
                        if point:
                            self._show_region_page_menu(event, manager, point)
                        self._spelling_point = None
                        continue
                    backend = manager.backend
                    point = self._spelling_point
                    if point and hasattr(backend, "respond_spelling_choice"):
                        menu = None
                        try:
                            request_id = int(event.body.decode("ascii"))
                            menu = tk.Menu(self.root, tearoff=False)
                            if event.link_uri:
                                menu.add_command(label="Copy link address",
                                    command=lambda u=event.link_uri, m=manager, d=event.document_id:
                                        self._copy_link_address(u, m, d))
                                menu.add_command(label="Open link in new window",
                                    command=lambda u=event.link_uri, m=manager, d=event.document_id, popup=menu:
                                        self._open_link_from_menu(popup, u, m, d))
                            if event.image_uri:
                                menu.add_command(label="Save Image As…",
                                    command=lambda e=event, m=manager, popup=menu:
                                        self._save_image_from_menu(popup, e, m))
                            if event.can_cut:
                                menu.add_command(label="Cut", command=lambda m=manager, d=event.document_id:
                                    self._cut() if self.manager is m and self.current_document_id == d else None)
                            menu.add_command(label="Copy", command=lambda m=manager, d=event.document_id:
                                self._copy() if self.manager is m and self.current_document_id == d else None)
                            menu.add_command(label="Paste", command=lambda m=manager, d=event.document_id:
                                self._paste() if self.manager is m and self.current_document_id == d else None)
                            menu.add_separator()
                            menu.add_command(label="Print…", command=lambda m=manager, d=event.document_id:
                                self._print_page() if self.manager is m and self.current_document_id == d else None)
                            if event.detail:
                                menu.add_separator()
                            for index, label in enumerate(event.detail.split("\0") if event.detail else ()):
                                menu.add_command(
                                    label=label,
                                    command=lambda i=index, b=backend, rid=request_id:
                                        b.respond_spelling_choice(rid, i),
                                )
                            # The popup can grab X input before the physical
                            # button-up reaches the surface. Balance the native
                            # press now so future pointer events are not drags.
                            self._release_surface_buttons()
                            self._post_context_menu(menu, *point)
                        except Exception as exc:
                            self.status.set(f"Spelling menu unavailable — {exc}")
                    self._spelling_point = None

                elif event.kind is RendererEventKind.SCRIPT_DIALOG_REQUESTED:
                    backend = self.manager.backend if self.manager else None
                    if backend is None or not hasattr(backend, "respond_script_dialog"):
                        continue
                    try:
                        request_id = int(event.body.decode("ascii"))
                        dialog_type, message, default_text = (event.detail.split("\0") + ["", "", ""])[:3]
                        accepted = False
                        answer = ""
                        if dialog_type == "0":
                            messagebox.showinfo("Website message", message, parent=self.root)
                            accepted = True
                        elif dialog_type == "1":
                            accepted = messagebox.askokcancel("Website confirmation", message, parent=self.root)
                        elif dialog_type == "2":
                            value = simpledialog.askstring("Website prompt", message, initialvalue=default_text, parent=self.root)
                            accepted = value is not None
                            answer = value or ""
                        elif dialog_type == "3":
                            accepted = messagebox.askyesno("Leave this page?", message or "This page is asking whether you want to leave.", parent=self.root)
                        backend.respond_script_dialog(request_id, accepted, answer)
                        self._restore_surface_focus_if_current()
                    except Exception as exc:
                        self.status.set(f"Website dialog failed — {exc}")

                elif event.kind is RendererEventKind.POST_NAVIGATION_REQUESTED:
                    if event.navigation_cause == "user-form" or messagebox.askyesno("Submit form data?",
                                           f"Send this form to {event.uri}?",
                                           parent=self.root):
                        self.root.after_idle(lambda value=event: self._submit_navigation(value))
                    else:
                        self.status.set("Form submission cancelled")

                elif event.kind is RendererEventKind.TERMINAL_FAILURE:
                    from bojangles.diagnostics import record
                    record("wpe_failure", url=self.current_url, detail=event.detail)
                    self.status.set(
                        f"Renderer failure — {event.detail}"
                    )
                    self.control_panel.report(f"Renderer failure — {event.detail}")

        self._update_blocking()
        if getattr(self, "downloads_visible", False):
            self._refresh_downloads()

    def _open_browser_window(self, target: str | None = None,
                             *, from_page_gesture: bool = False) -> WindowSession | None:
        try:
            chosen = (target if isinstance(target, str) else
                      None if self.current_url == HOME_URI else
                      self.current_url or self.plan.primary_url)
            child = WindowSession(
                chosen,
                renderer_factories=self.renderer_factories,
                renderer_name="wpe" if isinstance(target, str) else self.renderer_name,
                multi_window=True,
                owner=self.coordinator.primary,
            )
            if from_page_gesture and isinstance(target, str):
                parsed = urlsplit(chosen)
                child._bridge_origin = (parsed.scheme.lower(), parsed.hostname, parsed.port)
                child._bridge_document_id = None
            self.coordinator.add_browser(child)
            child.root.after_idle(child._start_child)
            return child
        except Exception as exc:
            messagebox.showerror("New window unavailable", str(exc), parent=self.root)
            return None

    def _pump_search_handoff(self) -> None:
        if self.closed or self.search_listener is None:
            return
        self.search_listener.drain(self._open_browser_window)
        self.root.after(40, self._pump_search_handoff)

    def _draw_window_tabs(self) -> None:
        if not hasattr(self, "window_tabs"):
            return
        for child in self.window_tabs.winfo_children():
            child.destroy()
        browsers = [self.coordinator.primary] + sorted(
            (item for item in self.coordinator.browsers if item is not self.coordinator.primary),
            key=id,
        )
        for index, browser in enumerate(browsers, 1):
            button = tk.Button(self.window_tabs, text=f"Browser {index}",
                relief="sunken" if browser is self else "raised",
                command=lambda target=browser: target._activate_browser_window())
            button.pack(side="left")
            for sequence in ('<Button-3>', '<Menu>', '<Shift-F10>'):
                button.bind(sequence, lambda event, target=browser: self._region_tab_menu(event,target))
        show_bookmarks = self.current_url != HOME_URI or self.bookmarks_visible
        if not show_bookmarks:
            try:
                show_bookmarks = bool(self.bookmark_store.load())
            except OSError:
                show_bookmarks = False
        if show_bookmarks:
            tk.Button(
                self.window_tabs, text="Bookmarks",
                relief="sunken" if self.bookmarks_visible else "raised",
                command=self._show_bookmarks,
            ).pack(side="left")
        # A fixed tab in every browser keeps session transfers reachable even
        # when the window that offered them has been closed.
        tk.Button(
            self.window_tabs, text="Downloads",
            relief="sunken" if self.downloads_visible else "raised",
            command=self._show_downloads,
        ).pack(side="left")
        tk.Button(self.window_tabs, text="Media Center",
                  command=self.coordinator.show_media_center).pack(side="left")

    def _activate_browser_window(self) -> None:
        """Return both the visible page and input focus to a chosen browser."""
        if self.closed:
            return
        self._show_browser()
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.image_label.focus_set()
        self._surface_focus(True)

    def _add_bookmark(self) -> None:
        url = self.current_url
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            self.status.set("Open a website to add a bookmark")
            return
        title = self.page_title or parts.hostname or url
        try:
            from .bookmark_dialog import BookmarkDialog
            dialog = BookmarkDialog(
                self.root, self.bookmark_store.load_tree(), Bookmark(title, url)
            )
            if dialog.result is None:
                return
            bookmark, folder = dialog.result
            self.bookmark_store.add_to_folder(bookmark, folder)
            title = bookmark.title
            self.coordinator.refresh_bookmarks()
            self.status.set(f"Bookmark saved — {title}")
        except Exception as exc:
            self.status.set(f"Could not save bookmark — {exc}")

    def _bookmark_store_stamp(self):
        try:
            stat = self.bookmark_store.path.stat()
            return (stat.st_ino, stat.st_size, stat.st_mtime_ns)
        except FileNotFoundError:
            return None

    def _refresh_bookmark_view(self, event=None) -> None:
        # Separate foreground processes share HTML storage, not renderer state.
        # Reload on focus so an already-open list sees saves from another process.
        if event is not None and event.widget is not self.root:
            return
        if (not self.closed and self.bookmarks_visible
                and self._bookmark_store_stamp() != getattr(self, "_bookmark_view_stamp", None)):
            self._populate_bookmarks()

    def _show_bookmarks(self) -> None:
        self.bookmarks_visible = True
        self.downloads_visible = False
        self._surface_focus(False)
        self.image_label.pack_forget()
        self.home_surface.hide()
        self.downloads_frame.pack_forget()
        self.bookmarks_frame.pack(fill="both", expand=True)
        self._populate_bookmarks()
        self.coordinator.refresh_tabs()

    def _show_browser(self) -> None:
        self.bookmarks_visible = False
        self.downloads_visible = False
        self.bookmarks_frame.pack_forget()
        self.downloads_frame.pack_forget()
        if self.current_url == HOME_URI:
            self.image_label.pack_forget()
            self.home_surface.show()
        else:
            self.home_surface.hide()
            self.image_label.pack(fill="both", expand=True)
        self.coordinator.refresh_tabs()

    def _show_downloads(self) -> None:
        self.downloads_visible = True
        self.bookmarks_visible = False
        self._surface_focus(False)
        self.image_label.pack_forget()
        self.home_surface.hide()
        self.bookmarks_frame.pack_forget()
        self.downloads_frame.pack(fill="both", expand=True)
        self._refresh_downloads()
        self.coordinator.refresh_tabs()

    def _refresh_downloads(self) -> None:
        from .download_display import download_row
        items = self.downloads.snapshot()
        live = {str(item.id) for item in items}
        for key in self.download_list.get_children():
            if key not in live:
                self.download_list.delete(key)
        for item in items:
            key = str(item.id)
            values = download_row(item)
            if self.download_list.exists(key):
                if tuple(self.download_list.item(key, "values")) != values:
                    self.download_list.item(key, values=values)
            else:
                self.download_list.insert("", "end", iid=key, values=values)
        selection = self.download_list.selection()
        selected = next((item for item in items if selection and str(item.id) == selection[0]), None)
        if selected is not None:
            detail = str(selected.path or selected.directory / selected.filename)
            if selected.error:
                detail += "\n" + selected.error
        else:
            active = sum(item.state == "downloading" for item in items)
            detail = (f"{len(items)} downloads · {active} active — Select a file to see its save location or error"
                      if items else "No downloads this session")
        self.download_details.configure(text=detail)

    def _selected_download(self):
        selection = self.download_list.selection()
        if not selection:
            return None
        return next((item for item in self.downloads.snapshot()
                     if item.id == int(selection[0])), None)

    def _cancel_download(self) -> None:
        item = self._selected_download()
        if item:
            self.downloads.cancel(item)

    def _retry_download(self) -> None:
        item = self._selected_download()
        if item and item.state in {"failed", "cancelled"}:
            self.downloads.save(item)

    def _offer_magnet(self, uri: str, document_id: str | None) -> None:
        if document_id != self.current_document_id:
            return
        current = urlsplit(self.current_url)
        origin = (current.scheme.lower(), current.hostname, current.port)
        now = monotonic()
        if (
            getattr(self, "_click_bridge_origin", None) != origin
            or getattr(self, "_click_bridge_document_id", None) != self.current_document_id
        ):
            self.status.set("Torrent link blocked — a page selection is required")
            self.control_panel.report("Torrent link blocked — no selection for this document")
            return

        # One click can authorize at most one external torrent handoff.
        self._click_bridge_origin = None
        self._click_bridge_document_id = None
        self._recent_page_click = None
        try:
            magnet = _validated_magnet(uri)
        except ValueError as exc:
            self.status.set(f"Torrent link rejected — {exc}")
            self.control_panel.report(f"Torrent link rejected — {exc}")
            return

        if not messagebox.askyesno(
            "Add torrent?",
            "Add this user-selected magnet to the trusted torrent queue?",
            parent=self.root,
        ):
            self.status.set("Torrent handoff cancelled")
            return

        queue = Path.home() / ".local" / "bin" / "torrent-mgmnt"
        if not queue.is_file():
            self.status.set("Torrent handoff unavailable — torrent-mgmnt is missing")
            return
        origin = urlsplit(self.current_url).hostname or "bojangles"
        try:
            result = subprocess.run(
                [str(queue), "submit", magnet, "--origin", origin],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.status.set(f"Torrent handoff failed — {exc}")
            self.control_panel.report(f"Torrent handoff failed — {exc}")
            return
        if result.returncode != 0:
            reason = (result.stderr or result.stdout or "torrent-queue rejected request").strip()
            self.status.set(f"Torrent handoff failed — {reason[:240]}")
            self.control_panel.report("Torrent queue rejected the selected magnet")
            return
        notice = (result.stdout.strip().splitlines() or ["Torrent submitted"])[0]
        self.status.set(notice)
        self.control_panel.report(notice)

    def _save_image_from_menu(self, menu, event, manager) -> None:
        menu.tk.call("tk::MenuUnpost", str(menu))
        if self.closed or self.manager is not manager or self.current_document_id != event.document_id:
            self.status.set("Save image failed — the page has changed")
            return
        item = None
        try:
            from .image_save import image_filename
            data = manager.backend.image_data(int(event.body.decode("ascii")), event.document_id)
            item = self.downloads.offer_image(event.image_uri,
                image_filename(event.image_uri, event.mime_type or '', data), data)
            selected = choose_save_path(parent=self.root, title="Save Image As…",
                initialdir=item.directory, initialfile=item.filename)
            if selected:
                self.downloads.save(item, Path(selected))
                self._show_downloads()
                self.status.set(f"Saving image — {item.filename}")
            else:
                self.downloads.cancel(item)
                self.status.set("Save image cancelled")
        except Exception as exc:
            if item is not None:
                self.downloads.cancel(item)
            self.status.set(f"Save image failed — {exc}")
        finally:
            self._restore_surface_focus_if_current()

    def _offer_download(self, url: str, suggested_filename: str = '') -> None:
        try:
            backend = self.manager.backend if self.manager else None
            transport = getattr(backend, '_transport', None)
            active_page_url = self.current_url
            credentials = (
                (lambda target: trusted_session_headers(transport, target, active_page_url))
                if transport is not None else None
            )
            item = self.downloads.offer(url, suggested_filename, credentials)
        except ValueError as exc:
            self.status.set(f"Download rejected — {exc}")
            return
        self.downloads_shown = True
        self.coordinator.refresh_tabs()
        dialog = tk.Toplevel(self.root)
        dialog.title("BoJangles download")
        self.status.set(f"Download offered — {item.filename}")
        dialog.transient(self.root)
        dialog.grab_set()
        tk.Label(dialog, text=f"Download {item.filename}\nfrom {urlsplit(url).hostname}",
                 padx=20, pady=12).pack()
        actions = tk.Frame(dialog)
        actions.pack(padx=12, pady=12)
        def choose(destination=None, *, default=False):
            if destination is None and not default:
                self.downloads.cancel(item)
                self.status.set(f"Download cancelled — {item.filename}")
            else:
                self.downloads.save(item, destination)
                self._show_downloads()
            dialog.destroy()
        tk.Button(actions, text="Save", command=lambda: choose(default=True)).pack(side="left")
        def save_as():
            selected = choose_save_path(parent=dialog, initialdir=item.directory,
                                                   initialfile=item.filename)
            if selected:
                choose(Path(selected))
        tk.Button(actions, text="Save As", command=save_as).pack(side="left")
        tk.Button(actions, text="Cancel", command=lambda: choose()).pack(side="left")
        dialog.protocol("WM_DELETE_WINDOW", lambda: choose())

    def _remember_bookmark_folder_state(self) -> None:
        for row, key in tuple(self._bookmark_folder_keys.items()):
            if self.bookmark_list.exists(row):
                self._bookmark_folder_open[key] = bool(self.bookmark_list.item(row, "open"))

    def _populate_bookmarks(self) -> None:
        self._remember_bookmark_folder_state()
        self.bookmark_list.delete(*self.bookmark_list.get_children())
        self.bookmark_targets = {}
        self.bookmark_numbers = {}
        self._bookmark_folder_keys = {}
        absolute_number = 0

        def add(parent, entries, path=()):
            nonlocal absolute_number
            for index, item in enumerate(entries):
                key = path + (index,)
                if isinstance(item, BookmarkFolder):
                    row = self.bookmark_list.insert(
                        parent,
                        "end",
                        text="📁 " + item.title,
                        open=self._bookmark_folder_open.get(key, False),
                    )
                    self._bookmark_folder_keys[row] = key
                    add(row, item.children, key)
                elif isinstance(item, Bookmark):
                    absolute_number += 1
                    page = ((absolute_number - 1) // 999) + 1
                    number = ((absolute_number - 1) % 999) + 1
                    row = self.bookmark_list.insert(
                        parent, "end", text=f"{number:>3}. 🔖 {item.title}"
                    )
                    self.bookmark_targets[row] = item.url
                    self.bookmark_numbers[row] = (page, number)
        self._bookmark_view_stamp = self._bookmark_store_stamp()
        self._bookmark_tree = self.bookmark_store.load_tree()
        add("", self._bookmark_tree.children)

    def _find_bookmark(self) -> None:
        query = simpledialog.askstring(
            "Find bookmark",
            "Bookmark number, title, or URL:",
            parent=self.root,
        )
        if query is None:
            return
        query = query.strip()
        if not query:
            return
        lowered = query.casefold()
        numeric = int(query) if query.isdigit() and 1 <= int(query) <= 999 else None
        for row, url in self.bookmark_targets.items():
            _page, number = self.bookmark_numbers.get(row, (1, 0))
            text = str(self.bookmark_list.item(row, "text") or "")
            matches = number == numeric if numeric is not None else (
                lowered in text.casefold() or lowered in url.casefold()
            )
            if not matches:
                continue
            parent = self.bookmark_list.parent(row)
            while parent:
                self.bookmark_list.item(parent, open=True)
                parent = self.bookmark_list.parent(parent)
            self.bookmark_list.selection_set(row)
            self.bookmark_list.focus(row)
            self.bookmark_list.see(row)
            self.status.set(f"Bookmark found — {number}. {text.split('🔖 ', 1)[-1]}")
            return
        self.status.set(f"Bookmark not found — {query}")

    def _show_bookmark_context_menu(self, event) -> str:
        from .context_menu import post, position
        view = self.bookmark_list
        keyboard = getattr(event, "keysym", "") in {"Menu", "F10"}
        selection = view.selection()
        row = (selection[0] if selection else "") if keyboard else view.identify_row(event.y)
        if row:
            view.selection_set(row)
            view.focus(row)
        else:
            view.selection_remove(*selection)
        if row not in self.bookmark_numbers:
            return "break"
        # Capture the row and rendered tree; a later selection or refresh must
        # never redirect this menu's command to another bookmark.
        tree = self._bookmark_tree
        post(view, [("Remove Bookmark",
                     lambda: self._delete_selected_bookmark(row, tree), True)],
             position(event, view))
        return "break"

    def _delete_selected_bookmark(self, row=None, tree=None) -> None:
        selected = tuple(self.bookmark_list.selection())
        if row is None:
            if not selected:
                self.status.set("Select a bookmark to delete")
                return
            row = selected[0]
        expected = self._bookmark_tree if tree is None else tree
        try:
            if expected is not self._bookmark_tree or self.bookmark_store.load_tree() != expected:
                self._populate_bookmarks()
                self.status.set("Bookmarks changed — select the bookmark again")
                return
            numbered = self.bookmark_numbers.get(row)
            if row not in self.bookmark_targets or numbered is None:
                self.status.set("Folders are removed with: bojangles bookmarks folder remove <path>")
                return
            page, number = numbered
            _folder_path, bookmark = self.bookmark_store.show(number, page=page)
            if not messagebox.askyesno(
                "Delete bookmark?",
                f"Delete bookmark {number}: {bookmark.title}?",
                parent=self.root,
            ):
                return
            if self.bookmark_store.load_tree() != expected:
                self._populate_bookmarks()
                self.status.set("Bookmarks changed — select the bookmark again")
                return
            removed = self.bookmark_store.remove(number, page=page)
            self._populate_bookmarks()
            self.status.set(f"Bookmark deleted — {removed.title}")
        except (OSError, ValueError) as exc:
            self.status.set(f"Could not remove bookmark — {exc}")

    def _double_click_bookmark(self, event) -> str:
        # The indicator already toggled on the first press. Handle row activation
        # here and stop the class binding from toggling the same folder again.
        if self.bookmark_list.identify_element(event.x, event.y) != "Treeitem.indicator":
            self._activate_bookmark(event)
        return "break"

    def _activate_bookmark(self, event=None) -> None:
        if event is not None:
            row = self.bookmark_list.identify_row(event.y)
        else:
            selected = self.bookmark_list.selection()
            row = selected[0] if selected else ""
        url = self.bookmark_targets.get(row)
        if not url:
            if row in self._bookmark_folder_keys:
                self.bookmark_list.item(row, open=not bool(self.bookmark_list.item(row, "open")))
            return
        try:
            if not url.lower().startswith(("http://", "https://")):
                raise ValueError("bookmark must use HTTP or HTTPS")
            plan = plan_open_target(url)
            self._navigate(plan.primary_url)
        except Exception as exc:
            # A failed bookmark must not grab every window with a modal error.
            notice = f"Bookmark unavailable — {exc}"
            self.status.set(notice)
            self.control_panel.report(notice)

    def _choose_window(self) -> None:
        picker = tk.Toplevel(self.root)
        picker.title("BoJangles windows")
        for browser in tuple(self.coordinator.browsers):
            tk.Button(picker, text=f"Browser — {browser.current_url or 'starting'}",
                      command=lambda window=browser: (window.root.deiconify(), window.root.lift(), picker.destroy())).pack(fill="x")
        for media in tuple(self.coordinator.media):
            tk.Button(picker, text="Media — " + media.window.title(),
                      command=lambda window=media: (window.window.deiconify(), window.window.lift(), picker.destroy())).pack(fill="x")

    def _toggle_maximize(self) -> None:
        previous = getattr(self, "_restored_geometry", None)
        if previous is not None:
            self.root.geometry(previous)
            self._restored_geometry = None
        else:
            self._restored_geometry = self.root.geometry()
            self.root.geometry(
                f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}+0+0"
            )

    def _start_child(self) -> None:
        try:
            self._initial_navigation()
            self.image_label.focus_set()
            self._surface_focus(True)
            self.root.after(20, self._pump_events)
            self.root.after(50, self._refresh_frame)
        except Exception as exc:
            self.status.set(f"Window failed — {exc}")
            self.close()

    def _page_media_candidates(self):
        backend = self.manager.backend if self.manager else None
        catalog = getattr(backend, "media_candidates", None)
        document_id = self.current_document_id
        if catalog is None or document_id is None:
            return None, ()
        return catalog, tuple(candidate for candidate in catalog.for_document(document_id)
                              if candidate.kind is not MediaKind.CAPTION)

    def _offer_drm_retry(self, event) -> None:
        document_id = event.document_id
        if document_id != self.current_document_id or document_id in self._drm_prompted_documents:
            return
        self._drm_prompted_documents.add(document_id)
        scheme = (event.drm_scheme or "DRM").strip() or "DRM"
        if scheme.casefold() == "widevine":
            message = "Content not available"
            self.status.set(message)
            self.control_panel.report(message)
            return
        if scheme.casefold() in {"fairplay", "playready"}:
            message = f"Protected media uses {scheme}; BoJangles Clear Key does not support it."
            self.status.set(message)
            self.control_panel.report(message)
            return
        if not messagebox.askyesno(
            "Protected media",
            f"{scheme} protected media detected.\n\nTry BoJangles DRM for this page?",
            parent=self.root,
        ):
            self.status.set("DRM left disabled for this page")
            return
        manager = self.manager
        if manager is None or "wpe-drm" not in manager.available_names:
            self.status.set("DRM retry unavailable")
            self.control_panel.report("DRM retry unavailable")
            return
        try:
            manager.switch_renderer("wpe-drm")
        except Exception as exc:
            self.status.set(f"DRM retry failed — {exc}")
            self.control_panel.report(f"DRM retry failed — {exc}")
            return
        self.status.set("DRM enabled for this page — retrying protected media")
        self.control_panel.report("DRM engine enabled for current document only")

    @staticmethod
    def _media_attachment_key(candidate):
        if candidate.kind in {MediaKind.HLS, MediaKind.DASH}:
            parsed = urlsplit(candidate.uri)
            return ("stream", parsed.scheme, parsed.netloc, parsed.path.rsplit("/", 1)[0])
        return candidate.uri

    def _live_media_attachment_identity(self, candidate):
        page = urlsplit(getattr(self, "current_url", ""))._replace(fragment="").geturl()
        if candidate.kind in {MediaKind.HLS, MediaKind.DASH}:
            # A source page may retry its stream on another CDN. Keep mirror
            # grouping page-scoped so unrelated pages retain independent audio.
            stream_path = urlsplit(candidate.uri).path.rsplit("/", 1)[0]
            return (page, "stream", stream_path)
        return (page, "file", candidate.uri)

    def _has_live_media_attachment(self, candidate):
        coordinator = getattr(self, "coordinator", None)
        identity = self._live_media_attachment_identity(candidate)
        return any(
            not getattr(window, "closed", False)
            and getattr(window, "_page_attachment_identity", None) == identity
            for window in getattr(coordinator, "media", ())
        )

    def _attach_page_media(self, event) -> bool:
        """Attach eligible current-page media once through the existing broker."""
        if (event.document_id != self.current_document_id or event.protected_media
                or getattr(self, "_history_media_suppressed_document_id", None) == self.current_document_id):
            return False
        catalog, candidates = self._page_media_candidates()
        candidate = next((item for item in candidates if item.uri == event.uri), None)
        if candidate is None or candidate.protection:
            return False
        if candidate.kind not in {MediaKind.FILE, MediaKind.HLS, MediaKind.DASH}:
            return False
        # A multi-video article index is a browsing page, not a request to
        # launch every preloaded clip. A directly opened media document remains
        # an explicit target; a single primary page player still auto-attaches.
        playable = {self._media_attachment_key(item) for item in candidates
                    if item.kind in {MediaKind.FILE, MediaKind.HLS, MediaKind.DASH, MediaKind.EMBED}
                    and not item.protection}
        if candidate.source != "document" and len(playable) > 1:
            return False
        if self._has_live_media_attachment(candidate):
            return False
        stream = candidate.kind in {MediaKind.HLS, MediaKind.DASH}
        # Wait for manifest inspection; fragments are not standalone movies.
        if stream and candidate.source == "html_hint":
            return False
        mime = candidate.mime_type.split(";", 1)[0].strip().lower()
        suffix = urlsplit(candidate.uri).path.lower().rsplit(".", 1)[-1]
        if not stream and (mime in {"video/mp2t", "video/iso.segment"}
                           or suffix in {"ts", "m4s", "cmfv", "cmfa"}):
            return False
        state = getattr(self, "_attached_page_media", None)
        if state is None or state[0] != self.current_document_id:
            state = (self.current_document_id, set())
            self._attached_page_media = state
        # Discovery can arrive incrementally. Once a primary player is attached,
        # later clips/variants must not multiply windows; explicit media choices
        # still use the ordinary broker and independent-window path.
        key = self._media_attachment_key(candidate)
        if state[1]:
            return False
        state[1].add(key)
        try:
            self._play_media_candidate(candidate, catalog)
        except Exception as exc:
            self.status.set(f"Page media unavailable — {exc}")
            self.control_panel.report(f"Page media unavailable — {exc}")
            return False
        from bojangles.diagnostics import record
        record("media_attachment", document_id=self.current_document_id,
               url=candidate.uri, kind=candidate.kind.value, source="automatic")
        return True

    def _offer_selected_live_stream(self, event) -> bool:
        """Consume one recent tile/link click for a real live HLS/DASH candidate."""
        pending = getattr(self, "_pending_stream_selection", None)
        if getattr(self, "_history_media_suppressed_document_id", None) == self.current_document_id:
            self._pending_stream_selection = None
            return False
        if pending is None:
            return False
        document_id, expiry, source_url, crossed_navigation = pending
        if (
            event.document_id != self.current_document_id
            or document_id != self.current_document_id
            or monotonic() > expiry
        ):
            self._pending_stream_selection = None
            return False
        if event.protected_media or event.detail not in {MediaKind.HLS.value, MediaKind.DASH.value}:
            return False
        catalog, candidates = self._page_media_candidates()
        candidate = next((
            item for item in candidates
            if item.uri == event.uri and item.kind in {MediaKind.HLS, MediaKind.DASH}
        ), None)
        if candidate is None:
            return False
        # Consume before launching so a burst of variant playlists cannot open
        # multiple players from one click.
        self._pending_stream_selection = None
        if self._has_live_media_attachment(candidate):
            return True
        try:
            self._play_media_candidate(candidate, catalog)
        except Exception as exc:
            self.status.set(f"Live stream unavailable — {exc}")
            self.control_panel.report(f"Live stream unavailable — {exc}")
            return True
        if crossed_navigation and source_url and source_url != self.current_url:
            # Keep the stream directory available behind the independent player.
            self.root.after_idle(lambda: self._cli_command("back"))
        return True

    def _play_media_candidate(self, candidate, catalog) -> None:
        document_id = self.current_document_id
        if document_id is None:
            return
        if len(self.coordinator.media) >= self.coordinator.MAX_MEDIA:
            raise WindowLimitReached("Media window limit reached")
        gesture = self.gestures.issue(document_id, actions={"media"})
        authorized = self.media_broker.authorize_candidate(
            document_id, candidate.candidate_id, gesture=gesture,
            candidates=catalog, request_channel=self.channel)
        active = self.coordinator.active_media
        start_muted = active is not None and not getattr(active, "closed", False)
        player_window = MediaWindow(self.coordinator.primary.root, authorized,
                                    self._media_closed, self.coordinator.activate_media,
                                    on_browser=lambda: self._return_to_browser(),
                                    on_back=lambda: self._return_to_browser(back=True),
                                    source_label=urlsplit(self.current_url).hostname or "page media",
                                    start_muted=start_muted)
        player_window._page_attachment_identity = self._live_media_attachment_identity(candidate)
        self.coordinator.add_media(player_window)
        state = getattr(self, "_attached_page_media", None)
        if state is None or state[0] != document_id:
            state = (document_id, set())
            self._attached_page_media = state
        state[1].add(self._media_attachment_key(candidate))

    def _media_closed(self, window) -> None:
        self.coordinator.remove_media(window)
        if not self.closed:
            self._return_to_browser()

    def _offer_requested_media(self, event) -> None:
        click = self._recent_page_click
        self._recent_page_click = None
        if click is None or click[0] != self.current_document_id or monotonic() - click[1] > 5:
            return
        if event.document_id != self.current_document_id:
            return
        catalog, candidates = self._page_media_candidates()
        candidate = next((item for item in candidates if item.uri == event.uri), None)
        if candidate is None:
            return
        if messagebox.askyesno("Play page video?",
                               "Open this video in a BoJangles media window?",
                               parent=self.root):
            try:
                self._play_media_candidate(candidate, catalog)
            except Exception as exc:
                messagebox.showerror("Media unavailable", str(exc), parent=self.root)

    def _go_address(self) -> None:
        target = self.address.get().strip()
        if target:
            self._cli_command(f"go {target}")

    def _return_to_browser(self, *, back: bool = False) -> None:
        if self.closed:
            return
        if back:
            self._cli_command("back")
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.image_label.focus_set()

    def _choose_media(self) -> None:
        document_id = self.current_document_id
        catalog, candidates = self._page_media_candidates()
        if not candidates:
            self.media_button.configure(state="disabled")
            return
        if len(candidates) == 1:
            try:
                self._play_media_candidate(candidates[0], catalog)
            except Exception as exc:
                messagebox.showerror("Media unavailable", str(exc), parent=self.root)
            return
        picker = tk.Toplevel(self.root)
        picker.title("Open page media")
        picker.transient(self.root)
        tk.Label(picker, text="Choose a page media source to open:").pack(fill="x")
        listing = tk.Listbox(picker, width=88, height=min(10, len(candidates)))
        listing.pack(fill="both", expand=True)
        for candidate in candidates:
            protection = (
                f" [{candidate.protection} protected]" if candidate.protection else ""
            )
            listing.insert(
                "end",
                f"{candidate.kind.value}{protection}: {candidate.uri}",
            )
        listing.selection_set(0)

        def selected() -> None:
            selection = listing.curselection()
            if not selection or self.current_document_id != document_id:
                return
            candidate = candidates[selection[0]]
            try:
                self._play_media_candidate(candidate, catalog)
                picker.destroy()
            except Exception as exc:
                messagebox.showerror("Media unavailable", str(exc), parent=picker)

        tk.Button(picker, text="Open selected", command=selected).pack(fill="x")

    def _read_cli(self) -> None:
        self.control_panel.run(self._cli_commands.put, lambda: self.closed)

    def _pump_cli(self) -> None:
        if self.closed:
            return
        try:
            while True:
                self._cli_command(self._cli_commands.get_nowait())
        except Empty:
            pass
        if not self.closed:
            self.root.after(40, self._pump_cli)

    def _cli_command(self, line: str) -> None:
        command, _, argument = line.strip().partition(" ")
        command = command.casefold()
        backend = self.manager.backend if self.manager else None
        if backend is None and self.current_url != HOME_URI and command != "media":
            self.control_panel.report("Renderer unavailable")
            return
        try:
            if command == "popup":
                from bojangles.popup_policy import snapshot, update
                import json
                action, _, value = argument.strip().partition(" ")
                if action in {"", "status"} and not value:
                    result = snapshot(self.current_url)
                elif action == "mode":
                    result = update(self.current_url, value.strip())
                elif action == "reset" and not value:
                    result = update(self.current_url, reset=True)
                else:
                    raise ValueError("Use popup status, popup mode balanced/strict, or popup reset")
                self.control_panel.report(json.dumps(result, indent=2))
                return
            if command == "blocking":
                action,_,value=argument.partition(" ")
                if action in {"","status"}:
                    import json
                    self.control_panel.report(json.dumps(self.channel.statistics.snapshot(value or "page"),indent=2))
                elif action=="reset-stats":self.channel.statistics.reset(value or "page")
                elif action in {"allow-page","allow-window","allow-site"}:
                    records=self.channel.statistics.snapshot()["recent"]
                    item=next((r for r in reversed(records) if r["rule"]==value.strip() and not r["exception"]),None)
                    if not item:raise ValueError("No matching recent optional block")
                    self._blocking_allow(item,action.split("-")[1])
                else:raise ValueError("Use blocking status [page/window], reset-stats [page/window], allow-page/window/site RULE_ID")
                self._update_blocking()
                return
            if command == "advertising":
                from bojangles.filter.advertising import update,origin
                action, _, value = argument.partition(" ")
                policy = self.channel.advertising
                if action in {"", "status"}:
                    import json
                    self.control_panel.report(json.dumps(policy.snapshot(), indent=2))
                elif action == "follow":
                    held = getattr(self, "_held_advertising_navigation", None)
                    if held is None or held[0] != self.current_document_id:
                        raise ValueError("No current held redirect")
                    self._held_advertising_navigation = None
                    self._follow_redirect(held[1], initiating_document=held[0], fresh_operator=True)
                elif action == "mode":
                    update(self.current_url, mode=value.strip())
                    policy.refresh()
                    self.control_panel.report("Advertising mode saved; reload to apply")
                elif action == "allow-session":
                    policy.allow_session(self.current_url, value.strip())
                    self.control_panel.report("Optional rule allowed for this site in this window")
                elif action == "allow-site":
                    update(self.current_url, allow=value.strip());policy.refresh()
                    self.control_panel.report("Optional site exception saved")
                elif action == "reset":
                    update(self.current_url, reset=True);policy.refresh()
                    policy.session = {entry for entry in policy.session if entry[0] != origin(self.current_url)}
                    self.control_panel.report("Site advertising preferences reset")
                else: raise ValueError("Use advertising status|follow|mode balanced/off|allow-session ID|allow-site ID|reset")
                return
            if command == "quit" and not argument:
                if backend is not None:
                    backend.cli_control(NativeMessage.TERMINATE)
                self.close()
                return
            if command == "status" and not argument:
                if backend is None:
                    self.control_panel.report(f"URL: {self.current_url}\nRenderer: trusted home")
                else:
                    state = backend.cli_control(NativeMessage.STATE_REQUEST)
                    self.control_panel.report(f"URL: {self.current_url}\nRenderer: {backend.lifecycle.value}\nNative URL: {state}")
                return
            if command == "print" and not argument:
                self._print_page()
                return
            if command == "media":
                center = self.coordinator.center()
                if argument in {"", "show"}:
                    self.coordinator.show_media_center()
                    self.control_panel.report("Media Center opened")
                elif argument == "download":
                    center.active_transfer()
                    self.control_panel.report("Active player download started")
                elif argument == "record":
                    center.active_transfer(recording=True)
                    self.control_panel.report("Active stream recording started")
                elif argument == "stop":
                    center.stop_recording()
                    self.control_panel.report("Recording stop requested")
                elif argument == "library":
                    center.sync()
                    self.control_panel.report(str(center.store.rows('library')))
                else:
                    raise ValueError("Use media show|download|record|stop|library")
                return
            if command == "downloads" and not argument:
                from .download_display import download_row
                items = self.downloads.snapshot()
                self.control_panel.report("\n".join(
                    f"{item.id}: {' · '.join(download_row(item))} — "
                    f"{item.path or item.directory / item.filename}"
                    for item in items) or "No downloads this session")
                return
            if command == "stop" and not argument:
                if backend is None:
                    self.control_panel.report("No page is loading")
                else:
                    backend.cli_control(NativeMessage.NAV_STOP)
                    self.control_panel.report("Loading stopped")
                return
            if command in {"back", "forward"} and not argument:
                previous_position = self.history.position
                target_position = previous_position - 1 if command == "back" else previous_position + 1
                if target_position < 0 or target_position >= len(self.history.entries):
                    self.control_panel.report("No page in that direction")
                    return
                departure_url = self.current_url
                next_url = self.history.entries[target_position]
                # One command owns exactly one frontend history step.
                # Renderer/native history must not advance the position again.
                self._history_direction = command
                self._history_departure_url = departure_url
                self._history_move = True
                self.history.position = target_position
                try:
                    self._navigate(next_url)
                except Exception:
                    self.history.position = previous_position
                    raise
                finally:
                    self._history_move = False
                return
            if command == "refresh" and not argument:
                self._history_direction = "refresh"
                self._history_departure_url = self.current_url
                self._history_move = True
                try:
                    self._navigate(self.current_url)
                finally:
                    self._history_move = False
                return
            if command == "go" and argument.strip():
                plan = plan_open_target(argument.strip())
                self._navigate(plan.primary_url)
                return
            self.control_panel.report("Use: back, forward, refresh, stop, go <url>, status, downloads, quit")
        except Exception as exc:
            self.control_panel.report(f"Command failed: {exc}")

    def _queue_surface_resize(self, event=None) -> None:
        if self.closed:
            return
        timer = getattr(self, "_resize_timer", None)
        if timer is not None:
            self.root.after_cancel(timer)
        self._resize_timer = self.root.after(80, self._resize_surface)

    def _resize_surface(self) -> None:
        self._resize_timer = None
        if self.closed or not self.image_label.winfo_ismapped():
            return
        width = self.image_label.winfo_width()
        height = self.image_label.winfo_height()
        if width <= 1 or height <= 1 or (width, height) == (self.WIDTH, self.HEIGHT):
            return
        if width > 16384 or height > 16384 or width * height * 4 > 512 * 1024 * 1024:
            self.status.set("Window is too large for the renderer")
            return
        replacement = SharedFramebuffer.create(width, height, pixel_format="ABGR8888")
        try:
            if self.manager is not None:
                self.manager.backend.resize_framebuffer(Viewport(width, height), replacement.target())
        except Exception as exc:
            replacement.close()
            self.status.set(f"Viewport resize failed — {exc}")
            return
        previous = self.plane
        self.plane = replacement
        self.WIDTH, self.HEIGHT = width, height
        previous.close()

    def _refresh_frame(self) -> None:
        if self.closed:
            return

        if self.current_url == HOME_URI:
            self.root.after(100, self._refresh_frame)
            return

        try:
            raw = self.plane.bytes()
            rgb = abgr_to_rgb(raw)
            display_width, display_height = self.WIDTH, self.HEIGHT

            header = (
                f"P6\n{display_width} {display_height}\n255\n"
            ).encode("ascii")

            image = tk.PhotoImage(
                data=header + rgb,
                format="PPM",
            )

            self.photo = image
            self.image_label.configure(image=image)

        except tk.TclError as exc:
            self.status.set(
                f"Framebuffer presentation error — {exc}"
            )

        self.root.after(100, self._refresh_frame)

    def _claim_address_focus(self, event=None) -> None:
        """A trusted address-bar click must win over page/renderer focus."""
        self._surface_focus(False)
        try:
            self.address_entry.focus_force()
        except tk.TclError:
            pass

    def _address_selected_text(self) -> str | None:
        try:
            if not self.address_entry.selection_present():
                return None
            first = self.address_entry.index("sel.first")
            last = self.address_entry.index("sel.last")
            return self.address_entry.get()[first:last]
        except tk.TclError:
            return None

    def _address_copy(self) -> None:
        """Copy selected text, or the trusted current page URL when unselected."""
        text = self._address_selected_text()
        if text is None:
            text = self.current_url or self.address_entry.get()
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
            self.status.set("Address copied to system clipboard")
        except tk.TclError as exc:
            self.status.set(f"Clipboard unavailable — {exc}")

    def _address_cut(self) -> None:
        selected = self._address_selected_text()
        if selected is None:
            return
        try:
            first = self.address_entry.index("sel.first")
            last = self.address_entry.index("sel.last")
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
            self.address_entry.delete(first, last)
            self.root.update_idletasks()
        except tk.TclError as exc:
            self.status.set(f"Clipboard unavailable — {exc}")

    def _address_paste(self) -> None:
        try:
            text = self.root.clipboard_get()
            if self.address_entry.selection_present():
                first = self.address_entry.index("sel.first")
                last = self.address_entry.index("sel.last")
                self.address_entry.delete(first, last)
                self.address_entry.icursor(first)
            self.address_entry.insert("insert", text)
        except tk.TclError as exc:
            self.status.set(f"Clipboard unavailable — {exc}")

    def _address_select_all(self) -> None:
        try:
            self.address_entry.selection_range(0, "end")
            self.address_entry.icursor("end")
            self.address_entry.focus_force()
        except tk.TclError:
            return

    @staticmethod
    def _post_context_menu(menu, x: int, y: int) -> None:
        """Keep Tk's popup grab until selection or cancellation restores focus."""
        def cancel(event):
            menu.tk.call("tk::MenuUnpost", str(menu))
            return "break"

        # Consume Escape before window/global shortcuts, and never interpret
        # a second right click as choosing the highlighted command.
        menu.bind("<Escape>", cancel)
        menu.bind("<ButtonPress-3>", cancel)
        menu.bind("<ButtonRelease-3>", lambda event: "break")
        try:
            menu.tk_popup(x, y)
        except Exception:
            menu.tk.call("tk::MenuUnpost", str(menu))
            raise
        # tk_popup returns immediately. Releasing its grab here would disable
        # the Menu class's outside-click cancellation on X11.

    def _show_field_context_menu(self, event) -> str:
        """Use Tk's own editing commands for application-owned text widgets."""
        from .context_menu import field_menu
        return field_menu(event)

    def _show_address_context_menu(self, event) -> str:
        from .context_menu import field_menu
        self._claim_address_focus(event)
        return field_menu(event)

    def _restore_surface_focus_if_current(self) -> None:
        """Never steal trusted chrome or another window's focus."""
        try:
            focused = self.root.focus_get()
            if focused is self.image_label:
                self._surface_focus(True)
                return
            if focused is not self.root:
                return
            self.image_label.focus_set()
            self._surface_focus(True)
        except tk.TclError:
            return

    def _renderer_failed(self, manager, document_id: str, detail: str) -> None:
        """One fresh-document GET recovery; never replay input or a submitted body."""
        if manager is not self.manager or document_id != self.current_document_id:
            return
        request = manager.current_request
        now = monotonic()
        previous = getattr(self, "_renderer_recovery_at", None)
        retry = (request is not None and request.method == "GET"
                 and urlsplit(self.current_url).scheme.lower() in {"http", "https"}
                 and (previous is None or now - previous >= 60.0))
        notice = ("Renderer disconnected — recovering page; unsaved form input may be lost"
                  if retry else "Renderer disconnected — use Reload to reopen the page")
        self.status.set(notice)
        self.control_panel.report(notice + ": " + detail)
        if not retry:
            return
        self._renderer_recovery_at = now
        target = self.current_url
        def recover():
            if (self.closed or self.manager is not manager
                    or self.current_document_id != document_id):
                return
            try:
                self._navigate(target, replace_history=True)
            except Exception as exc:
                self.status.set(f"Renderer recovery failed — use Reload: {exc}")
        self.root.after_idle(recover)

    def _surface_focus(self, focused: bool) -> None:
        backend = self.manager.backend if self.manager else None
        if backend is not None and hasattr(backend, "set_focused"):
            try:
                backend.set_focused(focused)
            except (OSError, RuntimeError):
                # Focus is advisory. Lifecycle failure is handled by the event pump.
                return

    def _send(self, event) -> None:
        manager = self.manager

        if manager is None or manager.backend is None:
            return
        if manager.backend.lifecycle is not RendererLifecycle.RUNNING:
            return
        if hasattr(manager.backend, "set_focused") and self.root.focus_get() is not self.image_label:
            return

        if isinstance(event, str) or (isinstance(event, dict)
                and event.get("kind") in {"button", "key"} and event.get("pressed")):
            self._history_restore_document_id = None
        try:
            manager.backend.input(event)
        except Exception as exc:
            self.status.set(f"Input rejected — {exc}")

    def _pointer(self, event) -> None:
        x, y = surface_point(
            event.x, event.y,
            self.WIDTH, self.HEIGHT,
            self.WIDTH, self.HEIGHT,
        )
        self._send(
            {
                "kind": "pointer",
                "x": x,
                "y": y,
            }
        )

    def _release_surface_buttons(self) -> None:
        backend = self.manager.backend if self.manager else None
        buttons = self._surface_buttons_down
        self._surface_buttons_down = set()
        if backend is not None:
            for button in sorted(buttons):
                backend.input({"kind": "button", "button": button, "pressed": False})

    def _button(self, event, pressed: bool) -> None:
        button = int(event.num)
        if not pressed and button not in self._surface_buttons_down:
            return
        if pressed:
            self._surface_buttons_down.add(button)
        else:
            self._surface_buttons_down.discard(button)
        if pressed and button == 3:
            self._spelling_point = (event.x_root, event.y_root)
            if int(event.state) & 1:
                token = object()
                self._region_force_token = token
                self.root.after(350, lambda m=self.manager,d=self.current_document_id,t=token: self._region_fallback(m,d,t))
        if pressed and int(event.num) == 1 and self.current_document_id is not None:
            now = monotonic()
            self._recent_page_click = (self.current_document_id, now)
            self._pending_stream_selection = (
                self.current_document_id, now + 12.0, self.current_url, False
            )
            current = urlsplit(self.current_url)
            if current.scheme.lower() in {"http", "https"} and current.hostname:
                self._click_bridge_origin = (
                    current.scheme.lower(), current.hostname, current.port
                )
                self._click_bridge_document_id = self.current_document_id
            else:
                self._click_bridge_origin = None
                self._click_bridge_document_id = None
        if pressed:
            # A physical page click is an explicit focus transfer. Tk's
            # focus_set alone waits for activation when another toplevel owns
            # X focus, dropping this click at the input guard in the meantime.
            self.root.focus_force()
            self.image_label.focus_set()
            self._surface_focus(True)
        self._pointer(event)

        self._send(
            {
                "kind": "button",
                "button": int(event.num),
                "pressed": bool(pressed),
            }
        )

    def _wheel(self, event, dx: int, dy: int) -> str:
        # Wheel input is pointer-directed; chrome may still own keyboard focus.
        self.image_label.focus_set()
        self._surface_focus(True)
        self._pointer(event)
        if event.state & 1:  # Shift + wheel scrolls horizontally.
            dx, dy = dy, dx
        self._send({"kind": "scroll", "dx": dx, "dy": dy})
        return "break"

    def _wheel_up(self, event) -> str:
        return self._wheel(event, 0, -80)

    def _wheel_down(self, event) -> str:
        return self._wheel(event, 0, 80)

    def _mouse_wheel(self, event) -> str:
        return self._wheel(event, 0, round(-event.delta * 80 / 120))

    def _show_snapshot_options(self):
        from .page_snapshot import FORMATS
        manager, document = self.manager, self.current_document_id
        if manager is None or document is None:
            self.status.set("Open a webpage to save a snapshot")
            return
        old = getattr(self, '_snapshot_panel', None)
        if old is not None:
            old.destroy()
        panel = self._snapshot_panel = tk.LabelFrame(self.content_frame, text="Save Snapshot", padx=8, pady=8)
        panel.pack(fill='x', before=self.image_label)
        tk.Label(panel, text="Capture the current page. Unloaded content may be absent. HTML ZIP is a passive offline copy; MHTML may retain active content.",
                 wraplength=750, justify='left').pack(anchor='w')
        row = tk.Frame(panel)
        row.pack(anchor='w')
        for label, format, extension in FORMATS:
            enabled = callable(getattr(manager.backend, 'print_pdf' if format == 'pdf' else 'export_page', None))
            tk.Button(row, text=label, state='normal' if enabled else 'disabled',
                      command=lambda f=format,e=extension: self._save_page_snapshot(manager, document, f, e)).pack(side='left', padx=3)
        tk.Button(row, text="Close", command=lambda: (panel.destroy(), setattr(self, '_snapshot_panel', None))).pack(side='left', padx=3)

    def _save_page_snapshot(self, manager, document, format, extension):
        from .page_snapshot import capture, save_snapshot
        def valid():
            return not self.closed and self.manager is manager and self.current_document_id == document
        if not valid():
            self.status.set("Page changed — reopen Save Snapshot")
            return
        if getattr(self, '_snapshot_pending', False):
            self.status.set("A snapshot is already being saved")
            return
        name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', self.page_title or 'page')[:100]
        try:
            path = choose_save_path(parent=self.root, title="Save Snapshot",
                initialfile=name + extension, defaultextension=extension,
                filetypes=[("Snapshot", "*" + extension)])
        except Exception as exc:
            self.status.set(f"Snapshot failed — {exc}")
            return
        if not path:
            self.status.set("Snapshot cancelled")
            return
        if not valid():
            self.status.set("Page changed — snapshot cancelled")
            return
        self._snapshot_pending = True
        self.status.set("Saving current page snapshot…")
        result = Queue(maxsize=1)
        def export():
            try:
                data = capture(manager.backend, format)
                if not valid():
                    raise RuntimeError("Page changed before capture completed")
                # Publication is performed on the UI thread after a final document check.
                result.put((data, None))
            except Exception as exc:
                result.put((None, str(exc)))
        def finish():
            if self.closed:
                self._snapshot_pending = False
                return
            try:
                data, error = result.get_nowait()
            except Empty:
                self.root.after(20, finish)
                return
            self._snapshot_pending = False
            try:
                if error: raise RuntimeError(error)
                if not valid(): raise RuntimeError("Page changed before save completed")
                save_snapshot(path, data)
                self.status.set(f"Snapshot saved — {path}")
            except Exception as exc:
                self.status.set(f"Snapshot failed — {exc}")
        try:
            Thread(target=export, daemon=True, name="bojangles-snapshot").start()
            self.root.after(20, finish)
        except Exception as exc:
            self._snapshot_pending = False
            self.status.set(f"Snapshot failed — {exc}")

    def _print_page(self, event=None):
        from .printing import available_printers
        if getattr(self, "_print_pending", False):
            dialog = getattr(self, "_print_dialog", None)
            if dialog is not None:
                dialog.lift()
            self.status.set("Print options are open" if dialog is not None else
                            "Printing is already in progress")
            return "break"
        manager, document = self.manager, self.current_document_id
        self._print_pending = True
        printers = Queue(maxsize=1)
        def discover():
            try:
                printers.put((available_printers(), None))
            except Exception as exc:
                printers.put(((), str(exc)))
        deadline = monotonic() + 5
        try:
            Thread(target=discover, daemon=True, name="bojangles-printers").start()
        except Exception as exc:
            self._print_pending = False
            self.status.set(f"Printer check failed — {exc}")
            return "break"
        self.status.set("Checking configured printers…")
        def ready():
            if self.closed or self.manager is not manager or self.current_document_id != document:
                self._print_pending = False
                return
            try:
                choices, error = printers.get_nowait()
            except Empty:
                if monotonic() < deadline:
                    self.root.after(20, ready)
                    return
                choices, error = (), "Printer check timed out"
            try:
                self._show_print_dialog(manager, document, choices)
                if error:
                    self.status.set(f"Printer check failed — {error}")
            except Exception as exc:
                self._cancel_print_dialog()
                self.status.set(f"Print options unavailable — {exc}")
        self.root.after(20, ready)
        return "break"

    def _cancel_print_dialog(self):
        dialog = getattr(self, "_print_dialog", None)
        self._print_dialog = None
        self._print_pending = False
        if dialog is not None:
            try:
                dialog.destroy()
            except tk.TclError:
                pass

    def _show_print_dialog(self, manager, document, printers):
        printable = (manager is not None and document is not None
                     and self.current_url != HOME_URI
                     and callable(getattr(manager.backend, "print_pdf", None)))
        dialog = self._print_dialog = tk.Toplevel(self.root)
        dialog.title("Print page" if printable else "Print options")
        dialog.transient(self.root)
        destination = tk.StringVar(dialog, value="Save as PDF")
        paper = tk.StringVar(dialog, value="Letter")
        tk.Label(dialog, text="Destination").grid(row=0, column=0, padx=12, pady=10, sticky="w")
        destinations = ("Save as PDF",) + tuple(printers)
        ttk.Combobox(dialog, textvariable=destination, values=destinations, state="readonly", width=30).grid(row=0, column=1, padx=12)
        tk.Label(dialog, text="Paper size").grid(row=1, column=0, padx=12, pady=10, sticky="w")
        ttk.Combobox(dialog, textvariable=paper, values=("Letter", "A4"), state="readonly", width=30).grid(row=1, column=1, padx=12)
        information = ("Configured printers: " + ", ".join(printers) if printers else
                       "No printer is configured. You can save an open page as PDF.")
        if not printable:
            information += "\nOpen a web page to print; checking printers sends no job."
        tk.Label(dialog, text=information, wraplength=420, justify="left").grid(
            row=2, column=0, columnspan=2, padx=12, pady=8)
        def valid():
            return (not self.closed and self.manager is manager
                    and self.current_document_id == document)
        def cancel(event=None):
            self._cancel_print_dialog()
            if not self.closed:
                self.status.set("Print cancelled")
            return "break"
        def submit():
            if not printable or not valid():
                cancel()
                return
            target = destination.get()
            selected_paper = "a4" if paper.get() == "A4" else "letter"
            path = None
            if target == "Save as PDF":
                name = re.sub(r'[\/:*?"<>|]', '_', self.page_title or 'page')[:100]
                try:
                    path = choose_save_path(parent=dialog, title="Save page as PDF",
                        initialfile=name + ".pdf", defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
                except Exception as exc:
                    cancel()
                    self.status.set(f"Print failed — {exc}")
                    return
                if not valid() or self._print_dialog is not dialog:
                    cancel()
                    return
                if not path:
                    return
            elif target not in printers:
                return
            self._print_dialog = None
            dialog.destroy()
            try:
                self._start_print(manager, document, selected_paper, path=path,
                                  printer=None if path else target)
            except Exception as exc:
                self._print_pending = False
                self.status.set(f"Print failed — {exc}")
        buttons = tk.Frame(dialog)
        buttons.grid(row=3, column=0, columnspan=2, padx=12, pady=12, sticky="e")
        tk.Button(buttons, text="Cancel", command=cancel).pack(side="left", padx=5)
        tk.Button(buttons, text="Print", command=submit,
                  state="normal" if printable else "disabled").pack(side="left")
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        dialog.bind("<Escape>", cancel)
        self.status.set("Choose a print destination" if printable else
                        "Open a web page to print — configured printers checked")
        # Options must never own a grab: browser input/navigation stays usable.
        def watch():
            if self._print_dialog is not dialog:
                return
            if not valid():
                cancel()
                return
            self.root.after(100, watch)
        self.root.after(100, watch)

    def _start_print(self, manager, document, paper, *, path=None, printer=None):
        from .printing import save_pdf, send_pdf_to_printer
        result = Queue(maxsize=1)
        self.status.set("Printing page…")
        def export():
            try:
                pdf = manager.backend.print_pdf(paper)
                if self.closed or self.manager is not manager or self.current_document_id != document:
                    raise RuntimeError("Page changed before printing completed")
                if path:
                    save_pdf(path, pdf)
                    message = f"PDF saved — {path}"
                else:
                    send_pdf_to_printer(printer, pdf)
                    message = f"Sent to printer — {printer}"
                result.put((message, None))
            except Exception as exc:
                result.put((None, str(exc)))
        def finish():
            if self.closed:
                self._print_pending = False
                return
            try:
                message, error = result.get_nowait()
            except Empty:
                self.root.after(20, finish)
                return
            self._print_pending = False
            self.status.set(f"Print failed — {error}" if error else message)
        Thread(target=export, daemon=True, name="bojangles-print").start()
        self.root.after(20, finish)

    def _show_popup_policy(self) -> None:
        from tkinter import simpledialog
        from bojangles.popup_policy import snapshot, update
        try:
            policy = snapshot(self.current_url)
            mode = simpledialog.askstring("Popup blocking", "Mode for " + policy["origin"] +
                "\nEnter balanced or strict. Strict blocks page-created windows, including click-triggered requests.",
                initialvalue=policy["mode"], parent=self.root)
            if mode is not None:
                result = update(self.current_url, mode.strip().casefold())
                self.status.set("Popup mode saved: " + result["mode"])
        except (ValueError, OSError) as exc:
            self.status.set("Popup preferences: " + str(exc))

    def _open_link_from_menu(self, menu, uri: str, manager, document_id: str) -> None:
        # Opening a window redraws the browser tabs and changes focus. Finish
        # the popup's pointer/keyboard grab before that transition starts.
        menu.tk.call("tk::MenuUnpost", str(menu))
        self.root.after_idle(lambda: self._open_link_window(uri, manager, document_id))

    def _open_link_window(self, uri: str, manager, document_id: str) -> None:
        """Open the explicitly selected link while its source page is current."""
        if self.closed or self.manager is not manager or self.current_document_id != document_id:
            return
        try:
            if not uri or len(uri.encode("utf-8")) > 8192 or urlsplit(uri).scheme.casefold() not in {"http", "https"}:
                raise ValueError("link requires an HTTP or HTTPS destination")
            target = plan_open_target(uri).primary_url
            if isinstance(self.channel, RendererRequestBroker):
                decision = self.channel.decide(ResourceRequest(document_id, target,
                    ResourceType.DOCUMENT, self.documents.require(document_id).uri,
                    phase="preflight"))
                if not decision.allow:
                    self.status.set("New window blocked: " + decision.reason)
                    return
            if self._open_browser_window(target, from_page_gesture=True) is not None:
                self.status.set("Opened link in new window — " + target)
                self.control_panel.report("Opened link in new window — " + target)
        except ValueError as exc:
            self.status.set("Cannot open link: " + str(exc))

    def _copy_link_address(self, uri: str, manager, document_id: str) -> None:
        """Copy the right-clicked address only while its document is current."""
        if self.closed or self.manager is not manager or self.current_document_id != document_id:
            return
        if not uri or len(uri.encode("utf-8")) > 8192 or any(c in uri for c in "\0\r\n"):
            return
        try:
            from .link_clipboard import copy_link
            copy_link(self.root, uri)
            self.status.set("Link address copied to system clipboard")
        except tk.TclError as exc:
            self.status.set(f"System clipboard unavailable — {exc}")

    def _cut(self, event=None) -> str:
        return self._copy(event, cut=True)

    def _copy(self, event=None, *, cut=False) -> str:
        action = "Cut" if cut else "Copy"
        backend = self.manager.backend if self.manager else None
        copy_selection = getattr(backend, "copy_selection", None)
        cut_selection = getattr(backend, "cut_rich_selection", None)
        if not callable(cut_selection if cut else copy_selection):
            self.status.set(f"{action} unavailable for this view")
            return "break"
        try:
            rich_copy = getattr(backend, "copy_rich_selection", None)
            text, html = cut_selection() if cut else (rich_copy() if callable(rich_copy) else (copy_selection(), ""))
        except Exception as exc:
            self.status.set(f"{action} failed — {exc}")
            return "break"
        if not text and not html:
            self.status.set("Nothing selected")
            return "break"
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            if html:
                self.root.clipboard_append(html, type="text/html", format="UTF8_STRING")
            self.root.update_idletasks()
        except tk.TclError as exc:
            self.status.set(f"System clipboard unavailable — {exc}")
            return "break"
        self.status.set("Cut selection to system clipboard" if cut else "Copied selection to system clipboard")
        return "break"

    def _paste_picture(self, target):
        from .clipboard_image import read_clipboard_image
        if getattr(self, "_clipboard_image_pending", False):
            return "break"
        manager, document = self.manager, self.current_document_id
        result = Queue(maxsize=1)
        self._clipboard_image_pending = True
        def acquire():
            try:
                result.put((read_clipboard_image(target), None))
            except Exception as exc:
                result.put((None, str(exc)))
        def finish():
            if self.closed or self.manager is not manager or self.current_document_id != document:
                self._clipboard_image_pending = False
                return
            try:
                png, error = result.get_nowait()
            except Empty:
                self.root.after(20, finish)
                return
            self._clipboard_image_pending = False
            if error:
                self.status.set(f"Picture paste failed — {error}")
                return
            try:
                self._restore_surface_focus_if_current()
                manager.backend.paste_png(png)
            except Exception as exc:
                self.status.set(f"Picture paste failed — {exc}")
                return
            self.status.set("Picture sent to page clipboard")
        Thread(target=acquire, daemon=True, name="bojangles-clipboard-image").start()
        self.root.after(20, finish)
        return "break"

    def _paste_html(self):
        from .clipboard_html import read_clipboard_html
        if getattr(self, "_clipboard_html_pending", False):
            return "break"
        manager, document = self.manager, self.current_document_id
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            text = ""
        result = Queue(maxsize=1)
        self._clipboard_html_pending = True
        def acquire():
            try:
                result.put((read_clipboard_html(), None))
            except Exception as exc:
                result.put((None, str(exc)))
        def finish():
            if self.closed or self.manager is not manager or self.current_document_id != document:
                self._clipboard_html_pending = False
                return
            try:
                html, error = result.get_nowait()
            except Empty:
                self.root.after(20, finish)
                return
            self._clipboard_html_pending = False
            if error:
                self.status.set(f"HTML paste failed — {error}")
                return
            try:
                self._restore_surface_focus_if_current()
                manager.backend.paste_rich(text, html)
                self.status.set("Pasted HTML from system clipboard")
            except Exception as exc:
                self.status.set(f"HTML paste failed — {exc}")
        Thread(target=acquire, daemon=True, name="bojangles-clipboard-html").start()
        self.root.after(20, finish)
        return "break"

    def _paste(self, event=None) -> str:
        from .clipboard_image import IMAGE_TARGETS
        try:
            targets = self.root.selection_get(selection="CLIPBOARD", type="TARGETS")
        except tk.TclError:
            targets = ""
        if isinstance(targets, str):
            available = self.root.tk.splitlist(targets)
            if "text/html" in available:
                return self._paste_html()
            target = next((item for item in IMAGE_TARGETS if item in available), None)
            if target:
                return self._paste_picture(target)
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            self.status.set("System clipboard is empty or unavailable")
            return "break"
        if not text:
            self.status.set("System clipboard is empty")
            return "break"

        backend = self.manager.backend if self.manager else None
        paste_text = getattr(backend, "paste_text", None)
        if not callable(paste_text):
            self.status.set("Paste unavailable for this view")
            return "break"
        try:
            paste_text(text)
        except Exception as exc:
            self.status.set(f"Paste failed — {exc}")
            return "break"
        self.status.set("Pasted from system clipboard")
        return "break"

    def _key_press(self, event) -> str | None:
        special = {
            "Return": "Enter",
            "KP_Enter": "Enter",
            "BackSpace": "Backspace",
            "Tab": "Tab",
            "ISO_Left_Tab": "Tab",
            "Escape": "Escape",
            "Left": "ArrowLeft",
            "Right": "ArrowRight",
            "Up": "ArrowUp",
            "Down": "ArrowDown",
            "Home": "Home",
            "End": "End",
            "Prior": "PageUp",
            "Next": "PageDown",
            "Delete": "Delete",
            "KP_Delete": "Delete",
        }

        # Named editing/navigation keys must win over Tk's character field.
        # On X11 Delete can arrive as character 127; sending that as text makes
        # WebKit ignore the physical forward-delete operation.
        key = special.get(event.keysym)
        # Keep selection and undo/redo inside WebKit's native editor. Tk's
        # control-character events do not enter the printable-text path.
        if key is None and event.state & 0x04 and event.keysym.lower() in {"a", "z", "y"}:
            key = event.keysym.lower()
        if key is not None:
            self._send(
                {
                    "kind": "key",
                    "key": key,
                    "modifiers": _wpe_key_modifiers(int(event.state)),
                    "pressed": True,
                }
            )
            return "break"

        # Printable text is sent through the renderer's typed text path.
        if (
            event.char
            and ord(event.char[0]) >= 0x20
            and not (event.state & 0x0C)
        ):
            self._send(event.char)
            return "break"

        return None

    def _key_release(self, event) -> str | None:
        special = {
            "Return": "Enter",
            "KP_Enter": "Enter",
            "BackSpace": "Backspace",
            "Tab": "Tab",
            "ISO_Left_Tab": "Tab",
            "Escape": "Escape",
            "Left": "ArrowLeft",
            "Right": "ArrowRight",
            "Up": "ArrowUp",
            "Down": "ArrowDown",
            "Home": "Home",
            "End": "End",
            "Prior": "PageUp",
            "Next": "PageDown",
            "Delete": "Delete",
            "KP_Delete": "Delete",
        }

        key = special.get(event.keysym)
        # Keep selection and undo/redo inside WebKit's native editor. Tk's
        # control-character events do not enter the printable-text path.
        if key is None and event.state & 0x04 and event.keysym.lower() in {"a", "z", "y"}:
            key = event.keysym.lower()

        if key is not None:
            self._send(
                {
                    "kind": "key",
                    "key": key,
                    "modifiers": _wpe_key_modifiers(int(event.state)),
                    "pressed": False,
                }
            )
            return "break"

        return None

    def _bind_input(self) -> None:
        surface = self.image_label
        surface.bind('<Menu>', self._region_keyboard_page)
        surface.bind('<Shift-F10>', self._region_keyboard_page)

        surface.bind("<Motion>", self._pointer)
        surface.bind("<FocusIn>", lambda event: self._surface_focus(True))
        surface.bind("<FocusOut>", lambda event: self._surface_focus(False))

        for button in (1, 2, 3):
            surface.bind(
                f"<ButtonPress-{button}>",
                lambda event, down=True:
                    self._button(event, down),
            )
            surface.bind(
                f"<ButtonRelease-{button}>",
                lambda event, down=False:
                    self._button(event, down),
            )

        surface.bind("<Button-4>", self._wheel_up)
        surface.bind("<Button-5>", self._wheel_down)
        surface.bind("<MouseWheel>", self._mouse_wheel)

        self.root.bind("<Control-p>", self._print_page)
        self.root.bind("<Control-P>", self._print_page)
        surface.bind("<Control-x>", self._cut)
        surface.bind("<Control-X>", self._cut)
        surface.bind("<Shift-Delete>", self._cut)
        surface.bind("<Control-c>", self._copy)
        surface.bind("<Control-C>", self._copy)
        surface.bind("<Control-Insert>", self._copy)
        surface.bind("<Control-v>", self._paste)
        surface.bind("<Control-V>", self._paste)
        surface.bind("<Shift-Insert>", self._paste)

        surface.bind("<KeyPress>", self._key_press)
        surface.bind("<KeyRelease>", self._key_release)

        surface.bind(
            "<ButtonPress>",
            lambda event: surface.focus_set(),
            add="+",
        )

    def close(self) -> None:
        if self.closed:
            return

        self.closed = True
        if hasattr(self, '_updates'):
            self._updates.cancel.set()
        if isinstance(getattr(self,"channel",None),RendererRequestBroker):
            from bojangles.diagnostics import record
            self.channel.statistics.close()
            record("blocking_summary",**self.channel.statistics.snapshot("window")["counts"])
        if getattr(self, "_print_dialog", None) is not None:
            self._cancel_print_dialog()
        cancellation = getattr(self, "_translation_cancel", None)
        if cancellation is not None:
            cancellation.set()
        try:
            # One click on the window-manager × must disappear immediately.
            # Renderer/resource teardown remains synchronous so the framebuffer
            # stays valid until WPE has finished with it.
            self.root.withdraw()
        except tk.TclError:
            pass

        if self.search_listener is not None:
            self.search_listener.close()
            self.search_listener = None
        if self.owner is None:
            self.coordinator.close_all()
        else:
            self.coordinator.remove_browser(self)

        try:
            if self.manager is not None:
                self.manager.stop()
        finally:
            self.documents.clear()
            self.renderer_factories = None
            self.plane.close()
            self.home_surface.hide()
            self.root.destroy()

    def run(self) -> int:
        try:
            self._initial_navigation()
            if self.owner is None:
                listener = BrowserSearchListener()
                try:
                    if listener.start():
                        self.search_listener = listener
                        self.root.after(40, self._pump_search_handoff)
                except (OSError, PermissionError) as exc:
                    self.status.set(f"Search handoff unavailable — {exc}")
            self._cli_thread = Thread(target=self._read_cli, name="bojangles-cli", daemon=True)
            self._cli_thread.start()

            self.image_label.focus_set()
            self._surface_focus(True)

            self.root.after(20, self._pump_events)
            self.root.after(20, self._pump_cli)
            self.root.after(50, self._refresh_frame)

            self.root.mainloop()
            return 0

        finally:
            if not self.closed:
                self.close()
            if self._cli_thread is not None and self._cli_thread.is_alive():
                self._cli_thread.join(timeout=2.0)


def run_windowed(
    target: str | None,
    *,
    renderer_factories=None,
    renderer_name: str = "wpe",
    multi_window: bool = False,
) -> int:
    from bojangles.update_notifications import session_lock, dispatch_pending
    try:
        with session_lock():
            if renderer_name == "wpe" and not multi_window:
                return WindowSession(target, renderer_factories=renderer_factories).run()
            return WindowSession(
                target, renderer_factories=renderer_factories,
                renderer_name=renderer_name, multi_window=multi_window,
            ).run()
    finally:
        # The installer runs only after the UI and renderer have closed and this
        # process has relinquished its shared lock. Other sessions still block it.
        try: dispatch_pending()
        except Exception: pass
