"""Session-only limits and audio focus for BoJangles-owned windows."""
from __future__ import annotations

from bojangles.media.mpris import MprisController
from bojangles.downloads import DownloadSession


class WindowLimitReached(RuntimeError):
    pass


class WindowCoordinator:
    MAX_MEDIA = 99

    def __init__(self, primary) -> None:
        self.downloads = DownloadSession()
        self.media_center = None
        self.recording_reminder = None
        self.center_window = None
        self.primary = primary
        self.browsers = {primary}
        self.media = set()
        self._media_order = []
        self.active_media = None
        self._audio_order = []
        self.mpris = MprisController(self, getattr(primary, "root", None))

    def center(self):
        if self.media_center is None:
            from bojangles.media.center import MediaCenter
            from .recording_reminder import RecordingReminder
            self.recording_reminder = RecordingReminder(self.primary.root)
            self.media_center = MediaCenter(on_recording_started=self.recording_reminder.started)
            for window in self.media:
                media = getattr(window, 'authorized_media', None)
                if media is not None:
                    self.media_center.register(window, media)
            self.media_center.activate(self.active_media)
        return self.media_center

    def show_media_center(self):
        from bojangles.media.center_window import CenterWindow
        if self.center_window is None or self.center_window.closed:
            self.center_window = CenterWindow(self.primary.root, self.center(), self)
        else:
            self.center_window.window.lift()

    def add_browser(self, browser) -> None:
        self.browsers.add(browser)
        self.refresh_tabs()

    def remove_browser(self, browser) -> None:
        self.browsers.discard(browser)
        self.refresh_tabs()

    def add_media(self, window) -> None:
        if len(self.media) >= self.MAX_MEDIA:
            raise WindowLimitReached(f"limit of {self.MAX_MEDIA} media windows reached")
        self.media.add(window)
        if self.media_center is not None and hasattr(window, 'authorized_media'):
            self.media_center.register(window, window.authorized_media)
        self._media_order = [item for item in self._media_order if item is not window]
        self._media_order.append(window)
        if self.active_media is None:
            self.activate_media(window)
        else:
            # New players negotiate/load in the background and must not alter
            # established players' mute/volume state merely by being created.
            window.set_audio_focus(False)
            self.refresh_tabs()
            self.mpris.notify_player()

    def activate_media(self, window) -> None:
        if window not in self.media or self.active_media is window:
            return
        self._audio_order = [item for item in self._audio_order if item is not window]
        self._audio_order.append(window)
        for other in tuple(self.media):
            other.set_audio_focus(other is window)
        self.active_media = window
        if self.media_center is not None:
            self.media_center.activate(window)
        self.refresh_tabs()
        self.mpris.notify_player()

    def remove_media(self, window) -> None:
        self.media.discard(window)
        if self.media_center is not None:
            self.media_center.unregister(window)
        self._media_order = [item for item in self._media_order if item is not window]
        self._audio_order = [item for item in self._audio_order if item is not window]
        if self.active_media is window:
            self.active_media = None
            if self._audio_order:
                self.activate_media(self._audio_order[-1])
                return
            if self._media_order:
                self.activate_media(self._media_order[-1])
                return
        self.refresh_tabs()
        self.mpris.notify_player()

    def refresh_bookmarks(self) -> None:
        """Refresh shared bookmark data without changing any page session."""
        for browser in tuple(self.browsers):
            if not browser.closed and browser.bookmarks_visible:
                browser._populate_bookmarks()
        self.refresh_tabs()

    def refresh_tabs(self) -> None:
        for browser in tuple(self.browsers):
            if not getattr(browser, "closed", False) and hasattr(browser, "_draw_window_tabs"):
                browser._draw_window_tabs()

    def close_all(self) -> None:
        if getattr(self, "recording_reminder", None) is not None:
            self.recording_reminder.close()
        # Downloads belong to the whole session, never an individual browser.
        self.downloads.close()
        if self.center_window is not None and not self.center_window.closed:
            self.center_window.close()
        if self.media_center is not None:
            self.media_center.close()
        for window in tuple(self.media):
            window.close()
        for browser in tuple(self.browsers):
            if browser is not self.primary:
                browser.close()
        self.mpris.close()
