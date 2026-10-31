"""Exercise trusted Copy menu and PDF dialog through real Tk/native pages."""
from http.server import ThreadingHTTPServer
from pathlib import Path
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from bojangles.frontend.window_session import WindowSession
from bojangles.renderer.wpe import WPEBackend
from bojangles.renderer.wpe_transport import WPEAllowedDataTransport
from test_wpe_clipboard_runtime import ClipboardPage
from test_window_history_runtime import close_fixture_session

@unittest.skipUnless(os.environ.get('DISPLAY') and os.environ.get('BOJANGLES_BROKER_RUNTIME'), 'isolated Tk display and native runtime required')
class WindowPrintRuntimeTests(unittest.TestCase):

    def open_fixture(self, handler, path):
        # Every frontend-owned store must be isolated, not just WPE profiles.
        authority = tempfile.TemporaryDirectory(prefix="bojangles-test-home-")
        self.addCleanup(authority.cleanup)
        env = {"HOME": authority.name,
               **{key: str(Path(authority.name) / folder) for key, folder in (
                   ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                   ("XDG_CACHE_HOME", "cache"), ("XDG_STATE_HOME", "state"))}}
        isolated = patch.dict(os.environ, env)
        isolated.start()
        self.addCleanup(isolated.stop)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        prefix = Path(os.environ['BOJANGLES_BROKER_RUNTIME'])

        def factory():
            return WPEBackend(prefix / 'bin/bojangles-wpe', prefix=prefix, extension_dir=prefix / 'extensions', transport=WPEAllowedDataTransport(), profile_data_dir=Path(temporary.name) / 'data', profile_cache_dir=Path(temporary.name) / 'cache')
        url = f'http://127.0.0.1:{server.server_port}{path}'
        session = WindowSession(url, renderer_factories={'wpe': factory})
        self.assertTrue(session.bookmark_store.path.is_relative_to(Path(authority.name)))
        self.addCleanup(self.close_print_fixture, session)
        session._initial_navigation()
        session._pump_events()
        self.wait_for(session, lambda: session.current_url == url and session.manager.backend.snapshot().uri == url)
        for _ in range(20):
            session.root.update()
            time.sleep(0.02)
        return (session, Path(temporary.name))

    def wait_for(self, session, predicate):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            session.root.update()
            if predicate():
                return
            time.sleep(0.02)
        self.fail('frontend operation timed out: ' + session.status.get())

    def test_right_click_copy_preserves_page_selection_and_sets_system_clipboard(self):
        session, _ = self.open_fixture(ClipboardPage, '/copy')
        session.root.focus_force()
        session.image_label.focus_force()
        session.root.update()
        x = int(90 * session.image_label.winfo_width() / session.WIDTH)
        y = int(20 * session.image_label.winfo_height() / session.HEIGHT)
        session.image_label.event_generate('<ButtonPress-3>', x=x, y=y)
        session.image_label.event_generate('<ButtonRelease-3>', x=x, y=y)

        def copy_menu():
            return next((w for w in session.root.winfo_children() if w.winfo_class() == 'Menu' and w.index('end') is not None and (w.entrycget(0, 'label') == 'Copy')), None)
        self.wait_for(session, lambda: copy_menu() is not None)
        menu = copy_menu()
        menu.invoke(0)
        menu.unpost()
        self.assertEqual(session.root.clipboard_get(), 'BoJangles clipboard Ω line')
        self.assertEqual(session.status.get(), 'Copied selection to system clipboard')

    def test_page_menu_cancellation_and_reopen(self):
        session, _ = self.open_fixture(ClipboardPage, '/copy')
        session.root.clipboard_clear()
        session.root.clipboard_append('unchanged sentinel')
        session.root.focus_force()
        session.image_label.focus_force()
        session.root.update()
        x = int(90 * session.image_label.winfo_width() / session.WIDTH)
        y = int(20 * session.image_label.winfo_height() / session.HEIGHT)
        for cancel in ('escape', 'outside', 'right'):
            session.image_label.event_generate('<ButtonPress-3>', x=x, y=y)
            session.image_label.event_generate('<ButtonRelease-3>', x=x, y=y)
            self.wait_for(session, lambda: session.root.grab_current() is not None)
            menu = session.root.grab_current()
            self.assertEqual(menu.entrycget(0, 'label'), 'Copy')
            if cancel == 'escape':
                session.root.event_generate('<Escape>')
            elif cancel == 'outside':
                menu.event_generate('<Motion>', x=-80, y=-80)
                menu.event_generate('<ButtonPress-1>', x=-80, y=-80)
                menu.event_generate('<ButtonRelease-1>', x=-80, y=-80)
            else:
                menu.activate(0)
                menu.event_generate('<ButtonPress-3>', x=10, y=10)
                menu.event_generate('<ButtonRelease-3>', x=10, y=10)
            session.root.update()
            self.assertFalse(menu.winfo_ismapped())
            self.assertIsNone(session.root.grab_current())
            self.assertEqual(session.root.clipboard_get(), 'unchanged sentinel')
            self.assertEqual(session.root.focus_get(), session.image_label)

    def close_print_fixture(self, session):
        if session.closed:
            return
        session.home_surface.hide()
        close_fixture_session(session)

    def open_home(self):
        session = WindowSession(None, renderer_factories={})
        self.addCleanup(self.close_print_fixture, session)
        session._initial_navigation()
        session.root.update()
        return session

    def descendants(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.descendants(child)
if __name__ == '__main__':
    unittest.main()
