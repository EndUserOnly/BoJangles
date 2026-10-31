"""Bookmark data refreshes independently of browser page state."""
import os
import unittest
from test_response_header_runtime import HeaderPage
import test_window_print_runtime as fixture

@unittest.skipUnless(os.environ.get('DISPLAY') and os.environ.get('BOJANGLES_BROKER_RUNTIME'), 'native runtime required')
class BookmarkSaveRuntime(unittest.TestCase):
    open_fixture = fixture.WindowPrintRuntimeTests.open_fixture
    wait_for = fixture.WindowPrintRuntimeTests.wait_for
    close_print_fixture = fixture.WindowPrintRuntimeTests.close_print_fixture
    def test_save_refreshes_other_visible_bookmark_view_and_persists(self):
        import tkinter as tk
        import subprocess, sys
        from bojangles.bookmarks.html_store import Bookmark, SandboxBookmarkStore
        from bojangles.frontend.bookmark_dialog import BookmarkDialog
        s, _ = self.open_fixture(HeaderPage, '/start')
        child = s._open_browser_window(s.current_url.rsplit('/', 1)[0] + '/sibling')
        self.addCleanup(child.close)
        self.wait_for(s, lambda: child.manager is not None and child.manager.backend.snapshot().uri == child.current_url)
        child._show_bookmarks()
        self.assertFalse(child.bookmark_targets)
        def accept():
            dialog = next(w for w in s.root.winfo_children() if isinstance(w, BookmarkDialog))
            dialog.ok()
        s.root.after(100, accept)
        s._add_bookmark()
        self.assertIn('Bookmark saved', s.status.get())
        self.assertIn(s.current_url, child.bookmark_targets.values())
        # New windows and freshly imported stores use the same persistent HTML.
        newer = s._open_browser_window(s.current_url.rsplit('/', 1)[0] + '/newer')
        self.addCleanup(newer.close)
        newer._show_bookmarks()
        self.assertIn(s.current_url, newer.bookmark_targets.values())
        out = subprocess.check_output([sys.executable, '-c',
            'from bojangles.bookmarks.html_store import SandboxBookmarkStore; print(len(SandboxBookmarkStore().load()))'], text=True)
        self.assertEqual(out.strip(), '1')

        subprocess.check_call([sys.executable, '-c',
            'from bojangles.bookmarks.html_store import SandboxBookmarkStore, Bookmark; SandboxBookmarkStore().add(Bookmark("External", "https://external.test/"))'])
        child.root.event_generate('<FocusIn>')
        child.root.update()
        self.assertIn('https://external.test/', child.bookmark_targets.values())
        rows = child.bookmark_list.get_children('')
        child.root.event_generate('<FocusIn>')
        child.root.update()
        self.assertEqual(child.bookmark_list.get_children(''), rows)
