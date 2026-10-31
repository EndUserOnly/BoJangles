import os
import tkinter as tk
import unittest
from pathlib import Path
from bojangles.bookmarks.html_store import Bookmark, BookmarkFolder, SandboxBookmarkStore
from bojangles.frontend.bookmark_dialog import BookmarkDialog

class BookmarkSaveRegression(unittest.TestCase):
    def test_save_from_separate_browser_windows(self):
        root = tk.Tk()
        self.addCleanup(root.destroy)
        store = SandboxBookmarkStore()
        self.assertTrue(store.path.is_relative_to(Path(os.environ['HOME'])))
        store.add_folder('News')
        for owner in (root, tk.Toplevel(root)):
            errors = []
            def accept():
                try:
                    dialog = next(w for w in owner.winfo_children() if isinstance(w, BookmarkDialog))
                    folder = dialog.folders.get_children(dialog.folders.get_children('')[0])[0]
                    dialog.folders.selection_set(folder)
                    dialog.name.set('Saved page')
                    dialog.ok()
                except Exception as exc:
                    errors.append(exc)
                    for w in owner.winfo_children():
                        if isinstance(w, BookmarkDialog): w.cancel()
            owner.after(100, accept)
            dialog = BookmarkDialog(owner, store.load_tree(), Bookmark('Page','https://example.test/'+str(owner)))
            self.assertEqual(errors, [])
            self.assertIsNotNone(dialog.result)
            store.add_to_folder(*dialog.result)
        self.assertEqual(len(store.load()), 2)
        self.assertEqual(len(store.load_tree().children[0].children), 2)
