"""Recovery must not depend on a stalled renderer or optional diagnostic sink."""
import fcntl
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from bojangles import diagnostics
from bojangles.renderer.api import NavigationRequest, RendererLifecycle, RendererEventKind
from bojangles.renderer.native_protocol import NativeMessage, NativePacket
from bojangles.renderer.wpe import WPEBackend
from bojangles.renderer.wpe_transport import WPEFetchedDocument, WPEAllowedDataTransport, WPETransportError, MAX_HEADER_COUNT, MAX_HEADER_BYTES, MAX_RESPONSE_HEADER_BYTES

class ErrorIsolation(unittest.TestCase):
    def backend(self):
        backend = WPEBackend('/unused', prefix='/unused', extension_dir='/unused')
        backend._context = SimpleNamespace(document=SimpleNamespace(document_id='d', uri='https://a.test/'))
        backend._request = NavigationRequest('d', 'https://a.test/')
        backend._lifecycle = RendererLifecycle.RUNNING
        return backend

    def test_cancel_and_other_window_events_while_document_send_stalls(self):
        backend = self.backend()
        entered, release = threading.Event(), threading.Event()
        cancelled = threading.Event()
        fetched = WPEFetchedDocument('https://a.test/', 200, 'text/html', 'utf-8', b'ok')
        backend._transport = SimpleNamespace(fetch_once=lambda *a, **k: fetched)
        backend._report_media = lambda *a, **k: None
        backend._inline_embedded_pdfs = lambda request, fetched: fetched
        def send(*args):
            entered.set()
            release.wait(2)
        backend._send_fetched_document = send
        def work():
            backend._navigation_local.cancelled = cancelled
            backend._load_document(backend._request, backend._context, cancelled)
        backend._navigation_cancel = cancelled
        worker = threading.Thread(target=work)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            backend._cancel_navigation()
            self.assertLess(time.monotonic() - started, .15)
            self.assertTrue(cancelled.is_set())
            self.assertEqual(self.backend().poll_events(), [])
        finally:
            release.set(); worker.join(2)

    def test_retirement_does_not_wait_for_control_sender(self):
        backend = self.backend()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        backend._sock = a
        backend._send_lock.acquire()
        try:
            started = time.monotonic()
            backend.begin_stop()
            self.assertLess(time.monotonic() - started, .15)
            self.assertEqual(b.recv(1), b'')
        finally:
            backend._send_lock.release(); a.close(); b.close()

    def test_input_sender_lock_has_deadline(self):
        backend = self.backend()
        backend._sock, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        backend._send_lock.acquire()
        try:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                backend._send(NativePacket(NativeMessage.NAV_STOP))
            self.assertLess(time.monotonic() - started, .3)
        finally:
            backend._send_lock.release()
            backend._sock.close(); peer.close()

    def test_failure_published_before_diagnostics_and_only_once(self):
        backend = self.backend()
        token = threading.Event()
        backend._navigation_local.cancelled = token
        with patch.object(diagnostics, 'record') as record:
            record.side_effect = lambda *a, **k: self.assertEqual(len(backend._events), 1)
            backend._queue_navigation_failure('https://a.test/', 'headers rejected')
            backend._queue_navigation_failure('https://a.test/', 'late response')
        self.assertTrue(token.is_set())
        self.assertEqual(len(backend._events), 1)

    def test_header_count_value_and_directional_byte_limits(self):
        clean = WPEAllowedDataTransport.sanitize_response_headers
        self.assertEqual(len(clean([('X-Test', 'a')] * MAX_HEADER_COUNT)), MAX_HEADER_COUNT)
        for pairs in ([('X-Test', 'a')] * (MAX_HEADER_COUNT + 1),
                      [('X-Test', 'a' * 8000)] * 5,
                      [('X-Test', 'a' * 8193)], [('X-Test', 'bad\r\nvalue')]):
            with self.assertRaises(WPETransportError): clean(pairs)
        self.assertEqual(MAX_HEADER_BYTES, 16384)
        self.assertEqual(MAX_RESPONSE_HEADER_BYTES, 32768)
        self.assertEqual(len(clean([("X-Test", "a" * 8000)] * 3)), 3)

    def test_diagnostic_budget_lock_does_not_wait(self):
        with tempfile.TemporaryDirectory() as root:
            session = diagnostics.DiagnosticSession('unused', root=Path(root))
            with open(Path(root) / '.budget.lock', 'rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                started = time.monotonic()
                session.write('http_attempt', method='GET')
                self.assertLess(time.monotonic() - started, .15)
                self.assertEqual(session.dropped_records, 1)
            session.close(clean=True)

    def test_shared_diagnostic_sink_never_blocks_callers(self):
        with tempfile.TemporaryDirectory() as root:
            entered, release = threading.Event(), threading.Event()
            with patch.object(diagnostics, 'DEFAULT_ROOT', Path(root)):
                # Constructor default is bound at definition time.
                real = diagnostics.DiagnosticSession
                with patch.object(diagnostics, 'DiagnosticSession', side_effect=lambda *a, **k: real(*a, root=Path(root), **k)):
                    session = diagnostics.start('unused')
            original = session.write
            def stalled(*a, **k):
                entered.set(); release.wait(2); original(*a, **k)
            try:
                with patch.object(session, 'write', side_effect=stalled):
                    diagnostics.record('http_attempt', method='GET', url='https://a.test/secret')
                    self.assertTrue(entered.wait(1))
                    started = time.monotonic()
                    for i in range(1000): diagnostics.record('navigation_failure', detail='secret')
                    self.assertLess(time.monotonic() - started, .15)
                    self.assertGreater(session.dropped_records, 0)
                    release.set()
            finally:
                release.set(); diagnostics.stop(clean=True)
            self.assertNotIn('secret', session.path.read_text())

    def test_event_pump_survives_handler_failure(self):
        from bojangles.frontend.window_session import WindowSession
        from unittest.mock import Mock
        event = SimpleNamespace(document_id='', kind=RendererEventKind.TITLE_CHANGED, detail=None)
        manager = SimpleNamespace(poll_events=lambda: [event])
        session = SimpleNamespace(closed=False, root=Mock(), status=Mock(), manager=manager,
                                  _pump_events=Mock())
        session._drain_events = lambda: WindowSession._drain_events(session)
        WindowSession._pump_events(session)
        session.root.after.assert_called_once_with(40, session._pump_events)
        self.assertIn("Browser event failed", session.status.set.call_args.args[0])

    def test_bookmark_startup_error_is_nonmodal(self):
        from bojangles.frontend.window_session import WindowSession
        from unittest.mock import Mock
        session = SimpleNamespace(bookmark_list=Mock(), bookmark_targets={'row': 'https://a.test/'},
            _navigate=Mock(side_effect=RuntimeError('startup failed')), status=Mock(), control_panel=Mock())
        session.bookmark_list.selection.return_value = ('row',)
        with patch('bojangles.frontend.window_session.messagebox.showerror') as popup:
            WindowSession._activate_bookmark(session)
        popup.assert_not_called()
        self.assertIn('startup failed', session.status.set.call_args.args[0])

    def test_blocked_terminal_output_does_not_block_report(self):
        from bojangles.frontend import terminal_control as terminal
        from unittest.mock import Mock
        entered, release = threading.Event(), threading.Event()
        # Exercise a fresh queue worker and replace only the output sink.
        terminal._notice_worker = None
        def blocked(*a, **k):
            entered.set(); release.wait(2)
        try:
            with patch.object(terminal, 'print', side_effect=blocked, create=True):
                panel = terminal.TerminalControlPanel('https://a.test/')
                with patch.object(terminal.sys.stdin, 'isatty', return_value=False):
                    panel.report('first')
                    self.assertTrue(entered.wait(1))
                    started = time.monotonic()
                    for _ in range(1000): panel.report('next')
                    self.assertLess(time.monotonic() - started, .15)
                    self.assertEqual(panel.notice, 'next')
                    release.set()
                    # Drain before removing the patched output sink.
                    end = time.monotonic() + 1
                    while not terminal._notices.empty() and time.monotonic() < end: time.sleep(.01)
        finally: release.set()

    def test_explicit_maintenance_diagnostics_remain_synchronous(self):
        with tempfile.TemporaryDirectory() as root:
            session = diagnostics.DiagnosticSession('unused', root=Path(root))
            with patch.object(diagnostics, '_active', session):
                diagnostics.record('http_attempt', method='GET')
                diagnostics.stop(clean=True)
            self.assertEqual(diagnostics.analyze_ledger(session.path)['actual_http_attempts'], 1)
