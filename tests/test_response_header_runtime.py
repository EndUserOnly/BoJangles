"""Large document and fetch response policies survive the native two-pipe path."""
import os
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs
import test_window_print_runtime as fixture

class HeaderPage(BaseHTTPRequestHandler):
    mark = None
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == '/probe':
            HeaderPage.mark = parse_qs(path.query).get('mark', [''])[0]
            self.send_response(204)
            self.end_headers()
            return
        body = (b'<!doctype html><title>Large headers</title><script>fetch("/api").then(async r=>fetch("/probe?mark="+encodeURIComponent(r.headers.get("X-Large-1").length+"|"+await r.text()))).catch(e=>fetch("/probe?mark=FAIL"))</script>'
                if path.path == '/start' else b'large-response-ok')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if path.path == '/start' else 'text/plain')
        for n in range(3): self.send_header('X-Large-'+str(n), 'a'*6000)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass

@unittest.skipUnless(os.environ.get('DISPLAY') and os.environ.get('BOJANGLES_BROKER_RUNTIME'), 'native runtime required')
class ResponseHeaderRuntimeTests(unittest.TestCase):
    open_fixture = fixture.WindowPrintRuntimeTests.open_fixture
    wait_for = fixture.WindowPrintRuntimeTests.wait_for
    close_print_fixture = fixture.WindowPrintRuntimeTests.close_print_fixture
    def test_large_document_and_resource_headers(self):
        HeaderPage.mark = None
        s, _ = self.open_fixture(HeaderPage, '/start')
        self.wait_for(s, lambda: HeaderPage.mark is not None)
        self.assertEqual(HeaderPage.mark, '6000|large-response-ok')
        self.assertEqual(s.page_title, 'Large headers')

