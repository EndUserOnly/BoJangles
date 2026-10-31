"""Directional aggregate budgets, including both sealed response envelopes."""
import unittest
from bojangles.renderer.wpe_transport import WPEAllowedDataTransport, WPETransportError, WPEFetchedDocument, MAX_HEADER_BYTES, MAX_RESPONSE_HEADER_BYTES
from bojangles.renderer.wpe import WPEBackend
from bojangles.renderer.api import NavigationRequest

class ResponseHeaderBudget(unittest.TestCase):
    def pairs(self, size):
        # Five values stay individually below 8 KiB; count is also bounded.
        return tuple(('X-Test', 'a' * n) for n in (8000, 8000, 8000, 8000, size - 32050))

    def test_response_exact_budget_and_one_byte_over(self):
        clean = WPEAllowedDataTransport.sanitize_response_headers
        pairs = self.pairs(MAX_RESPONSE_HEADER_BYTES)
        self.assertEqual(clean(pairs), pairs)
        with self.assertRaises(WPETransportError):
            clean(self.pairs(MAX_RESPONSE_HEADER_BYTES + 1))
        with self.assertRaises(WPETransportError):
            clean([('X-Test', 'a')] * 65)
        with self.assertRaises(WPETransportError):
            clean([('X-Test', 'a' * 8193)])
        with self.assertRaises(WPETransportError):
            clean([('X-Test', 'a\r\nb')])

    def test_request_budget_remains_16k(self):
        clean = WPEAllowedDataTransport.sanitize_request_headers
        pairs = [('Accept', 'a' * 4000)] * 4
        self.assertEqual(len(clean(pairs)), 4)
        with self.assertRaises(WPETransportError): clean(pairs + [('Accept', 'a' * 400)])
        self.assertEqual(MAX_HEADER_BYTES, 16384)

    def test_both_sealed_response_senders_enforce_response_budget(self):
        backend = WPEBackend('/unused', prefix='/unused', extension_dir='/unused')
        sent = []
        backend._send = lambda *a, **k: sent.append(a)
        request = NavigationRequest('d', 'https://example.test/')
        for size in (MAX_RESPONSE_HEADER_BYTES, MAX_RESPONSE_HEADER_BYTES + 1):
            fetched = WPEFetchedDocument(request.uri, 200, 'text/html', 'utf-8', b'ok', self.pairs(size))
            for send in (lambda: backend._send_fetched_document(request, fetched),):
                if size == MAX_RESPONSE_HEADER_BYTES:
                    send()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'headers exceed protocol bound'): send()

            sent.clear()
            backend._send_fetched_resource(7, fetched)
            from bojangles.renderer.native_protocol import NativeMessage
            self.assertEqual(sent[-1][0].kind, NativeMessage.RESOURCE_DATA if size == MAX_RESPONSE_HEADER_BYTES else NativeMessage.RESOURCE_DECISION)
