"""Catalog timeout recovery without live network or personal stores."""
import json
import unittest
from unittest.mock import Mock
from datetime import datetime, timezone
from bojangles.crawler.live import LiveWebCrawler, LiveCrawlOptions
from bojangles.renderer.wpe_transport import WPETransportError
from types import SimpleNamespace


def timeout():
    error = WPETransportError("trusted fetch failed")
    error.__cause__ = TimeoutError("read timed out")
    return error


def page():
    body = json.dumps({"response": {"numFound": 101, "start": 0, "docs": [
        {"identifier": "iran-video", "title": "Iran video", "date": "2020-01-01"}
    ]}}).encode()
    return SimpleNamespace(status=200, url="https://archive.org/advancedsearch.php", body=body)


class CatalogRecoveryTests(unittest.TestCase):
    def crawler(self):
        return LiveWebCrawler(now=datetime(2026, 11, 2, tzinfo=timezone.utc))

    def test_timeout_retries_once_and_returns_result(self):
        crawler = self.crawler()
        crawler.progress = Mock()
        crawler._fetch_crawl = Mock(side_effect=[timeout(), page()])
        report = crawler.search("iran video", LiveCrawlOptions(site="archive.org", max_pages=1))
        self.assertEqual(len(report.results), 1)
        self.assertEqual(crawler._fetch_crawl.call_count, 2)
        self.assertTrue(any("retrying once" in call.args[0] for call in crawler.progress.call_args_list))

    def test_later_failure_preserves_results_with_incomplete_notice(self):
        crawler = self.crawler()
        crawler._fetch_crawl = Mock(side_effect=[page(), timeout(), timeout()])
        report = crawler.search("iran video", LiveCrawlOptions(site="archive.org", max_pages=2))
        self.assertEqual(len(report.results), 1)
        self.assertIn("incomplete", report.notice)
        self.assertEqual(crawler._fetch_crawl.call_count, 3)

    def test_non_timeout_failure_is_not_retried(self):
        crawler = self.crawler()
        crawler._fetch_crawl = Mock(side_effect=WPETransportError("invalid response"))
        with self.assertRaises(ValueError):
            crawler.search("iran video", LiveCrawlOptions(site="archive.org", max_pages=1))
        self.assertEqual(crawler._fetch_crawl.call_count, 1)

    def test_repeated_timeout_stops_after_two_attempts(self):
        crawler = self.crawler()
        crawler._fetch_crawl = Mock(side_effect=[timeout(), timeout()])
        with self.assertRaises(ValueError):
            crawler.search("iran video", LiveCrawlOptions(site="archive.org", max_pages=1))
        self.assertEqual(crawler._fetch_crawl.call_count, 2)
