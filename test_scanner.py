import unittest
from unittest.mock import Mock, patch
import requests
from scanner import normalize_url, scan_url

class ScannerTests(unittest.TestCase):
    def test_normalize_adds_https(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_rejects_empty_url(self):
        with self.assertRaises(ValueError):
            normalize_url(" ")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:pass@example.com")

    @patch("scanner.requests.get")
    def test_scan_reports_present_and_missing_headers(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.url = "https://example.com/"
        response.headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
        mock_get.return_value = response
        result = scan_url("example.com")
        self.assertEqual(result["status_code"], 200)
        names = {h["name"]: h["present"] for h in result["headers"]}
        self.assertTrue(names["Content-Security-Policy"])
        self.assertTrue(names["X-Content-Type-Options"])
        self.assertFalse(names["Strict-Transport-Security"])

    @patch("scanner.requests.get", side_effect=requests.exceptions.Timeout)
    def test_timeout_handled(self, _mock_get):
        self.assertIn("timeout", scan_url("example.com")["error"].lower())

    @patch("scanner.requests.get", side_effect=requests.exceptions.SSLError)
    def test_ssl_error_handled(self, _mock_get):
        self.assertIn("TLS", scan_url("example.com")["error"])

    @patch("scanner.requests.get", side_effect=requests.exceptions.ConnectionError)
    def test_connection_error_handled(self, _mock_get):
        self.assertIn("connect", scan_url("example.com")["error"].lower())

    @patch("scanner.requests.get")
    def test_timeout_is_clamped(self, mock_get):
        response = Mock(status_code=200, url="https://example.com/", headers={})
        mock_get.return_value = response
        scan_url("example.com", timeout=999)
        self.assertEqual(mock_get.call_args.kwargs["timeout"], 30)

if __name__ == "__main__":
    unittest.main()
