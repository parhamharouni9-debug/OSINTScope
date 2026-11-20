import unittest

from osintscope.config import NetworkSettings
from osintscope.validation import normalize_domain


class ValidationTests(unittest.TestCase):
    def test_canonical_forms(self):
        for value, expected in [
            (" Example.COM. ", "example.com"),
            ("BÜCHER.de", "xn--bcher-kva.de"),
            ("faß.de", "xn--fa-hia.de"),
            ("www。Example.com", "www.example.com"),
            ("XN--BCHER-KVA.DE", "xn--bcher-kva.de"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(normalize_domain(value), expected)

    def test_invalid_inputs(self):
        for value in [
            "",
            "com",
            "example..com",
            "example.com..",
            "*.test.com",
            "https://example.com",
            "example.com:443",
            "a@example.com",
            "8.8.8.8",
            "[::1]",
            "ab.123",
            "-x.com",
            "x_.com",
            "xn--.com",
            "x" * 64 + ".com",
            ("a" * 63 + ".") * 4 + "com",
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_network_bounds(self):
        for timeout, retries in [(float("nan"), 1), (0, 1), (61, 1), (5, -1), (5, 4)]:
            with self.subTest(timeout=timeout, retries=retries), self.assertRaises(ValueError):
                NetworkSettings(timeout, retries)
