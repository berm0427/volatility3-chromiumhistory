import importlib.util
import pathlib
import struct
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
PLUGINS = ROOT.parent / "plugins"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


chromiumhistory = load_module(
    "volatility3.plugins.chromiumhistory", PLUGINS / "chromiumhistory.py"
)


class ChromiumHistoryTests(unittest.TestCase):
    @staticmethod
    def _sqlite_varint(value):
        if value < 0:
            raise ValueError("test varint must be non-negative")
        groups = [value & 0x7F]
        value >>= 7
        while value:
            groups.append(value & 0x7F)
            value >>= 7
        groups.reverse()
        return bytes(
            group | (0x80 if index < len(groups) - 1 else 0)
            for index, group in enumerate(groups)
        )

    @classmethod
    def _history_leaf_cell(cls, url, title):
        url_bytes = url.encode("utf-8")
        title_bytes = title.encode("utf-8")
        serial_types = [
            0,
            13 + 2 * len(url_bytes),
            13 + 2 * len(title_bytes),
            1,
            8,
            6,
            8,
            1,
        ]
        serial_header = b"".join(cls._sqlite_varint(x) for x in serial_types)
        header_size = 1 + len(serial_header)
        header = cls._sqlite_varint(header_size) + serial_header
        chrome_timestamp = 13_448_000_000_000_000
        body = (
            url_bytes
            + title_bytes
            + b"\x03"
            + chrome_timestamp.to_bytes(8, "big", signed=True)
            + b"\x09"
        )
        payload = header + body
        return cls._sqlite_varint(len(payload)) + b"\x01" + payload

    @staticmethod
    def _serialized_navigation(url, title, index=2, transition=1):
        payload = bytearray(struct.pack("<iI", index, len(url.encode("utf-8"))))
        payload.extend(url.encode("utf-8"))
        payload.extend(b"\x00" * (-len(payload) & 3))
        payload.extend(struct.pack("<I", len(title)))
        payload.extend(title.encode("utf-16le"))
        payload.extend(b"\x00" * (-len(payload) & 3))
        page_state = b"PAGE_STATE"
        payload.extend(struct.pack("<I", len(page_state)))
        payload.extend(page_state)
        payload.extend(b"\x00" * (-len(payload) & 3))
        payload.extend(struct.pack("<i", transition))
        payload.extend(struct.pack("<iI", 0, 0))  # type mask, empty referrer
        payload.extend(struct.pack("<iI", 2, 0))  # obsolete policy, original URL
        payload.extend(b"\x00\x00\x00\x00")  # override UA plus padding
        payload.extend(struct.pack("<qIi", 1, 0, 200))
        return bytes(payload)

    def test_serialized_navigation_entry(self):
        url = "https://example.com/private?q=apple"
        data = self._serialized_navigation(url, "Private title")
        recovered = chromiumhistory.parse_serialized_navigation(data, 8)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.url, url)
        self.assertEqual(recovered.title, "Private title")
        self.assertEqual(recovered.index, 2)
        self.assertEqual(recovered.transition_type, 1)

    def test_serialized_navigation_rejects_plain_url(self):
        data = b"\x00" * 8 + b"https://example.com/not-a-navigation-object"
        self.assertIsNone(
            chromiumhistory.parse_serialized_navigation(data, 8)
        )

    def test_ascii_url_recovery(self):
        data = b"https://example.com/private?q=1\x00ignored"
        self.assertEqual(
            chromiumhistory.extract_memory_url(data, False),
            "https://example.com/private?q=1",
        )

    def test_embedded_url_list_is_split(self):
        data = b"https://one.example/,https://two.example/path\x00"
        self.assertEqual(
            chromiumhistory.extract_memory_url(data, False),
            "https://one.example/",
        )

    def test_utf16le_url_recovery(self):
        expected = "https://example.org/incognito/path"
        data = (expected + "\x00ignored").encode("utf-16le")
        self.assertEqual(chromiumhistory.extract_memory_url(data, True), expected)

    def test_trailing_punctuation_is_removed(self):
        data = b"https://example.net/test).\x00"
        self.assertEqual(
            chromiumhistory.extract_memory_url(data, False),
            "https://example.net/test",
        )

    def test_history_correlation(self):
        history = {chromiumhistory.normalize_url("HTTPS://Example.com/a")}
        self.assertEqual(
            chromiumhistory.classify_memory_source(
                "https://example.com/a", history
            )[0],
            "ProcessMemory",
        )
        self.assertEqual(
            chromiumhistory.classify_memory_source(
                "https://example.com/private", history
            )[0],
            "MemoryOnly",
        )

    def test_sqlite_three_byte_integer(self):
        self.assertEqual(
            chromiumhistory._decode_sqlite_signed_integer(b"\x01\x02\x03"),
            0x010203,
        )

    def test_sqlite_six_byte_integer(self):
        self.assertEqual(
            chromiumhistory._decode_sqlite_signed_integer(
                b"\x01\x02\x03\x04\x05\x06"
            ),
            0x010203040506,
        )

    def test_sqlite_signed_nonstandard_integer_widths(self):
        self.assertEqual(
            chromiumhistory._decode_sqlite_signed_integer(b"\xff\xff\xff"),
            -1,
        )
        self.assertEqual(
            chromiumhistory._decode_sqlite_signed_integer(b"\xff" * 6),
            -1,
        )

    def test_sqlite_varint_decoding_and_reverse_boundary(self):
        encoded = b"\x81\x00"
        self.assertEqual(
            chromiumhistory._decode_sqlite_varint(encoded, 0),
            (128, 2),
        )
        self.assertEqual(
            chromiumhistory._decode_sqlite_varint_before(encoded, 1),
            (128, 2),
        )
        nine_byte = b"\xff" * 9
        self.assertEqual(
            chromiumhistory._decode_sqlite_varint(nine_byte, 0),
            ((1 << 64) - 1, 9),
        )

    def test_sqlite_serial_layout(self):
        self.assertEqual(
            chromiumhistory._sqlite_serial_layout(5),
            (6, None, "integer"),
        )
        self.assertEqual(
            chromiumhistory._sqlite_serial_layout(8),
            (0, 0, "integer"),
        )
        self.assertEqual(
            chromiumhistory._sqlite_serial_layout(13 + 2 * 12),
            (12, None, "text"),
        )
        with self.assertRaises(ValueError):
            chromiumhistory._sqlite_serial_layout(10)

    def test_history_record_uses_forward_sqlite_cell_decoder(self):
        expected_url = "https://example.test/path"
        cell = self._history_leaf_cell(expected_url, "Independent parser")
        data = b"\x00\x00" + cell + b"\x00" * 32
        fake_plugin = type(
            "FakePlugin", (), {"config": {"suppress_null_time": True}}
        )()
        recovered = chromiumhistory.ChromiumHistory._parse_history_buffer(
            fake_plugin, data, 0x1234
        )
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.url, expected_url)
        self.assertEqual(recovered.title, "Independent parser")
        self.assertEqual(recovered.visit_count, 3)
        self.assertEqual(recovered.typed_count, 0)

    def test_sqlite_cell_decoder_rejects_truncated_payload(self):
        cell = self._history_leaf_cell("https://example.test/", "title")
        with self.assertRaises(ValueError):
            chromiumhistory._decode_sqlite_table_leaf_cell(cell[:-3], 0)

    def test_edge_utf16_internal_url(self):
        expected = "edge://settings/privacy"
        data = (expected + "\x00ignored").encode("utf-16le")
        self.assertEqual(
            chromiumhistory.extract_memory_url(data, True), expected
        )

    def test_known_browser_fallback_names(self):
        self.assertIn("msedge.exe", chromiumhistory.KNOWN_CHROMIUM_PROCESSES)
        self.assertIn("chromium.exe", chromiumhistory.KNOWN_CHROMIUM_PROCESSES)
        self.assertIn("libcef.dll", chromiumhistory.CHROMIUM_MODULE_MARKERS)

    def test_search_metadata_is_optional_enrichment(self):
        self.assertEqual(
            chromiumhistory.search_details(
                "https://www.google.com/search?q=apple+pear&source=chrome"
            ),
            ("Google", "apple pear"),
        )
        self.assertEqual(
            chromiumhistory.search_details("https://example.com/article"),
            ("", ""),
        )

    def test_closed_recovery_rejects_match_patterns(self):
        self.assertTrue(
            chromiumhistory.is_recoverable_url("https://example.com/a")
        )
        self.assertFalse(
            chromiumhistory.is_recoverable_url("https://*/*")
        )

    def test_non_ascii_tail_is_trimmed(self):
        self.assertEqual(
            chromiumhistory.extract_memory_url(
                "https://example.com/path미리보기".encode("utf-8"), False
            ),
            "https://example.com/path",
        )

    def test_navigation_score_uses_provenance_not_search_engine(self):
        google = "https://www.google.com/search?q=apple"
        bing = "https://www.bing.com/search?q=apple"
        google_score, _ = chromiumhistory.navigation_score(google, "MemoryOnly")
        bing_score, _ = chromiumhistory.navigation_score(bing, "MemoryOnly")
        self.assertEqual(google_score, bing_score)
        physical_score, _ = chromiumhistory.navigation_score(
            bing, "PhysicalMemoryOnly"
        )
        self.assertGreater(bing_score, physical_score)

    def test_history_time_has_utc_and_kst(self):
        utc = "2026-10-01T05:41:36+00:00"
        self.assertEqual(
            chromiumhistory.utc_to_kst(utc),
            "2026-10-01T14:41:36+09:00",
        )

    def test_physical_browser_context_is_query_agnostic(self):
        first = b"msedge.exe\x00https://unknown.invalid/a?id=123"
        first += b"\x00referer: https://unknown.invalid/home\x00cookie: x=y"
        second = first.replace(b"id=123", b"anything=unseen")
        first_score, _ = chromiumhistory.physical_browser_context(
            first, first.index(b"https://"),
            "https://unknown.invalid/a?id=123",
        )
        second_score, _ = chromiumhistory.physical_browser_context(
            second, second.index(b"https://"),
            "https://unknown.invalid/a?anything=unseen",
        )
        self.assertEqual(first_score, second_score)
        self.assertGreaterEqual(first_score, 60)

    def test_physical_context_rejects_test_and_message_strings(self):
        url = "https://example.invalid/search?q=not-hardcoded"
        context = (
            b'self.assertEqual(record.url, "' + url.encode() +
            b'") <toast><text>' + url.encode() + b"</text></toast>"
        )
        score, _ = chromiumhistory.physical_browser_context(
            context, context.index(url.encode()), url
        )
        self.assertLess(score, 60)

    def test_network_record_url_cleanup_is_not_domain_specific(self):
        url = "https://unknown.invalid/a?q=x.unknown.invalid.0.0.416"
        self.assertEqual(
            chromiumhistory.clean_network_record_url(url),
            "https://unknown.invalid/a?q=x",
        )
        with_image = (
            "https://unknown.invalid/a?q=x/data:image/png;base64,AAAA"
        )
        self.assertEqual(
            chromiumhistory.clean_network_record_url(with_image),
            "https://unknown.invalid/a?q=x",
        )
        self.assertEqual(
            chromiumhistory.clean_network_record_url(
                "https://unknown.invalid/a?q=x..0.0.416"
            ),
            "https://unknown.invalid/a?q=x",
        )

    def test_activity_role_uses_generic_fetch_metadata(self):
        role, reason = chromiumhistory.classify_activity_role(
            "https://unknown.invalid/article/123",
            b"Sec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document",
            "PhysicalBrowserContext",
        )
        self.assertEqual(role, "ProbableTopLevelNavigation")
        self.assertEqual(reason, "fetch-metadata-navigation")

    def test_activity_role_rejects_static_resource(self):
        role, _ = chromiumhistory.classify_activity_role(
            "https://unknown.invalid/assets/app.js",
            b"Sec-Fetch-Dest: script",
            "PhysicalBrowserContext",
        )
        self.assertEqual(role, "SubresourceOrBackground")

    def test_artifact_class_rejects_internal_and_template_urls(self):
        for url in (
            "edge://resources/js/app.js",
            "https://permanently-removed.invalid/a",
            "https://www.bing.com/search?q=$1",
        ):
            artifact, canonical = chromiumhistory.classify_artifact(
                url, "ProcessURLString", "Unclassified"
            )
            self.assertEqual(artifact, "TemplateOrInternal")
            self.assertEqual(canonical, "")

    def test_search_activity_is_keyword_independent_and_canonical(self):
        first = "https://www.google.com/search?q=arbitrary+terms&tbm=nws"
        second = "https://www.google.com/search?q=arbitrary+terms&udm=2"
        a1 = chromiumhistory.classify_artifact(
            first, "ProcessURLString", "Unclassified"
        )
        a2 = chromiumhistory.classify_artifact(
            second, "ProcessURLString", "Unclassified"
        )
        self.assertEqual(a1[0], "SearchActivity")
        self.assertEqual(a1[1], a2[1])

        advanced = chromiumhistory.classify_artifact(
            "https://www.google.com/advanced_search?q=arbitrary+terms",
            "ProcessURLString", "Unclassified"
        )
        self.assertEqual(a1[1], advanced[1])

    def test_static_resource_is_background_artifact(self):
        artifact, canonical = chromiumhistory.classify_artifact(
            "https://cdn.invalid/assets/app.js",
            "ProcessURLString", "SubresourceOrBackground"
        )
        self.assertEqual(artifact, "BackgroundOrEmbedded")
        self.assertEqual(canonical, "")

    def test_csp_reporting_endpoint_is_background(self):
        role, _ = chromiumhistory.classify_activity_role(
            "https://csp.example/csp/report",
            b"Content-Type: text/html",
            "ProcessURLString",
        )
        self.assertEqual(role, "SubresourceOrBackground")

    def test_persistence_requires_an_actual_history_scan(self):
        url = "https://unknown.invalid/a"
        self.assertEqual(
            chromiumhistory.persistence_assessment(url, set(), False),
            "NotCompared",
        )
        self.assertEqual(
            chromiumhistory.persistence_assessment(url, set(), True),
            "NotInRecoveredHistory",
        )

    def test_browser_context_identity_classification(self):
        classify = chromiumhistory.ChromiumHistory._classify_browser_context
        self.assertEqual(classify(0x3000, {0x3000}, {0x2000}), "InPrivate")
        self.assertEqual(classify(0x2000, {0x3000}, {0x2000}), "Regular")
        self.assertEqual(classify(0x4000, {0x3000}, {0x2000}), "Unknown")

    def test_compact_row_prioritizes_search_activity(self):
        record = chromiumhistory.RecoveredURL(
            source="MemoryOnly",
            confidence="Possible Incognito",
            pid=20376,
            process="msedge.exe",
            offset=0x1234,
            url="https://www.google.com/search?q=readable+query",
            search_engine="Google",
            search_query="readable query",
            visit_count=-1,
            last_visit_time="",
            persistence_assessment="NotInRecoveredHistory",
            browsing_mode="InPrivate",
        )
        level, row = chromiumhistory.ChromiumHistory._compact_row(record)
        self.assertEqual(level, 0)
        self.assertEqual(len(row), 9)
        self.assertEqual(row[3], "InPrivate")
        self.assertEqual(row[4], "readable query")
        self.assertEqual(row[5], "www.google.com")
        self.assertEqual(row[8], "NotInRecoveredHistory")

    def test_compact_row_limits_long_activity(self):
        record = chromiumhistory.RecoveredURL(
            source="HistoryDB",
            confidence="Persisted SQLite record",
            pid=0,
            process="HistoryDB",
            offset=0,
            url="https://example.com/" + "a" * 200,
        )
        _level, row = chromiumhistory.ChromiumHistory._compact_row(record)
        self.assertEqual(len(row[4]), 96)
        self.assertTrue(row[4].endswith("..."))


if __name__ == "__main__":
    unittest.main()
