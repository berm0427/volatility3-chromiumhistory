"""Chromium browser history and private-mode URL recovery for Volatility 3.

Chromium browsers do not persist private-mode visits to their History database.
Accordingly, this plugin correlates recovered History rows with HTTP(S) URL
strings carved directly from browser process VADs. URLs seen only in
process memory are reported as MemoryOnly (possible Incognito), not as proof.

This implementation originated from the 2024 forsick/Windows feat/v2 team
project and was subsequently extensively rewritten and expanded.  See the
repository's NOTICE.md for provenance and rights information.
"""

import dataclasses
import datetime
import logging
import re
import struct
import urllib.parse
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import cmdline, filescan, pslist, psscan


vollog = logging.getLogger(__name__)


def _sqlite_serial_layout(serial_type: int) -> Tuple[int, Optional[int], str]:
    """Returns payload size, inline integer value, and SQLite value kind.

    The mapping follows SQLite's public record-format table. Codes 10 and 11
    are reserved and rejected because their transient meaning is not stable.
    """

    if serial_type < 0:
        raise ValueError("negative SQLite serial type")
    if serial_type == 0:
        return 0, None, "null"
    integer_sizes = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}
    if serial_type in integer_sizes:
        return integer_sizes[serial_type], None, "integer"
    if serial_type == 7:
        return 8, None, "float"
    if serial_type in (8, 9):
        return 0, serial_type - 8, "integer"
    if serial_type in (10, 11):
        raise ValueError("reserved SQLite serial type")
    if serial_type % 2 == 0:
        return (serial_type - 12) // 2, None, "blob"
    return (serial_type - 13) // 2, None, "text"


def _decode_sqlite_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Decodes one SQLite varint beginning at *offset*."""

    if not 0 <= offset < len(data):
        raise ValueError("SQLite varint starts outside the buffer")
    value = 0
    for index in range(9):
        position = offset + index
        if position >= len(data):
            raise ValueError("truncated SQLite varint")
        byte = data[position]
        if index == 8:
            return ((value << 8) | byte), 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, index + 1
    raise ValueError("invalid SQLite varint")


def _decode_sqlite_varint_before(data: bytes, end: int) -> Tuple[int, int]:
    """Decodes the longest valid SQLite varint whose last byte is *end*."""

    if not 0 <= end < len(data):
        raise ValueError("SQLite varint ends outside the buffer")
    for begin in range(max(0, end - 8), end + 1):
        try:
            value, length = _decode_sqlite_varint(data, begin)
        except ValueError:
            continue
        if begin + length - 1 == end:
            return value, length
    raise ValueError("no SQLite varint ends at the requested byte")


def _decode_sqlite_signed_integer(data: bytes) -> int:
    """Decodes a big-endian two's-complement SQLite record integer."""

    if len(data) not in (0, 1, 2, 3, 4, 6, 8):
        raise ValueError("unsupported SQLite integer width")
    return int.from_bytes(data, byteorder="big", signed=True) if data else 0


def _decode_sqlite_record_value(
    payload: bytes, cursor: int, serial_type: int
) -> Tuple[object, int]:
    """Decodes one value from a SQLite record body."""

    size, inline, kind = _sqlite_serial_layout(serial_type)
    end = cursor + size
    if end > len(payload):
        raise ValueError("SQLite record value exceeds the available payload")
    raw = payload[cursor:end]
    if kind == "null":
        value: object = None
    elif kind == "integer":
        value = inline if inline is not None else _decode_sqlite_signed_integer(raw)
    elif kind == "float":
        value = struct.unpack(">d", raw)[0]
    elif kind == "text":
        value = raw.decode("utf-8", errors="replace")
    else:
        value = raw
    return value, end


def _decode_sqlite_table_leaf_cell(
    data: bytes, cell_start: int
) -> Tuple[int, List[object], int]:
    """Decodes an inline SQLite table-leaf cell and its record payload.

    Overflow pages are intentionally not reconstructed here: Chromium URL rows
    of forensic interest are expected to fit in the acquisition window, and a
    partial cell is safer to reject than to manufacture from unrelated bytes.
    """

    payload_size, payload_size_len = _decode_sqlite_varint(data, cell_start)
    rowid_start = cell_start + payload_size_len
    rowid, rowid_len = _decode_sqlite_varint(data, rowid_start)
    payload_start = rowid_start + rowid_len
    payload_end = payload_start + payload_size
    if payload_size <= 0 or payload_end > len(data):
        raise ValueError("SQLite cell payload is unavailable or truncated")

    header_size, header_size_len = _decode_sqlite_varint(data, payload_start)
    header_end = payload_start + header_size
    if header_size < header_size_len or header_end > payload_end:
        raise ValueError("invalid SQLite record header size")

    serial_types: List[int] = []
    cursor = payload_start + header_size_len
    while cursor < header_end:
        serial_type, length = _decode_sqlite_varint(data, cursor)
        if cursor + length > header_end:
            raise ValueError("SQLite serial type crosses the record header")
        _sqlite_serial_layout(serial_type)
        serial_types.append(serial_type)
        cursor += length

    values: List[object] = []
    cursor = header_end
    for serial_type in serial_types:
        value, cursor = _decode_sqlite_record_value(data, cursor, serial_type)
        if cursor > payload_end:
            raise ValueError("SQLite record body exceeds its declared payload")
        values.append(value)
    return rowid, values, payload_end


def chrome_time(value: int) -> datetime.datetime:
    seconds, microseconds = divmod(value, 1_000_000)
    days, seconds = divmod(seconds, 86_400)
    if days > 160_000 or days < 140_000:
        days = seconds = microseconds = 0
    return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(
        days=days, seconds=seconds, microseconds=microseconds
    )


def utc_to_kst(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone(datetime.timedelta(hours=9))).isoformat()

SQLITE_NEEDLES = [
    b"\x08http", b"\x08file", b"\x08ftp", b"\x08chrome", b"\x08data",
    b"\x08about", b"\x01\x01http", b"\x01\x01file", b"\x01\x01ftp",
    b"\x01\x01chrome", b"\x01\x01data", b"\x01\x01about",
]

URL_SCHEMES = ("http", "https", "chrome", "edge", "brave", "opera", "vivaldi")
KNOWN_CHROMIUM_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
}

# PE TimeDateStamp + SizeOfImage values from matching browser binaries.  An
# unknown build is never guessed: it remains Unknown until its PDB-derived RVA
# is added here or supplied explicitly with --private-flag-rva.
PRIVATE_FLAG_BUILDS = {
    # Google Chrome 154.0.8037.98 (chrome.dll).  The RVA is the PDB-resolved
    # `anonymous namespace'::g_is_incognito_process renderer flag.
    (0x6ABD899F, 0x12320000): (
        0x117AAEF8, "Google Chrome 154.0.8037.98"
    ),
    # Brave 1.96.61 / Chromium 154 (chrome.dll), from Brave's official PDB.
    (0x6ABF8DA1, 0x13AE2000): (
        0x12F00E20, "Brave 1.96.61 (Chromium 154)"
    ),
    (0x6ABACB8E, 0x14F08000): (
        0x13FB3B78, "Microsoft Edge 154.0.4258.48"
    ),
    (0x6ABD9861, 0x14F3B000): (
        0x13E6B6CC, "Microsoft Edge 154.0.4258.53"
    ),
}
# Exact-build object metadata used when the renderer's flag page is not
# resident.  The key is the PDB-derived private-flag RVA selected above.
PRIVATE_CONTEXT_OBJECT_BUILDS = {
    0x117AAEF8: {
        # Values below are RVAs, not preferred-image virtual addresses.
        # Chrome's PDB reports several RenderProcessHostImpl vftables because
        # the class has multiple polymorphic bases. Candidate objects still
        # have to pass the client-id and BrowserContext identity checks.
        "otr_profile_vftable_rva": 0xF8FE0C8,
        "otr_original_profile_offset": 0xD0,
        "render_host_vftable_rvas": (
            0xF948948, 0xF915C68, 0xF8B4A48, 0xF947DF8,
            0xF8D7B20, 0xF5D5F00, 0xF955588, 0xF948888,
        ),
        "render_host_client_id_offset": 0x1B0,
        "render_host_browser_context_offset": 0x1B8,
        "navigation_controller_vftable_rva": 0xF5D5340,
        "navigation_entry_vftable_rva": 0xF5D54D0,
        "navigation_controller_context_offset": 0x10,
        "navigation_controller_entries_offset": 0x18,
        "navigation_entry_virtual_url_offset": 0x28,
        "navigation_entry_frame_tree_offset": 0x18,
        "tree_node_frame_entry_offset": 0x08,
        "frame_navigation_url_offset": 0x60,
    },
    0x12F00E20: {
        "otr_profile_vftable_rva": 0x10C8BB48,
        "otr_original_profile_offset": 0xD0,
        "render_host_vftable_rvas": (
            0x10D15450, 0x109531D8, 0x10C70CB8, 0x10D14890,
            0x10C96748, 0x109531D0, 0x10D221A0, 0x10D15390,
        ),
        "render_host_client_id_offset": 0x1B0,
        "render_host_browser_context_offset": 0x1B8,
        "navigation_controller_vftable_rva": 0x10952600,
        "navigation_entry_vftable_rva": 0x10952790,
        "navigation_controller_context_offset": 0x10,
        "navigation_controller_entries_offset": 0x18,
        # Brave adds browser-specific fields before its committed URL GURL.
        "navigation_entry_virtual_url_offset": 0x1D0,
        "navigation_entry_frame_tree_offset": 0x18,
        "tree_node_frame_entry_offset": 0x08,
        "frame_navigation_url_offset": 0x60,
    },
    # Edge 154.0.4258.53: all three values below were derived from the
    # matching msedge.dll PDB and validated against live renderer client IDs.
    0x13E6B6CC: {
        "otr_profile_vftable_rva": 0x112A73A8,
        "otr_original_profile_offset": 0xF8,
        # Primary complete-object vftable.  Other PDB vftables refer to base
        # subobjects and must not be parsed with complete-object offsets.
        "render_host_vftable_rvas": (0x112B3760,),
        "render_host_client_id_offset": 0x1B0,
        "render_host_browser_context_offset": 0x1B8,
    },
}
CHROMIUM_MODULE_MARKERS = {
    "chrome.dll",
    "chrome_elf.dll",
    "msedge.dll",
    "libcef.dll",
    "opera_browser.dll",
    "vivaldi.dll",
}
BROWSER_MODULE_PREFERENCES = {
    "chrome.exe": ("chrome.dll",),
    "chromium.exe": ("chrome.dll",),
    "brave.exe": ("chrome.dll",),
    "msedge.exe": ("msedge.dll",),
    "opera.exe": ("opera_browser.dll", "chrome.dll"),
    "vivaldi.exe": ("vivaldi.dll", "chrome.dll"),
}
MEMORY_NEEDLES = [
    needle
    for scheme in URL_SCHEMES
    for needle in (
        (scheme + "://").encode("ascii"),
        (scheme + "://").encode("utf-16le"),
    )
]

SCHEME_PATTERN = rb"(?:https?|chrome|edge|brave|opera|vivaldi)"
ASCII_URL = re.compile(
    rb"^" + SCHEME_PATTERN + rb"://[^\x00-\x20\x22\x27<>\\\x7f]+", re.I
)
TEXT_URL = re.compile(
    r"^(?:https?|chrome|edge|brave|opera|vivaldi)://"
    r"[^\x00-\x20\x22\x27<>\\\x7f]+",
    re.I,
)
TRAILING_PUNCTUATION = ".,;!)]}"
RESOURCE_EXTENSIONS = {
    ".js", ".css", ".map", ".json", ".xml", ".wasm",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".m4a", ".mp4", ".webm",
}
STATIC_HOST_MARKERS = (
    "cdn.", "static.", "assets.", "schemas.", "fonts.", "img.",
    "images.", "gstatic.com", "googleapis.com", "akamaized.net",
)
BROWSER_CONTEXT_NAMES = tuple(
    name.encode("ascii") for name in sorted(KNOWN_CHROMIUM_PROCESSES)
)
NETWORK_CONTEXT_MARKERS = (
    b"user-agent", b"referer", b"authorization", b"cookie",
    b"sec-fetch-", b"content-type", b"origin:", b"accept-language",
)
SESSION_FILE_RE = re.compile(
    r"(?:^|\\)(?P<profile>[^\\]+)\\Sessions\\"
    r"(?P<kind>Tabs|Session)_(?P<stamp>\d+)$",
    re.IGNORECASE,
)
SESSION_URL_RE = re.compile(rb"https?://[^\x00-\x20\"<>]{3,4096}")
NON_BROWSER_TEXT_MARKERS = (
    b"self.assert", b"unittest.", b"def test_", b"<toast", b"</toast",
    b"<text>", b"</text>", b"<binding", b"</binding>", b"<actions",
    b"placeholdercontent=", b"launch=", b"```", b"source code",
)


@dataclasses.dataclass(frozen=True)
class RecoveredURL:
    source: str
    confidence: str
    pid: int
    process: str
    offset: int
    url: str
    search_engine: str = ""
    search_query: str = ""
    candidate_score: int = 0
    candidate_reasons: str = ""
    title: str = ""
    visit_count: int = -1
    typed_count: int = -1
    last_visit_time: str = ""
    navigation_structure: str = ""
    navigation_index: int = -1
    transition_type: int = -1
    activity_role: str = "Unclassified"
    persistence_assessment: str = "NotCompared"
    browsing_mode: str = "Unknown"
    mode_evidence: str = "No private-mode structure linked"
    artifact_class: str = "StaleOrUnattributed"
    canonical_activity: str = ""


@dataclasses.dataclass(frozen=True)
class SerializedNavigation:
    """Strictly validated prefix of Chromium SerializedNavigationEntry."""

    url: str
    title: str
    index: int
    transition_type: int


def chromium_session_time(value: str) -> str:
    """Converts a Chromium session filename timestamp to ISO-8601 UTC."""

    try:
        timestamp = int(value)
        result = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        result += datetime.timedelta(microseconds=timestamp)
    except (ValueError, OverflowError):
        return ""
    return result.isoformat()


def extract_session_urls(data: bytes, max_url_length: int = 4096) -> Iterator[Tuple[int, str]]:
    """Yields conservative HTTP(S) URL strings from cached SNSS data."""

    seen: Set[str] = set()
    for match in SESSION_URL_RE.finditer(data):
        raw = match.group(0)[:max_url_length]
        try:
            url = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        url = extract_memory_url(raw + b"\x00", False, max_url_length)
        if not is_recoverable_url(url):
            continue
        key = normalize_url(url)
        if key in seen:
            continue
        seen.add(key)
        yield match.start(), url


def _pickle_aligned(position: int, payload_start: int) -> int:
    relative = position - payload_start
    return position + ((-relative) & 3)


def parse_serialized_navigation(
    data: bytes, url_offset: int
) -> Optional[SerializedNavigation]:
    """Parses stable leading fields written by Chromium's WriteToPickle."""

    if url_offset < 8 or url_offset + 8 > len(data):
        return None
    payload_start = url_offset - 8
    index = struct.unpack_from("<i", data, payload_start)[0]
    url_length = struct.unpack_from("<I", data, url_offset - 4)[0]
    if (not -1 <= index <= 100000
            or not 8 <= url_length <= 4096):
        return None
    url_end = url_offset + url_length
    if url_end > len(data):
        return None
    try:
        url = data[url_offset:url_end].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not is_recoverable_url(url):
        return None

    cursor = _pickle_aligned(url_end, payload_start)
    if cursor + 4 > len(data):
        return None
    title_chars = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    if title_chars > 4096 or cursor + title_chars * 2 > len(data):
        return None
    try:
        title = data[cursor:cursor + title_chars * 2].decode(
            "utf-16le", errors="strict"
        )
    except UnicodeDecodeError:
        return None
    cursor = _pickle_aligned(cursor + title_chars * 2, payload_start)

    if cursor + 4 > len(data):
        return None
    page_state_length = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    if page_state_length > 65536 or cursor + page_state_length > len(data):
        return None
    cursor = _pickle_aligned(cursor + page_state_length, payload_start)
    if cursor + 8 > len(data):
        return None
    transition_type = struct.unpack_from("<i", data, cursor)[0]
    if transition_type & 0xFF > 10:
        return None
    cursor += 4
    type_mask = struct.unpack_from("<i", data, cursor)[0]
    if type_mask not in (0, 1):
        return None
    cursor += 4

    def read_string(position: int) -> Optional[Tuple[str, int]]:
        if position + 4 > len(data):
            return None
        length = struct.unpack_from("<I", data, position)[0]
        position += 4
        if length > 4096 or position + length > len(data):
            return None
        try:
            value = data[position:position + length].decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
        return value, _pickle_aligned(position + length, payload_start)

    referrer_result = read_string(cursor)
    if referrer_result is None:
        return None
    referrer, cursor = referrer_result
    if referrer and not is_recoverable_url(referrer):
        return None
    if cursor + 4 > len(data) or struct.unpack_from("<i", data, cursor)[0] != 2:
        return None
    cursor += 4
    original_result = read_string(cursor)
    if original_result is None:
        return None
    original_url, cursor = original_result
    if original_url and not is_recoverable_url(original_url):
        return None
    if cursor + 20 > len(data):
        return None
    override_ua = data[cursor]
    cursor += 4  # Pickle bool is one byte padded to uint32 alignment.
    timestamp = struct.unpack_from("<q", data, cursor)[0]
    cursor += 8
    removed_search_terms = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    http_status = struct.unpack_from("<i", data, cursor)[0]
    if (override_ua not in (0, 1) or removed_search_terms != 0
            or not 0 <= http_status <= 999
            or timestamp < 0):
        return None
    return SerializedNavigation(url, title, index, transition_type)


def normalize_url(url: str) -> str:
    value = url.strip().rstrip(TRAILING_PUNCTUATION)
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return value.casefold()
    if parsed.scheme.casefold() not in ("http", "https") or not parsed.netloc:
        return value.casefold()
    return urllib.parse.urlunsplit(
        (parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path,
         parsed.query, parsed.fragment)
    )


def extract_memory_url(data: bytes, wide: bool, max_length: int = 4096) -> str:
    """Extracts a bounded URL that starts at the beginning of data."""
    if max_length <= 0:
        return ""
    if wide:
        text = data[: max_length * 2].decode("utf-16le", errors="ignore")
        match = TEXT_URL.match(text)
        value = match.group(0) if match else ""
        value = re.split(r"[^\x21-\x7e]", value, maxsplit=1)[0]
    else:
        match = ASCII_URL.match(data[:max_length])
        value = match.group(0).decode("utf-8", errors="replace") if match else ""
    value = re.split(r"[^\x21-\x7e]", value, maxsplit=1)[0]
    lower_value = value.casefold()
    embedded_starts = [
        lower_value.find(separator)
        for separator in (
            ",http://", ",https://", ",edge://", ",chrome://",
            ";http://", ";https://", ";edge://", ";chrome://",
        )
    ]
    embedded_starts = [position for position in embedded_starts if position >= 0]
    if embedded_starts:
        value = value[:min(embedded_starts)]
    return value.rstrip(TRAILING_PUNCTUATION)


def decode_libcpp_string(
    layer: object, address: int, max_length: int = 4096
) -> str:
    """Reads Chromium's 64-bit libc++ ``std::string`` representation."""

    header = layer.read(address, 24, pad=False)
    candidates = []
    if header[0] & 1:
        candidates.append((struct.unpack_from("<Q", header, 16)[0],
                           struct.unpack_from("<Q", header, 8)[0], b""))
    else:
        candidates.append((0, header[0] >> 1,
                           header[1:1 + (header[0] >> 1)]))

    # Chromium 154 also uses libc++'s alternate string layout in which a
    # long string is {pointer, size, capacity} and a short string keeps its
    # length in the final byte.  Pointer/length plausibility plus strict UTF-8
    # decoding prevents treating arbitrary objects as strings.
    pointer, length = struct.unpack_from("<QQ", header, 0)
    if 0x10000 <= pointer < 0x800000000000:
        candidates.append((pointer, length, b""))
    for short_length in (header[23] >> 1, header[23] & 0x7F):
        if short_length:
            candidates.append((0, short_length, header[:short_length]))

    for data_pointer, length, inline in candidates:
        if not (0 < length <= max_length):
            continue
        try:
            raw = inline if inline else layer.read(
                data_pointer, int(length), pad=False
            )
            return raw.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, exceptions.InvalidAddressException):
            continue
    return ""


def is_recoverable_url(url: str) -> bool:
    """Rejects browser match-patterns and malformed web URLs."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme.casefold() in ("http", "https"):
        host = parsed.hostname or ""
        return bool(host) and "*" not in host and "*" not in parsed.path
    return bool(parsed.scheme and parsed.netloc)


def search_details(url: str) -> Tuple[str, str]:
    """Returns a recognized search engine and decoded query value."""
    try:
        parsed = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except ValueError:
        return "", ""
    host = (parsed.hostname or "").casefold()
    path = parsed.path.casefold()
    engine = ""
    key = ""
    if "google." in host and path == "/search":
        engine, key = "Google", "q"
    elif host.endswith("bing.com") and path == "/search":
        engine, key = "Bing", "q"
    elif host.endswith("duckduckgo.com"):
        engine, key = "DuckDuckGo", "q"
    elif host.endswith("search.naver.com"):
        engine, key = "Naver", "query"
    elif host.endswith("search.daum.net"):
        engine, key = "Daum", "q"
    elif "search.yahoo." in host:
        engine, key = "Yahoo", "p"
    elif host.endswith("baidu.com") and path == "/s":
        engine, key = "Baidu", "wd"
    elif "yandex." in host and "search" in path:
        engine, key = "Yandex", "text"
    elif "search" in path and "q" in params:
        engine, key = host, "q"
    query = ""
    if key:
        # parse_qs replaces malformed UTF-8 percent escapes with U+FFFD.  A
        # truncated memory string such as q=%ED%86%A0%EB must not be promoted
        # to a genuine search for ``토�``.  Decode the selected value again
        # with strict UTF-8 so incomplete memory fragments remain ordinary URL
        # remnants rather than high-confidence search activity.
        for field in parsed.query.split("&"):
            raw_key, separator, raw_value = field.partition("=")
            if not separator:
                continue
            try:
                decoded_key = urllib.parse.unquote_plus(
                    raw_key, encoding="utf-8", errors="strict"
                )
                if decoded_key != key:
                    continue
                query = urllib.parse.unquote_to_bytes(
                    raw_value.replace("+", " ")
                ).decode("utf-8", errors="strict").strip()
            except (UnicodeDecodeError, ValueError):
                return "", ""
            break
    if not query or "{searchterms" in query.casefold():
        return "", ""
    return (engine, query) if query else ("", "")


def session_recovery_is_exclusive(config) -> bool:
    """Returns whether --recover-sessions should avoid generic memory scans."""

    if not config.get("recover_sessions", False):
        return False
    scalar_modes = (
        "recover_searches", "recover_closed", "navigation_candidates",
        "navigation_structures", "memory_only", "scan_physical",
        "physical_only", "physical_browser_context", "process_only",
    )
    if any(config.get(name, False) for name in scalar_modes):
        return False
    if str(config.get("search_terms", "")).strip():
        return False
    if config.get("pid") or config.get("eprocess_offsets"):
        return False
    return True


def search_query_value(url: str) -> str:
    return search_details(url)[1]


def matches_search_terms(url: str, terms: Sequence[str]) -> bool:
    query = search_query_value(url).casefold()
    return bool(query) and query in {term.strip().casefold() for term in terms}


def search_identity(url: str) -> str:
    """Collapses duplicate copies of the same engine/path/query search URL."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return normalize_url(url)
    query = search_query_value(url)
    if not query:
        return normalize_url(url)
    return "|".join((parsed.netloc.casefold(), parsed.path, query.casefold()))


def url_components(url: str) -> Tuple[str, str, str]:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "", "", ""
    return parsed.hostname or "", parsed.path, parsed.query


def physical_browser_context(
    context: bytes, url_position: int, url: str
) -> Tuple[int, str]:
    """Scores browser/network artifacts surrounding a physical URL string.

    The URL value itself and its query terms do not affect this score. This
    deliberately lets the same logic handle unknown sites and blind tests.
    """

    lower = context.lower()
    score = 0
    reasons: List[str] = []
    nearby_start = max(0, url_position - 256)
    nearby_end = min(len(lower), url_position + len(url.encode("utf-8")) + 256)
    nearby = lower[nearby_start:nearby_end]
    browser_names = [name for name in BROWSER_CONTEXT_NAMES if name in nearby]
    if browser_names:
        score += 55
        reasons.append("adjacent-browser-process-name")

    url_count = len(re.findall(rb"https?://", lower))
    if url_count >= 2:
        score += 20
        reasons.append("neighboring-url-cluster")

    host, _path, _query = url_components(url)
    try:
        host_bytes = (host.casefold().encode("idna")
                      if host and len(host) <= 253 else b"")
    except UnicodeError:
        host_bytes = b""
    if host_bytes and lower.count(host_bytes) >= 2:
        score += 15
        reasons.append("same-host-request-cluster")

    marker_count = sum(1 for marker in NETWORK_CONTEXT_MARKERS if marker in lower)
    if marker_count:
        score += min(30, marker_count * 10)
        reasons.append("http-network-metadata")

    if any(marker in lower for marker in NON_BROWSER_TEXT_MARKERS):
        score -= 80
        reasons.append("code-or-message-context-penalty")
    return max(0, score), ";".join(reasons or ["isolated-url-string"])


def clean_network_record_url(url: str) -> str:
    """Removes adjacent fields commonly concatenated in network records."""

    for separator in ("/data:image/", "/blob:http://", "/blob:https://"):
        if separator in url:
            url = url.split(separator, 1)[0]
    host, _path, _query = url_components(url)
    if host:
        trailer = re.compile(
            r"\." + re.escape(host) + r"\.\d+\.\d+\.\d+.*$", re.I
        )
        url = trailer.sub("", url)
    url = re.sub(
        r"(?:\.\.|\.[a-z0-9-]+(?:\.[a-z0-9-]+)+\.)\d+\.\d+\.\d+$",
        "", url, flags=re.I,
    )
    return url.rstrip(TRAILING_PUNCTUATION)


def classify_activity_role(
    url: str, context: bytes = b"", source: str = ""
) -> Tuple[str, str]:
    """Classifies navigation likelihood without using site or query names."""

    if source == "HistoryDB":
        return "PersistedNavigation", "persisted-history-row"
    if source == "SerializedNavigation":
        return "ConfirmedNavigationStructure", "serialized-navigation-entry"
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "Unclassified", "invalid-url"
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "/").casefold()
    leaf = path.rsplit("/", 1)[-1]
    extension = "." + leaf.rsplit(".", 1)[-1] if "." in leaf else ""
    if (extension in RESOURCE_EXTENSIONS
            or any(marker in host for marker in STATIC_HOST_MARKERS)
            or any(marker in path for marker in (
                "/api/", "/telemetry", "/gen_204", "/favicon", "/csp/"
            ))):
        return "SubresourceOrBackground", "resource-or-background-shape"

    lower = context.lower()
    explicit_navigation = (
        re.search(rb"sec-fetch-dest.{0,32}document", lower, re.S)
        or re.search(rb"sec-fetch-mode.{0,32}navigate", lower, re.S)
    )
    html_response = re.search(rb"content-type.{0,32}text/html", lower, re.S)
    if explicit_navigation:
        return "ProbableTopLevelNavigation", "fetch-metadata-navigation"
    if html_response:
        return "ProbableTopLevelNavigation", "html-response-context"
    if source == "PhysicalBrowserContext" and not extension:
        return "PossibleDocumentRequest", "document-like-url-with-browser-context"
    return "Unclassified", "insufficient-navigation-context"


def classify_artifact(
    url: str, source: str, activity_role: str
) -> Tuple[str, str]:
    """Separates user-activity candidates from browser-owned URL strings."""

    if source == "HistoryDB":
        return "PersistedNavigation", normalize_url(url)
    if source == "SerializedNavigation":
        return "ConfirmedNavigationStructure", normalize_url(url)
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "TemplateOrInternal", ""
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    path = (parsed.path or "/").casefold()
    if (scheme not in ("http", "https")
            or host in ("permanently-removed.invalid", "webui-test", "resources",
                        "newtab")
            or "$" in url or "{" in url or "}" in url
            or "%s" in url.casefold()):
        return "TemplateOrInternal", ""
    if activity_role == "SubresourceOrBackground":
        return "BackgroundOrEmbedded", ""
    engine, query = search_details(url)
    query = " ".join(query.split())
    if query and not re.fullmatch(r"\$\d+", query):
        provider = host.removeprefix("www.")
        canonical = "search:{}:{}".format(provider, query.casefold())
        return "SearchActivity", canonical
    if activity_role in (
        "PersistedNavigation", "ConfirmedNavigationStructure",
        "ProbableTopLevelNavigation",
    ):
        return "ProbableUserNavigation", normalize_url(url)
    return "StaleOrUnattributed", normalize_url(url)


def persistence_assessment(
    url: str, history_keys: Set[str], history_scanned: bool
) -> str:
    if not history_scanned:
        return "NotCompared"
    if normalize_url(url) in history_keys:
        return "PersistedHistoryCorroborated"
    return "NotInRecoveredHistory"


def recovered_activity_identity(record: RecoveredURL) -> str:
    """Builds a cross-source identity for default-output deduplication."""

    if record.canonical_activity:
        return record.canonical_activity
    engine, query = search_details(record.url)
    if query:
        return "search:{}:{}".format(
            (engine or urlparse(record.url).netloc).casefold(),
            query.casefold(),
        )
    return normalize_url(record.url)


def navigation_score(url: str, source: str = "") -> Tuple[int, str]:
    """Scores URL-shaped remnants without claiming they prove a visit."""
    try:
        parsed = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except ValueError:
        return 0, "invalid-url"
    host = (parsed.hostname or "").casefold()
    path = parsed.path or "/"
    lower_path = path.casefold()
    suffix = lower_path.rsplit("/", 1)[-1]
    extension = "." + suffix.rsplit(".", 1)[-1] if "." in suffix else ""
    if (not host or "{" in url or "}" in url
            or "*" in host or "*" in parsed.path):
        return 0, "template-or-invalid"
    if extension in RESOURCE_EXTENSIONS:
        return 0, "static-resource-extension"

    score = 10
    reasons = ["web-url"]
    if source == "SerializedNavigation":
        score += 140
        reasons.append("serialized-navigation-entry")
    elif source == "HistoryDB":
        score += 90
        reasons.append("persisted-history-row")
    elif source in ("ProcessMemory", "MemoryOnly", "ProcessURLString"):
        score += 60
        reasons.append("browser-process-vad")
    else:
        reasons.append("unattributed-physical-string")

    if path == "/":
        score += 15
        reasons.append("root-document-shape")
    elif not extension:
        score += 10
        reasons.append("document-like-path")

    engine, query = search_details(url)
    if query:
        score += 5
        reasons.append(f"search-query:{engine}")

    if any(marker in host for marker in STATIC_HOST_MARKERS):
        score -= 25
        reasons.append("static-host-penalty")
    if any(marker in lower_path for marker in ("/api/", "/telemetry", "/gen_204", "/favicon")):
        score -= 20
        reasons.append("background-request-penalty")
    return max(0, score), ";".join(reasons)


def evidence_class(source: str) -> str:
    if source == "SerializedNavigation":
        return "BrowserNavigationStructure"
    if source == "PhysicalBrowserContext":
        return "BrowserNetworkContext"
    if source == "HistoryDB" or source in ("ProcessMemory", "PhysicalMemory"):
        return "PersistedHistoryCorroborated"
    if source in ("MemoryOnly", "ProcessURLString"):
        return "BrowserProcessCandidate"
    return "UnattributedPhysical"


def classify_memory_source(url: str, history_keys: Set[str]) -> Tuple[str, str]:
    if normalize_url(url) in history_keys:
        return "ProcessMemory", "Corroborated by HistoryDB"
    return "MemoryOnly", "Possible Incognito; not conclusive"


def classify_physical_source(url: str, history_keys: Set[str]) -> Tuple[str, str]:
    if normalize_url(url) in history_keys:
        return "PhysicalMemory", "Corroborated by HistoryDB; browser unknown"
    return "PhysicalMemoryOnly", "Possible closed private session; not conclusive"


class ChromiumHistory(interfaces.plugins.PluginInterface):
    """Recovers Chromium history and possible private-mode URLs."""

    _required_framework_version = (2, 4, 0)
    _version = (3, 16, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.VersionRequirement(
                name="psscan", component=psscan.PsScan, version=(2, 0, 0)),
            requirements.VersionRequirement(
                name="filescan", component=filescan.FileScan, version=(2, 0, 0)),
            requirements.ListRequirement(
                name="pid", description="Browser process IDs to include",
                element_type=int, optional=True),
            requirements.ListRequirement(
                name="eprocess_offsets",
                description=(
                    "Optional virtual _EPROCESS offsets recovered by PsScan; "
                    "allows scanning Chromium processes missing from PsList"
                ),
                element_type=int, optional=True),
            requirements.IntRequirement(
                name="private_flag_rva",
                description=(
                    "Renderer private-mode bool RVA resolved from the exact "
                    "browser PDB; 0 selects a supported build automatically"
                ),
                default=0, optional=True),
            requirements.StringRequirement(
                name="browser_module",
                description=(
                    "Browser code module containing the private-mode flag; "
                    "auto selects a module from each process family"
                ),
                default="auto", optional=True),
            requirements.StringRequirement(
                name="process_names",
                description=(
                    "Optional comma-separated process-name override; empty uses "
                    "Chromium module auto-detection"
                ),
                default="",
                optional=True),
            requirements.StringRequirement(
                name="process_name",
                description="Single browser process name (compatibility override)",
                default="", optional=True),
            requirements.BooleanRequirement(
                name="memory_only",
                description="Only show URLs absent from recovered HistoryDB rows",
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="skip_history",
                description="Skip HistoryDB scanning and carve browser VAD URLs directly",
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="history_only",
                description=(
                    "Recover only persisted Chromium History database rows; "
                    "do not scan process or physical memory for URL strings"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="compare_history",
                description=(
                    "Scan recovered HistoryDB rows even when a targeted memory "
                    "mode is selected, enabling persistence comparison"
                ),
                default=False, optional=True),
            requirements.StringRequirement(
                name="url_filter",
                description="Optional comma-separated URL substrings to retain",
                default="", optional=True),
            requirements.StringRequirement(
                name="search_terms",
                description=(
                    "Comma-separated exact q= search values; automatically scans "
                    "browser VADs and physical memory"
                ),
                default="", optional=True),
            requirements.BooleanRequirement(
                name="recover_searches",
                description=(
                    "Automatically recover recognized search-engine queries from "
                    "browser VADs and physical memory"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="recover_closed",
                description=(
                    "Recover arbitrary URL remnants from browser VADs and full "
                    "physical memory without requiring a known URL or search term"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="recover_sessions",
                description=(
                    "Recover cached Chromium Sessions/Tabs files and label "
                    "restored or session-backed navigation separately"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="raw_url_strings",
                description=(
                    "Include browser-owned internal, template, static-resource, "
                    "and background URL strings that are suppressed by default"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="include_unattributed",
                description=(
                    "Include document-shaped URL strings that lack navigation "
                    "or search evidence; still suppress background/templates"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="navigation_candidates",
                description=(
                    "Correlate HistoryDB and score likely top-level navigation "
                    "URLs while suppressing common resource noise"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="navigation_structures",
                description=(
                    "Experimentally recover strictly validated Chromium "
                    "SerializedNavigationEntry structures from browser VADs"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="include_chromium_apps",
                description=(
                    "Include non-browser Chromium/CEF/Electron applications in "
                    "navigation candidate mode"
                ),
                default=False, optional=True),
            requirements.IntRequirement(
                name="min_candidate_score",
                description="Minimum navigation candidate score",
                default=70, optional=True),
            requirements.BooleanRequirement(
                name="suppress_null_time",
                description="Suppress HistoryDB rows with a null Chromium timestamp",
                default=True, optional=True),
            requirements.IntRequirement(
                name="max_url_length", description="Maximum URL character length",
                default=4096, optional=True),
            requirements.IntRequirement(
                name="max_results", description="Maximum unique memory URLs",
                default=10000, optional=True),
            requirements.BooleanRequirement(
                name="physical_fallback",
                description=(
                    "Scan physical memory when process VAD scanning yields no URLs"
                ),
                default=True, optional=True),
            requirements.BooleanRequirement(
                name="scan_physical",
                description="Always scan physical memory for stale browser URLs",
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="physical_only",
                description="Only scan physical memory; skip browser process VADs",
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="physical_browser_context",
                description=(
                    "Only retain physical URLs with adjacent generic browser or "
                    "HTTP/network artifacts; no search terms are required"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="top_level_only",
                description=(
                    "Only retain persisted or structurally probable top-level "
                    "navigation rows; exclude possible document requests"
                ),
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="process_only",
                description="Do not invoke the physical-memory fallback",
                default=False, optional=True),
            requirements.BooleanRequirement(
                name="full_output",
                description=(
                    "Show all forensic fields; the default compact view keeps "
                    "terminal output readable"
                ),
                default=False, optional=True),
        ]

    def _cached_file_data(self, file_obj) -> Iterator[bytes]:
        """Reads resident DataSection/SharedCacheMap pages without writing files."""

        kernel = self.context.modules[self.config["kernel"]]
        primary_layer = self.context.layers[kernel.layer_name]
        memory_layer = self.context.layers[primary_layer.config["memory_layer"]]
        candidates = []
        try:
            control_area = (
                file_obj.SectionObjectPointer.DataSectionObject
                .dereference().cast("_CONTROL_AREA")
            )
            if control_area.is_valid():
                candidates.append((control_area, memory_layer))
        except exceptions.InvalidAddressException:
            pass
        try:
            shared = (
                file_obj.SectionObjectPointer.SharedCacheMap
                .dereference().cast("_SHARED_CACHE_MAP")
            )
            if shared.is_valid():
                candidates.append((shared, primary_layer))
        except exceptions.InvalidAddressException:
            pass

        for memory_object, layer in candidates:
            chunks = []
            logical_size = 0
            try:
                pages = list(memory_object.get_available_pages())
                for memoffset, fileoffset, datasize in pages:
                    if fileoffset > 32 * 1024 * 1024:
                        continue
                    data = layer.read(memoffset, datasize, pad=True)
                    chunks.append((fileoffset, data))
                    logical_size = max(logical_size, fileoffset + len(data))
            except exceptions.InvalidAddressException:
                continue
            if not chunks or logical_size > 32 * 1024 * 1024:
                continue
            result = bytearray(logical_size)
            for fileoffset, data in chunks:
                result[fileoffset:fileoffset + len(data)] = data
            yield bytes(result)

    def _session_records(self) -> Iterator[RecoveredURL]:
        """Recovers URLs from resident Chromium SNSS session/tab files."""

        emitted: Set[Tuple[str, str, str]] = set()
        for file_obj in filescan.FileScan.scan_files(
            self.context, self.config["kernel"]
        ):
            try:
                name = str(file_obj.file_name_with_device())
            except (exceptions.InvalidAddressException, ValueError):
                continue
            match = SESSION_FILE_RE.search(name)
            if not match:
                continue
            lowered = name.casefold()
            if "\\microsoft\\edge\\" in lowered:
                process = "msedge.exe"
            elif "\\opera software\\" in lowered:
                process = "opera.exe"
            elif "\\google\\chrome\\" in lowered:
                process = "chrome.exe"
            elif "\\bravesoftware\\" in lowered:
                process = "brave.exe"
            elif "\\vivaldi\\" in lowered:
                process = "vivaldi.exe"
            else:
                process = "chromium"
            kind = match.group("kind").title()
            timestamp = chromium_session_time(match.group("stamp"))
            timestamp_kst = utc_to_kst(timestamp)
            for data in self._cached_file_data(file_obj):
                for local_offset, url in extract_session_urls(
                    data, self.config.get("max_url_length", 4096)
                ):
                    navigation = parse_serialized_navigation(data, local_offset)
                    if navigation is None:
                        continue
                    url = navigation.url
                    identity = (process, kind, normalize_url(url))
                    if identity in emitted:
                        continue
                    emitted.add(identity)
                    engine, query = search_details(url)
                    yield RecoveredURL(
                        source="SessionFile",
                        confidence=(
                            "Cached Chromium session state; may represent an "
                            "open, closed, restored, or prior navigation entry; "
                            f"session file time {timestamp_kst or timestamp}"
                        ),
                        pid=-1,
                        process=process,
                        offset=file_obj.vol.offset + local_offset,
                        url=url,
                        search_engine=engine,
                        search_query=query,
                        title=navigation.title,
                        # The timestamp in the SNSS filename is the session
                        # file generation/update time, not this URL's visit
                        # time.  Never expose it as LastVisitUTC/KST.
                        last_visit_time="",
                        navigation_structure="SerializedNavigationEntry",
                        navigation_index=navigation.index,
                        transition_type=navigation.transition_type,
                        activity_role=f"{kind}StateNavigation",
                        persistence_assessment="SessionStateArtifact",
                        browsing_mode="Unknown",
                        mode_evidence=(
                            "Session files do not establish regular/private mode; "
                            f"file time {timestamp_kst or timestamp} is not a URL visit time"
                        ),
                        artifact_class="BrowserSessionState",
                        canonical_activity=normalize_url(url),
                    )

    def _history_records(self) -> Iterator[RecoveredURL]:
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]
        scanner = scanners.MultiStringScanner(SQLITE_NEEDLES)
        for offset, _needle in layer.scan(
            self.context, scanner, progress_callback=self._progress_callback
        ):
            try:
                data = layer.read(offset - 15, 4500, pad=False)
                record = self._parse_history_buffer(data, offset)
            except (exceptions.InvalidAddressException, IndexError, ValueError, TypeError):
                continue
            if record:
                yield record

    def _parse_history_buffer(
        self, data: bytes, offset: int
    ) -> Optional[RecoveredURL]:
        """Finds and validates a Chromium ``urls`` table-leaf cell.

        The scanner anchor is 15 bytes into this window. Instead of assuming a
        fixed arrangement before that anchor, every possible local cell start
        is decoded using SQLite's declared payload and record header lengths.
        """

        allowed = (
            "http://", "https://", "file:", "ftp:", "chrome:",
            "edge:", "brave:", "opera:", "vivaldi:", "data:", "about:",
        )
        anchor = min(15, len(data) - 1)
        for cell_start in range(anchor + 1):
            try:
                _rowid, values, _cell_end = _decode_sqlite_table_leaf_cell(
                    data, cell_start
                )
            except (IndexError, TypeError, ValueError, struct.error):
                continue
            if len(values) < 7:
                continue
            url_id, url, title, visit_count, typed_count, raw_time, hidden = (
                values[:7]
            )
            # INTEGER PRIMARY KEY values may be represented only by the cell
            # rowid, leaving the corresponding record column as serial NULL.
            if url_id is not None and not isinstance(url_id, int):
                continue
            if not isinstance(url, str) or not url.startswith(allowed):
                continue
            if not 0 < len(url.encode("utf-8", errors="replace")) <= 4096:
                continue
            if title is None:
                title = ""
            if not isinstance(title, str):
                continue
            if not all(
                isinstance(value, int)
                for value in (visit_count, typed_count, raw_time, hidden)
            ):
                continue
            if len(values) > 7 and values[7] is not None and not isinstance(
                values[7], int
            ):
                continue

            timestamp = chrome_time(raw_time)
            if timestamp.year == 1601 and self.config.get(
                "suppress_null_time", True
            ):
                continue
            engine, query = search_details(url)
            return RecoveredURL(
                source="HistoryDB",
                confidence="Persisted SQLite record",
                pid=0,
                process="",
                offset=int(offset),
                url=url,
                search_engine=engine,
                search_query=query,
                title=title,
                visit_count=visit_count,
                typed_count=typed_count,
                last_visit_time=str(timestamp),
                activity_role="PersistedNavigation",
                persistence_assessment="PersistedHistory",
                browsing_mode="Regular",
                mode_evidence="Persisted Chromium History database record",
            )
        return None

    def _selected_processes(self) -> Iterable[object]:
        pid_filter = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        override = self.config.get("process_name", "").strip()
        configured = override or self.config.get("process_names", "")
        wanted = {
            name.strip().casefold()
            for name in configured.replace(";", ",").split(",")
            if name.strip()
        }
        explicit_pids = bool(self.config.get("pid", None))
        eprocess_offsets = self.config.get("eprocess_offsets", None) or []
        if eprocess_offsets:
            kernel = self.context.modules[self.config["kernel"]]
            for offset in eprocess_offsets:
                proc = kernel.object(
                    "_EPROCESS", offset=int(offset), absolute=True
                )
                try:
                    if not pid_filter(proc):
                        yield proc
                except exceptions.InvalidAddressException:
                    continue
            return
        seen_offsets: Set[int] = set()
        for proc in pslist.PsList.list_processes(
            self.context, self.config["kernel"], filter_func=pid_filter
        ):
            name = utility.array_to_string(proc.ImageFileName)
            if explicit_pids or (wanted and name.casefold() in wanted):
                seen_offsets.add(int(proc.vol.offset))
                yield proc
                continue
            if (not self.config.get("include_chromium_apps", False)
                    and name.casefold() not in KNOWN_CHROMIUM_PROCESSES):
                continue
            if not wanted and self._is_chromium_process(proc, name):
                seen_offsets.add(int(proc.vol.offset))
                yield proc

        # PsList can omit active Chromium renderers.  In the ordinary no-hint
        # workflow, recover browser _EPROCESS objects directly with PsScan.
        if not explicit_pids and not wanted:
            for proc in psscan.PsScan.scan_processes(
                self.context, self.config["kernel"], filter_func=pid_filter
            ):
                try:
                    offset = int(proc.vol.offset)
                    if offset in seen_offsets:
                        continue
                    name = utility.array_to_string(proc.ImageFileName)
                    if name.casefold() not in KNOWN_CHROMIUM_PROCESSES:
                        continue
                    seen_offsets.add(offset)
                    yield proc
                except exceptions.InvalidAddressException:
                    continue

    @staticmethod
    def _auto_private_flag_rva(layer: object, module_base: int) -> Tuple[int, str]:
        """Resolves a supported browser build from its in-memory PE header."""

        try:
            dos = layer.read(module_base, 0x1000, pad=False)
            if dos[:2] != b"MZ":
                return 0, "Browser module DOS header unavailable"
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            needed = pe_offset + 24 + 60
            if needed > len(dos):
                dos = layer.read(module_base, needed, pad=False)
            if dos[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return 0, "Browser module PE header unavailable"
            timestamp = struct.unpack_from("<I", dos, pe_offset + 8)[0]
            size_of_image = struct.unpack_from("<I", dos, pe_offset + 24 + 56)[0]
            matched = PRIVATE_FLAG_BUILDS.get((timestamp, size_of_image))
            if not matched:
                return 0, (
                    f"Unsupported browser build PE timestamp={timestamp:#x}, "
                    f"SizeOfImage={size_of_image:#x}"
                )
            rva, build = matched
            return int(rva), f"Auto-resolved {build} private flag RVA {rva:#x}"
        except (exceptions.InvalidAddressException, IndexError, struct.error):
            return 0, "Browser module PE header page not resident"

    def _renderer_context_modes(
        self, processes: Sequence[object], flag_rva: int, module_name: str
    ) -> Dict[int, Tuple[str, str]]:
        """Maps renderer client IDs through RenderProcessHostImpl objects.

        This is an exact-build fallback for captures where the renderer's
        module data page is absent.  It identifies an actual
        OffTheRecordProfileImpl object and compares each render host's owning
        BrowserContext pointer with that object.
        """

        layout = PRIVATE_CONTEXT_OBJECT_BUILDS.get(int(flag_rva))
        if not layout:
            return {}
        kernel = self.context.modules[self.config["kernel"]]
        module_name = module_name.casefold()
        for proc in processes:
            try:
                args = cmdline.CmdLine.get_cmdline(
                    self.context, kernel.symbol_table_name, proc
                ) or ""
                # RenderProcessHostImpl lives in the main browser process.
                if "--type=" in args:
                    continue
                module_base = 0
                sections: List[Tuple[int, int]] = []
                for vad in proc.get_vad_root().traverse():
                    try:
                        mapped_name = vad.get_file_name()
                        if (mapped_name and
                                str(mapped_name).casefold().endswith(
                                    "\\" + module_name)):
                            module_base = int(vad.get_start())
                    except (AttributeError,
                            exceptions.InvalidAddressException):
                        pass
                    if bool(vad.get_private_memory()):
                        start, end = int(vad.get_start()), int(vad.get_end())
                        if end >= start:
                            sections.append((start, end - start + 1))
                if not module_base or not sections:
                    continue

                otr_va = module_base + int(layout["otr_profile_vftable_rva"])
                otr_objects: Set[int] = set()
                original_profiles: Set[int] = set()
                for offset in self.context.layers[
                        proc.add_process_layer()].scan(
                    self.context, scanners.BytesScanner(struct.pack("<Q", otr_va)),
                    sections=sections, progress_callback=self._progress_callback
                ):
                    try:
                        prefix = self.context.layers[
                            proc.add_process_layer()].read(
                                int(offset), 0x100, pad=False
                            )
                    except exceptions.InvalidAddressException:
                        continue
                    otr_objects.add(int(offset))
                    original_offset = int(
                        layout.get("otr_original_profile_offset", 0xF8)
                    )
                    original_profile = struct.unpack_from(
                        "<Q", prefix, original_offset
                    )[0]
                    if 0x10000 <= original_profile < 0x800000000000:
                        original_profiles.add(original_profile)
                if not otr_objects:
                    continue

                layer = self.context.layers[proc.add_process_layer()]
                rvas = layout["render_host_vftable_rvas"]
                needles = [
                    struct.pack("<Q", module_base + int(rva)) for rva in rvas
                ]
                modes: Dict[int, Tuple[str, str]] = {}
                client_offset = int(layout["render_host_client_id_offset"])
                context_offset = int(
                    layout["render_host_browser_context_offset"]
                )
                required = max(client_offset + 4, context_offset + 8)
                for offset, _needle in layer.scan(
                    self.context, scanners.MultiStringScanner(needles),
                    sections=sections, progress_callback=self._progress_callback
                ):
                    try:
                        data = layer.read(int(offset), required, pad=False)
                        client_id = struct.unpack_from(
                            "<I", data, client_offset
                        )[0]
                        browser_context = struct.unpack_from(
                            "<Q", data, context_offset
                        )[0]
                    except (exceptions.InvalidAddressException, struct.error):
                        continue
                    if not (0 < client_id < 0x100000):
                        continue
                    mode = self._classify_browser_context(
                        browser_context, otr_objects, original_profiles
                    )
                    modes[client_id] = (
                        mode,
                        f"RenderProcessHostImpl client={client_id} owns "
                        f"BrowserContext {browser_context:#x}; "
                        f"OTR profile object(s)="
                        + ",".join(f"{value:#x}" for value in otr_objects)
                        + "; original profile object(s)="
                        + ",".join(
                            f"{value:#x}" for value in original_profiles
                        )
                    )
                if modes:
                    return modes
            except (exceptions.InvalidAddressException, AttributeError,
                    TypeError):
                continue
        return {}

    def _navigation_controller_records(
        self,
        processes: Sequence[object],
        history_keys: Set[str],
        history_scanned: bool,
    ) -> Iterator[RecoveredURL]:
        """Recovers GURLs owned by exact-build NavigationControllers."""

        session_flags = getattr(self, "_session_private_flags", {})
        kernel = self.context.modules[self.config["kernel"]]
        seen: Set[Tuple[int, int, str]] = set()
        for proc in processes:
            try:
                args = cmdline.CmdLine.get_cmdline(
                    self.context, kernel.symbol_table_name, proc
                ) or ""
                if "--type=" in args:
                    continue
                process_name = utility.array_to_string(proc.ImageFileName)
                module_name, module_base = ChromiumHistory._find_browser_module(
                    self, proc, process_name
                )
                if not module_base:
                    continue
                explicit_rva = int(self.config.get("private_flag_rva", 0))
                family_key = (process_name.casefold(), module_name)
                flag_data = session_flags.get(family_key)
                effective_rva = explicit_rva or (
                    int(flag_data[0]) if flag_data else 0
                )
                if not effective_rva:
                    continue
                layout = PRIVATE_CONTEXT_OBJECT_BUILDS.get(effective_rva)
                required_keys = (
                    "navigation_controller_vftable_rva",
                    "navigation_entry_vftable_rva",
                    "navigation_controller_context_offset",
                    "navigation_controller_entries_offset",
                    "navigation_entry_virtual_url_offset",
                    "navigation_entry_frame_tree_offset",
                    "tree_node_frame_entry_offset",
                    "frame_navigation_url_offset",
                )
                if not layout or not all(key in layout for key in required_keys):
                    continue
                layer = self.context.layers[proc.add_process_layer()]
                sections = self._vad_sections(proc, private_only=True)
                if not sections:
                    continue

                otr_va = module_base + int(layout["otr_profile_vftable_rva"])
                otr_objects: Set[int] = set()
                original_profiles: Set[int] = set()
                for offset in layer.scan(
                    self.context,
                    scanners.BytesScanner(struct.pack("<Q", otr_va)),
                    sections=sections,
                    progress_callback=self._progress_callback,
                ):
                    try:
                        prefix = layer.read(int(offset), 0x100, pad=False)
                    except exceptions.InvalidAddressException:
                        continue
                    otr_objects.add(int(offset))
                    original_offset = int(
                        layout.get("otr_original_profile_offset", 0xF8)
                    )
                    original_profile = struct.unpack_from(
                        "<Q", prefix, original_offset
                    )[0]
                    if 0x10000 <= original_profile < 0x800000000000:
                        original_profiles.add(original_profile)
                if not otr_objects:
                    vollog.debug(
                        "PID %d: no exact-build OTR profile objects",
                        int(proc.UniqueProcessId),
                    )
                    continue

                vollog.debug(
                    "PID %d: recovered %d OTR profile object(s)",
                    int(proc.UniqueProcessId), len(otr_objects),
                )

                controller_va = module_base + int(
                    layout["navigation_controller_vftable_rva"]
                )
                entry_va = module_base + int(
                    layout["navigation_entry_vftable_rva"]
                )
                context_offset = int(
                    layout["navigation_controller_context_offset"]
                )
                entries_offset = int(
                    layout["navigation_controller_entries_offset"]
                )
                url_offset = int(layout["navigation_entry_virtual_url_offset"])
                controller_matches = 0
                for controller_offset in layer.scan(
                    self.context,
                    scanners.BytesScanner(struct.pack("<Q", controller_va)),
                    sections=sections,
                    progress_callback=self._progress_callback,
                ):
                    controller_matches += 1
                    try:
                        data = layer.read(int(controller_offset), 0x30, pad=False)
                        browser_context = struct.unpack_from(
                            "<Q", data, context_offset
                        )[0]
                        begin, end, capacity = struct.unpack_from(
                            "<QQQ", data, entries_offset
                        )
                    except (exceptions.InvalidAddressException, struct.error):
                        continue
                    browsing_mode = self._classify_browser_context(
                        browser_context, otr_objects, original_profiles
                    )
                    vollog.debug(
                        "PID %d controller=%#x context=%#x mode=%s "
                        "entries=%#x-%#x capacity=%#x",
                        int(proc.UniqueProcessId), int(controller_offset),
                        browser_context, browsing_mode, begin, end, capacity,
                    )
                    if browsing_mode == "Unknown":
                        continue
                    # Chromium's hardened libc++ ABI stores some vectors as
                    # {data pointer, size, capacity}; older builds use the
                    # conventional {begin, end, end_cap} layout.  Accept only
                    # a bounded, internally consistent instance of either.
                    if (end <= 512 and capacity <= 512 and end <= capacity):
                        count = int(end)
                    elif (begin <= end <= capacity and (end - begin) % 8 == 0
                          and end - begin <= 4096):
                        count = (end - begin) // 8
                    else:
                        continue
                    if begin < 0x10000 or count == 0:
                        continue
                    for index in range(count):
                        try:
                            entry_object = struct.unpack(
                                "<Q", layer.read(begin + index * 8, 8, pad=False)
                            )[0]
                            if not (0x10000 <= entry_object < 0x800000000000):
                                continue
                            vftable = struct.unpack(
                                "<Q", layer.read(entry_object, 8, pad=False)
                            )[0]
                            if vftable != entry_va:
                                continue
                            url = decode_libcpp_string(
                                layer, entry_object + url_offset,
                                int(self.config.get("max_url_length", 4096)),
                            )
                            url_address = entry_object + url_offset
                            # virtual_url_ is intentionally empty for many
                            # committed entries.  Follow the owning TreeNode
                            # to FrameNavigationEntry::url_ instead.
                            if not is_recoverable_url(url):
                                tree_offset = int(
                                    layout["navigation_entry_frame_tree_offset"]
                                )
                                node_entry_offset = int(
                                    layout["tree_node_frame_entry_offset"]
                                )
                                frame_url_offset = int(
                                    layout["frame_navigation_url_offset"]
                                )
                                frame_tree = struct.unpack(
                                    "<Q", layer.read(
                                        entry_object + tree_offset, 8, pad=False
                                    )
                                )[0]
                                frame_entry = struct.unpack(
                                    "<Q", layer.read(
                                        frame_tree + node_entry_offset, 8,
                                        pad=False,
                                    )
                                )[0]
                                url_address = frame_entry + frame_url_offset
                                url = decode_libcpp_string(
                                    layer, url_address,
                                    int(self.config.get("max_url_length", 4096)),
                                )
                        except (exceptions.InvalidAddressException, struct.error):
                            continue
                        if not is_recoverable_url(url):
                            continue
                        identity = (int(controller_offset), index, normalize_url(url))
                        if identity in seen:
                            continue
                        seen.add(identity)
                        engine, query = search_details(url)
                        artifact_class, canonical_activity = classify_artifact(
                            url, "NavigationEntry", "ConfirmedNavigationStructure"
                        )
                        if (not self.config.get("raw_url_strings", False)
                                and artifact_class in (
                                    "TemplateOrInternal",
                                    "BackgroundOrEmbedded",
                                )):
                            continue
                        yield RecoveredURL(
                            source="NavigationEntry",
                            confidence=(
                                "PDB-validated NavigationControllerImpl entries_ "
                                "and NavigationEntryImpl virtual_url_"
                            ),
                            pid=int(proc.UniqueProcessId),
                            process=process_name,
                            offset=url_address,
                            url=url,
                            search_engine=engine,
                            search_query=query,
                            candidate_score=200,
                            candidate_reasons=(
                                "navigation-controller;navigation-entry;"
                                "browser-context-identity"
                            ),
                            navigation_structure="NavigationEntryImpl",
                            navigation_index=index,
                            activity_role="ConfirmedNavigationStructure",
                            persistence_assessment=persistence_assessment(
                                url, history_keys, history_scanned
                            ),
                            browsing_mode=browsing_mode,
                            mode_evidence=(
                                f"NavigationControllerImpl {int(controller_offset):#x} "
                                f"owns BrowserContext {browser_context:#x}; "
                                f"OTR objects="
                                + ",".join(f"{value:#x}" for value in otr_objects)
                            ),
                            artifact_class=artifact_class,
                            canonical_activity=canonical_activity,
                        )
                vollog.debug(
                    "PID %d: scanned %d NavigationControllerImpl candidate(s)",
                    int(proc.UniqueProcessId), controller_matches,
                )
            except (exceptions.InvalidAddressException, AttributeError,
                    TypeError, struct.error):
                continue

    @staticmethod
    def _classify_browser_context(
        browser_context: int,
        otr_objects: Set[int],
        original_profiles: Set[int],
    ) -> str:
        """Classifies only identity-proven Chromium profile objects."""

        if browser_context in otr_objects:
            return "InPrivate"
        if browser_context in original_profiles:
            return "Regular"
        return "Unknown"

    def _renderer_host_mode(self, proc: object) -> Tuple[str, str]:
        modes = getattr(self, "_renderer_client_modes", {})
        if not modes:
            return "Unknown", "Renderer-host ownership map unavailable"
        try:
            kernel = self.context.modules[self.config["kernel"]]
            args = cmdline.CmdLine.get_cmdline(
                self.context, kernel.symbol_table_name, proc
            ) or ""
        except exceptions.InvalidAddressException:
            return "Unknown", "Renderer command line unavailable"
        match = re.search(r"--renderer-client-id=(\d+)", args)
        if not match:
            return "Unknown", "No renderer client ID"
        client_id = int(match.group(1))
        process_name = utility.array_to_string(proc.ImageFileName)
        module_name, _module_base = ChromiumHistory._find_browser_module(
            self,
            proc, process_name
        )
        return modes.get(
            (process_name.casefold(), module_name, client_id),
            ("Unknown", f"Renderer client {client_id} not recovered in browser host")
        )

    def _browser_module_candidates(self, process_name: str) -> Tuple[str, ...]:
        configured = str(self.config.get("browser_module", "auto")).strip().casefold()
        if configured and configured != "auto":
            return (configured,)
        preferred = BROWSER_MODULE_PREFERENCES.get(process_name.casefold(), ())
        remaining = tuple(
            name for name in sorted(CHROMIUM_MODULE_MARKERS)
            if name not in preferred and name != "chrome_elf.dll"
        )
        return tuple(preferred) + remaining

    def _find_browser_module(
        self, proc: object, process_name: str
    ) -> Tuple[str, int]:
        """Returns the browser-family code module and its mapped base."""

        candidates = ChromiumHistory._browser_module_candidates(
            self, process_name
        )
        mapped: Dict[str, int] = {}
        try:
            for vad in proc.get_vad_root().traverse():
                try:
                    mapped_name = vad.get_file_name()
                    if not mapped_name:
                        continue
                    leaf = str(mapped_name).replace("/", "\\").rsplit("\\", 1)[-1]
                    leaf = leaf.casefold()
                    if leaf in candidates and leaf not in mapped:
                        mapped[leaf] = int(vad.get_start())
                except (AttributeError, exceptions.InvalidAddressException):
                    continue
        except (AttributeError, exceptions.InvalidAddressException):
            return candidates[0] if candidates else "", 0
        for name in candidates:
            if name in mapped:
                return name, mapped[name]
        return candidates[0] if candidates else "", 0

    def _private_mode(self, proc: object) -> Tuple[str, str]:
        """Reads the exact-build renderer private-mode flag when configured."""

        flag_rva = int(self.config.get("private_flag_rva", 0))
        process_name = utility.array_to_string(proc.ImageFileName)
        module_name, module_base = ChromiumHistory._find_browser_module(
            self, proc, process_name
        )
        try:
            if not module_base:
                fallback = self._renderer_host_mode(proc)
                if fallback[0] != "Unknown":
                    return fallback
                return "Unknown", f"{module_name} mapping not recovered"
            layer = self.context.layers[proc.add_process_layer()]
            resolution = "Explicit private flag RVA"
            if not flag_rva:
                flag_rva, resolution = self._auto_private_flag_rva(
                    layer, module_base
                )
                # A renderer's image header is commonly paged out even while
                # its data page containing the flag remains resident.  All
                # browser processes in one capture use the same image build,
                # so reuse a build identity recovered from a sibling process.
                if not flag_rva:
                    session_flags = getattr(self, "_session_private_flags", {})
                    family_key = (process_name.casefold(), module_name)
                    session_value = session_flags.get(family_key)
                    if session_value:
                        flag_rva = int(session_value[0])
                        resolution = str(session_value[1])
                if not flag_rva:
                    fallback = self._renderer_host_mode(proc)
                    if fallback[0] != "Unknown":
                        return fallback
                    return "Unknown", resolution
            try:
                value = int(layer.read(
                    module_base + flag_rva, 1, pad=False
                )[0])
            except exceptions.InvalidAddressException:
                fallback = self._renderer_host_mode(proc)
                if fallback[0] != "Unknown":
                    return fallback
                return "Unknown", "Private-mode flag page not resident"
            if value == 1:
                return "InPrivate", (
                    f"{resolution}; ChromeRenderThreadObserver flag=1 at "
                    f"{module_base + flag_rva:#x}"
                )
            if value != 0:
                return "Unknown", f"Invalid private-mode flag value {value}"
            try:
                kernel = self.context.modules[self.config["kernel"]]
                args = cmdline.CmdLine.get_cmdline(
                    self.context, kernel.symbol_table_name, proc
                ) or ""
            except exceptions.InvalidAddressException:
                args = ""
            if "--type=renderer" in args:
                return "Regular", (
                    f"{resolution}; ChromeRenderThreadObserver flag=0 at "
                    f"{module_base + flag_rva:#x}"
                )
            return "MixedOrNotApplicable", (
                "Flag=0 in non-renderer process; browser may host both profiles"
            )
        except exceptions.InvalidAddressException:
            fallback = self._renderer_host_mode(proc)
            if fallback[0] != "Unknown":
                return fallback
            return "Unknown", "Private-mode flag page not resident"

    @staticmethod
    def _is_chromium_process(proc: object, process_name: str) -> bool:
        """Identifies Chromium/CEF processes by executable or loaded module."""

        if process_name.casefold() in KNOWN_CHROMIUM_PROCESSES:
            return True
        try:
            for module in proc.load_order_modules():
                try:
                    module_name = module.BaseDllName.get_string().casefold()
                except exceptions.InvalidAddressException:
                    continue
                if module_name in CHROMIUM_MODULE_MARKERS:
                    return True
        except exceptions.InvalidAddressException:
            return False
        return False

    @staticmethod
    def _vad_sections(
        proc: object, private_only: bool = False
    ) -> List[Tuple[int, int]]:
        sections = []
        for vad in proc.get_vad_root().traverse():
            try:
                start, end = int(vad.get_start()), int(vad.get_end())
            except (AttributeError, exceptions.InvalidAddressException):
                continue
            if private_only:
                try:
                    is_private = bool(vad.get_private_memory())
                except (AttributeError, exceptions.InvalidAddressException):
                    is_private = False
                if not is_private:
                    continue
            if end >= start:
                sections.append((start, end - start + 1))
        return sections

    @staticmethod
    def _containing_section(
        offset: int, sections: Sequence[Tuple[int, int]]
    ) -> Optional[Tuple[int, int]]:
        for start, size in sections:
            if start <= offset < start + size:
                return start, size
        return None

    def _memory_records(
        self, history_keys: Set[str], history_scanned: bool = False
    ) -> Iterator[RecoveredURL]:
        max_length = max(128, int(self.config.get("max_url_length", 4096)))
        maximum = max(1, int(self.config.get("max_results", 10000)))
        seen: Set[Tuple[int, str]] = set()
        emitted = 0
        structured = self.config.get("navigation_structures", False)
        processes = list(self._selected_processes())

        # Resolve each browser family's build independently.  An Edge RVA must
        # never be reused for Chrome (or another Chromium browser) merely
        # because both families coexist in the same capture.
        if not int(self.config.get("private_flag_rva", 0)):
            self._session_private_flags: Dict[
                Tuple[str, str], Tuple[int, str]
            ] = {}
            for candidate in processes:
                try:
                    process_name = utility.array_to_string(
                        candidate.ImageFileName
                    )
                    module_name, candidate_base = ChromiumHistory._find_browser_module(
                        self, candidate, process_name
                    )
                    if not candidate_base:
                        continue
                    family_key = (process_name.casefold(), module_name)
                    if family_key in self._session_private_flags:
                        continue
                    candidate_layer = self.context.layers[
                        candidate.add_process_layer()
                    ]
                    resolved_rva, resolved_evidence = (
                        self._auto_private_flag_rva(
                            candidate_layer, candidate_base
                        )
                    )
                    if resolved_rva:
                        self._session_private_flags[family_key] = (
                            resolved_rva,
                            resolved_evidence
                            + f"; reused across {module_name} session",
                        )
                except exceptions.InvalidAddressException:
                    continue

        context_mode_reader = getattr(self, "_renderer_context_modes", None)
        self._renderer_client_modes: Dict[
            Tuple[str, str, int], Tuple[str, str]
        ] = {}
        explicit_rva = int(self.config.get("private_flag_rva", 0))
        session_flags = getattr(self, "_session_private_flags", {})
        if callable(context_mode_reader):
            module_groups: Dict[Tuple[str, str], List[object]] = {}
            for candidate in processes:
                process_name = utility.array_to_string(candidate.ImageFileName)
                module_name, _base = ChromiumHistory._find_browser_module(
                    self, candidate, process_name
                )
                family_key = (process_name.casefold(), module_name)
                module_groups.setdefault(family_key, []).append(candidate)
            for family_key, grouped_processes in module_groups.items():
                process_family, module_name = family_key
                effective_rva = explicit_rva
                if not effective_rva and family_key in session_flags:
                    effective_rva = int(session_flags[family_key][0])
                if not effective_rva:
                    continue
                recovered = context_mode_reader(
                    grouped_processes, effective_rva, module_name
                )
                for client_id, value in recovered.items():
                    self._renderer_client_modes[
                        (process_family, module_name, client_id)
                    ] = value

        navigation_reader = getattr(
            self, "_navigation_controller_records", None
        )
        navigation_records = (
            navigation_reader(processes, history_keys, history_scanned)
            if callable(navigation_reader) else ()
        )
        for record in navigation_records:
            identity_pid = (
                record.pid if self.config.get("raw_url_strings", False) else 0
            )
            normalized = record.canonical_activity or normalize_url(record.url)
            identity = (identity_pid, normalized)
            if identity in seen:
                continue
            seen.add(identity)
            yield record
            emitted += 1
            if emitted >= maximum:
                return

        for proc in processes:
            pid = int(proc.UniqueProcessId)
            process_name = utility.array_to_string(proc.ImageFileName)
            private_mode_reader = getattr(self, "_private_mode", None)
            if callable(private_mode_reader):
                browsing_mode, mode_evidence = private_mode_reader(proc)
            else:
                browsing_mode, mode_evidence = (
                    "Unknown", "Private-mode reader unavailable"
                )
            try:
                layer = self.context.layers[proc.add_process_layer()]
                sections = self._vad_sections(
                    proc,
                    private_only=(self.config.get("navigation_candidates", False)
                                  or structured
                                  or bool(self.config.get(
                                      "private_flag_rva", 0))),
                )
                scanner = scanners.MultiStringScanner(MEMORY_NEEDLES)
                for offset, pattern in layer.scan(
                    self.context, scanner,
                    progress_callback=self._progress_callback, sections=sections
                ):
                    section = self._containing_section(offset, sections)
                    if section is None:
                        continue
                    section_start, section_size = section
                    wide = b"\x00" in pattern
                    if structured and wide:
                        continue
                    prefix = 8 if structured else 0
                    read_start = max(section_start, offset - prefix)
                    relative_offset = offset - read_start
                    available = section_start + section_size - read_start
                    requested = (relative_offset + max_length + 69648
                                 if structured else max_length * (2 if wide else 1))
                    read_size = min(available, requested)
                    if read_size <= len(pattern):
                        continue
                    try:
                        data = layer.read(read_start, read_size, pad=True)
                    except exceptions.InvalidAddressException:
                        continue
                    navigation = (parse_serialized_navigation(data, relative_offset)
                                  if structured else None)
                    if structured and navigation is None:
                        continue
                    url = (navigation.url if navigation else
                           extract_memory_url(data[relative_offset:], wide, max_length))
                    if not url:
                        continue
                    if (self.config.get("recover_closed", False)
                            and not is_recoverable_url(url)):
                        continue
                    engine, query = search_details(url)
                    if self.config.get("recover_searches", False) and not query:
                        continue
                    terms = [item.strip() for item in
                             self.config.get("search_terms", "").split(",")
                             if item.strip()]
                    if terms and not matches_search_terms(url, terms):
                        continue
                    filters = [item.strip().casefold() for item in
                               self.config.get("url_filter", "").split(",")
                               if item.strip()]
                    if filters and not any(item in url.casefold() for item in filters):
                        continue
                    source, confidence = classify_memory_source(url, history_keys)
                    if navigation:
                        source = "SerializedNavigation"
                        confidence = "Validated SerializedNavigationEntry structure"
                    if (self.config.get("skip_history", False)
                            or self.config.get("recover_closed", False)
                            or self.config.get("recover_searches", False)
                            or terms):
                        if not navigation:
                            source = "ProcessURLString"
                            confidence = "URL string only; visit/private mode not established"
                    score, reasons = navigation_score(url, source)
                    if structured and score < 100:
                        continue
                    if (self.config.get("navigation_candidates", False)
                            and score < int(self.config.get("min_candidate_score", 70))):
                        continue
                    if (self.config.get("memory_only", False)
                            and source not in ("MemoryOnly", "ProcessURLString")):
                        continue
                    role, _role_reason = classify_activity_role(
                        url, data, source
                    )
                    artifact_class, canonical_activity = classify_artifact(
                        url, source, role
                    )
                    if (not self.config.get("raw_url_strings", False)
                            and artifact_class in (
                                "TemplateOrInternal", "BackgroundOrEmbedded"
                            )):
                        continue
                    if (artifact_class == "StaleOrUnattributed"
                            and not self.config.get("raw_url_strings", False)
                            and not self.config.get(
                                "include_unattributed", False)):
                        continue
                    normalized = (("" if self.config.get(
                                      "raw_url_strings", False)
                                   else canonical_activity) or
                                  (search_identity(url) if terms
                                   else normalize_url(url)))
                    # The same OTR navigation can survive in more than one
                    # renderer after tabs are closed/reused.  Default output
                    # represents the activity once across identity-proven
                    # InPrivate renderers; raw mode retains per-PID copies.
                    identity_pid = (
                        pid if self.config.get("raw_url_strings", False) else 0
                    )
                    identity = (identity_pid, normalized)
                    if identity in seen:
                        continue
                    if (artifact_class == "SearchActivity"
                            and any(
                                prior_pid == identity_pid
                                and prior_key.startswith(normalized)
                                and len(prior_key) > len(normalized)
                                for prior_pid, prior_key in seen
                            )):
                        continue
                    if (self.config.get("top_level_only", False)
                            and role not in (
                                "PersistedNavigation",
                                "ConfirmedNavigationStructure",
                                "ProbableTopLevelNavigation",
                            )):
                        continue
                    seen.add(identity)
                    yield RecoveredURL(
                        source=source, confidence=confidence, pid=pid,
                        process=process_name, offset=int(offset), url=url,
                        search_engine=engine, search_query=query,
                        candidate_score=score, candidate_reasons=reasons,
                        title=navigation.title if navigation else "",
                        navigation_structure=("SerializedNavigationEntry"
                                              if navigation else ""),
                        navigation_index=navigation.index if navigation else -1,
                        transition_type=(navigation.transition_type
                                         if navigation else -1),
                        activity_role=role,
                        persistence_assessment=persistence_assessment(
                            url, history_keys, history_scanned),
                        browsing_mode=browsing_mode,
                        mode_evidence=mode_evidence,
                        artifact_class=artifact_class,
                        canonical_activity=canonical_activity)
                    emitted += 1
                    if emitted >= maximum:
                        return
            except exceptions.InvalidAddressException as exc:
                vollog.debug("Unable to scan PID %d: %s", pid, exc)

    def _physical_records(
        self, history_keys: Set[str], history_scanned: bool = False
    ) -> Iterator[RecoveredURL]:
        """Carves URL strings from the base layer after browser termination."""

        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]
        memory_layer_name = kernel_layer.config.get("memory_layer", None)
        if not memory_layer_name or memory_layer_name not in self.context.layers:
            vollog.warning("Unable to locate the base physical-memory layer")
            return

        layer = self.context.layers[memory_layer_name]
        max_length = max(128, int(self.config.get("max_url_length", 4096)))
        maximum = max(1, int(self.config.get("max_results", 10000)))
        scanner = scanners.MultiStringScanner(MEMORY_NEEDLES)
        seen: Set[str] = set()
        emitted = 0

        for offset, pattern in layer.scan(
            self.context, scanner, progress_callback=self._progress_callback
        ):
            wide = b"\x00" in pattern
            context_mode = self.config.get("physical_browser_context", False)
            lookbehind = 2048 if context_mode else 0
            read_start = max(0, int(offset) - lookbehind)
            relative_offset = int(offset) - read_start
            read_size = (relative_offset + max_length * (2 if wide else 1)
                         + (2048 if context_mode else 0))
            read_size = min(
                read_size, int(layer.maximum_address) + 1 - read_start
            )
            if read_size <= len(pattern):
                continue
            try:
                data = layer.read(read_start, read_size, pad=True)
            except exceptions.InvalidAddressException:
                continue
            url = extract_memory_url(data[relative_offset:], wide, max_length)
            if not url:
                continue
            if context_mode:
                url = clean_network_record_url(url)
                if not is_recoverable_url(url):
                    continue
            if (self.config.get("recover_closed", False)
                    and not is_recoverable_url(url)):
                continue
            engine, query = search_details(url)
            if self.config.get("recover_searches", False) and not query:
                continue
            terms = [item.strip() for item in
                     self.config.get("search_terms", "").split(",")
                     if item.strip()]
            if terms and not matches_search_terms(url, terms):
                continue
            filters = [item.strip().casefold() for item in
                       self.config.get("url_filter", "").split(",")
                       if item.strip()]
            if filters and not any(item in url.casefold() for item in filters):
                continue
            source, confidence = classify_physical_source(url, history_keys)
            if (self.config.get("skip_history", False)
                    or self.config.get("recover_closed", False)
                    or self.config.get("recover_searches", False)
                    or terms):
                source = "PhysicalURLString"
                confidence = "URL string only; origin/visit/private mode not established"
            score, reasons = navigation_score(url, source)
            if context_mode:
                context_score, context_reasons = physical_browser_context(
                    data, relative_offset, url
                )
                if context_score < 60:
                    continue
                source = "PhysicalBrowserContext"
                confidence = (
                    "Adjacent browser/network artifacts; probable browser "
                    "activity, private mode not established"
                )
                score = context_score
                reasons = context_reasons
            if (self.config.get("navigation_candidates", False)
                    and score < int(self.config.get("min_candidate_score", 70))):
                continue
            if (
                self.config.get("memory_only", False)
                and source not in (
                    "PhysicalMemoryOnly", "PhysicalURLString",
                    "PhysicalBrowserContext",
                )
            ):
                continue
            role, _role_reason = classify_activity_role(url, data, source)
            artifact_class, canonical_activity = classify_artifact(
                url, source, role
            )
            if (not self.config.get("raw_url_strings", False)
                    and artifact_class in (
                        "TemplateOrInternal", "BackgroundOrEmbedded"
                    )):
                continue
            if (artifact_class == "StaleOrUnattributed"
                    and not self.config.get("raw_url_strings", False)
                    and not self.config.get("include_unattributed", False)):
                continue
            normalized = (("" if self.config.get("raw_url_strings", False)
                           else canonical_activity) or
                          (search_identity(url) if terms
                           else normalize_url(url)))
            if normalized in seen:
                continue
            if (self.config.get("top_level_only", False)
                    and role != "ProbableTopLevelNavigation"):
                continue
            seen.add(normalized)
            yield RecoveredURL(
                source,
                confidence,
                -1,
                "PhysicalMemory",
                int(offset),
                url,
                engine,
                query,
                score,
                reasons,
                activity_role=role,
                persistence_assessment=persistence_assessment(
                    url, history_keys, history_scanned),
                artifact_class=artifact_class,
                canonical_activity=canonical_activity,
            )
            emitted += 1
            if emitted >= maximum:
                return

    @staticmethod
    def _row(record: RecoveredURL):
        host, path, raw_query = url_components(record.url)
        score, reasons = (record.candidate_score, record.candidate_reasons)
        if not reasons:
            score, reasons = navigation_score(record.url, record.source)
        return 0, (
            record.source, record.confidence, record.pid, record.process,
            format_hints.Hex(record.offset), record.url,
            host, path, raw_query, record.search_engine, record.search_query,
            evidence_class(record.source), score, reasons,
            record.navigation_structure, record.navigation_index,
            record.transition_type, record.activity_role,
            record.persistence_assessment, record.browsing_mode,
            record.mode_evidence, record.artifact_class,
            record.canonical_activity, record.title,
            record.visit_count, record.typed_count, record.last_visit_time,
            utc_to_kst(record.last_visit_time))

    @staticmethod
    def _compact_row(record: RecoveredURL):
        """Returns a terminal-friendly summary without discarding full output."""
        host, _path, _raw_query = url_components(record.url)
        activity = record.search_query or record.title or record.url
        activity = " ".join(activity.split())
        if len(activity) > 96:
            activity = activity[:93] + "..."
        return 0, (
            record.source,
            record.pid,
            record.process,
            record.browsing_mode,
            activity,
            host,
            record.visit_count,
            utc_to_kst(record.last_visit_time),
            record.persistence_assessment,
        )

    def _output_row(self, record: RecoveredURL):
        if self.config.get("full_output", False):
            return self._row(record)
        return self._compact_row(record)

    def _generator(self):
        history: Dict[str, RecoveredURL] = {}
        reported_activities: Set[str] = set()
        raw_output = self.config.get("raw_url_strings", False)
        targeted_search = bool(self.config.get("search_terms", "").strip())
        recover_searches = self.config.get("recover_searches", False)
        recover_closed = self.config.get("recover_closed", False)
        navigation_candidates = self.config.get("navigation_candidates", False)
        navigation_structures = self.config.get("navigation_structures", False)
        history_scanned = (
            not self.config.get("skip_history", False)
            and (self.config.get("compare_history", False)
                 or not (
                     targeted_search or recover_searches or recover_closed
                     or self.config.get("recover_sessions", False)
                 ))
        )
        if history_scanned:
            for record in self._history_records():
                history.setdefault(normalize_url(record.url), record)
        search_terms = [
            item.strip() for item in self.config.get("search_terms", "").split(",")
            if item.strip()
        ]
        url_filters = [
            item.strip().casefold()
            for item in self.config.get("url_filter", "").split(",")
            if item.strip()
        ]
        if not self.config.get("memory_only", False):
            for record in history.values():
                if search_terms and not matches_search_terms(
                    record.url, search_terms
                ):
                    continue
                if url_filters and not any(
                    item in record.url.casefold() for item in url_filters
                ):
                    continue
                if not raw_output:
                    reported_activities.add(recovered_activity_identity(record))
                yield self._output_row(record)
        if self.config.get("history_only", False):
            return
        focused_session_recovery = session_recovery_is_exclusive(self.config)
        if self.config.get("recover_sessions", False):
            for record in self._session_records():
                if search_terms and not matches_search_terms(
                    record.url, search_terms
                ):
                    continue
                if url_filters and not any(
                    item in record.url.casefold() for item in url_filters
                ):
                    continue
                identity = recovered_activity_identity(record)
                if not raw_output and identity in reported_activities:
                    continue
                if not raw_output:
                    reported_activities.add(identity)
                yield self._output_row(record)
        process_count = 0
        if not self.config.get("physical_only", False):
            for record in self._memory_records(set(history), history_scanned):
                process_count += 1
                # A focused session run also preserves URLs owned by a
                # structurally proven private renderer.  Unknown/Regular VAD
                # strings remain suppressed so the old hundreds-of-candidates
                # noise does not return.
                if (focused_session_recovery
                        and record.browsing_mode != "InPrivate"):
                    continue
                identity = recovered_activity_identity(record)
                if not raw_output and identity in reported_activities:
                    continue
                if not raw_output:
                    reported_activities.add(identity)
                yield self._output_row(record)
        if focused_session_recovery:
            # Physical strings have no owning renderer/BrowserContext and
            # therefore cannot meet the structural InPrivate requirement.
            return
        use_fallback = (
            self.config.get("physical_fallback", True) and process_count == 0
        )
        if self.config.get("process_only", False):
            return
        if navigation_structures:
            return
        targeted_physical = (targeted_search or recover_searches or recover_closed
                             or self.config.get("physical_only", False)
                             or self.config.get("physical_browser_context", False)
                             or bool(
            self.config.get("url_filter", "").strip()
        ))
        if use_fallback or self.config.get("scan_physical", False) or targeted_physical:
            for record in self._physical_records(set(history), history_scanned):
                identity = recovered_activity_identity(record)
                if not raw_output and identity in reported_activities:
                    continue
                if not raw_output:
                    reported_activities.add(identity)
                yield self._output_row(record)

    def run(self):
        if not self.config.get("full_output", False):
            return renderers.TreeGrid(
                [("Source", str), ("PID", int), ("Process", str),
                 ("Mode", str), ("Activity", str), ("Host", str),
                 ("Visits", int), ("LastVisitKST", str),
                 ("Persistence", str)],
                self._generator())
        return renderers.TreeGrid(
            [("Source", str), ("Confidence", str), ("PID", int),
             ("Process", str), ("Offset", format_hints.Hex), ("URL", str),
             ("Host", str), ("Path", str), ("RawQuery", str),
             ("SearchEngine", str), ("SearchQuery", str),
             ("EvidenceClass", str), ("CandidateScore", int),
             ("CandidateReasons", str), ("NavigationStructure", str),
             ("NavigationIndex", int), ("TransitionType", int),
             ("ActivityRole", str), ("PersistenceAssessment", str),
             ("BrowsingMode", str), ("ModeEvidence", str),
             ("ArtifactClass", str), ("CanonicalActivity", str),
             ("Title", str),
             ("VisitCount", int), ("TypedCount", int),
             ("LastVisitUTC", str), ("LastVisitKST", str)], self._generator())
