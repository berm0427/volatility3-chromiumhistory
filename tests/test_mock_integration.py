import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock


PLUGIN = pathlib.Path(__file__).parent.parent / "plugins" / "chromiumhistory.py"
SPEC = importlib.util.spec_from_file_location(
    "volatility3.plugins.chromiumhistory", PLUGIN
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class FakeLayer:
    def __init__(self, base, data, hits):
        self.base = base
        self.data = data
        self.hits = hits
        self.minimum_address = base
        self.maximum_address = base + len(data) - 1

    def scan(self, _context, _scanner, progress_callback=None, sections=None):
        yield from self.hits

    def read(self, address, size, pad=False):
        start = address - self.base
        return self.data[start : start + size].ljust(size, b"\x00")


class FakeVad:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end


class FakeVadRoot:
    def __init__(self, vad):
        self.vad = vad

    def traverse(self):
        yield self.vad


class FakeProc:
    UniqueProcessId = 4242
    ImageFileName = "msedge.exe"

    def __init__(self, vad):
        self.vad = vad

    def add_process_layer(self):
        return "edge_layer"

    def get_vad_root(self):
        return FakeVadRoot(self.vad)


class ChromiumMockIntegrationTests(unittest.TestCase):
    def test_ascii_and_utf16_urls_flow_through_memory_records(self):
        base = 0x1000
        ascii_url = b"https://private.example/one\x00"
        wide_text = "https://edge.example/inprivate"
        wide_url = (wide_text + "\x00").encode("utf-16le")
        data = bytearray(b"\x00" * 0x1000)
        data[0x100 : 0x100 + len(ascii_url)] = ascii_url
        data[0x300 : 0x300 + len(wide_url)] = wide_url
        layer = FakeLayer(
            base,
            bytes(data),
            [
                (base + 0x100, b"https://"),
                (base + 0x300, "https://".encode("utf-16le")),
            ],
        )
        proc = FakeProc(FakeVad(base, base + len(data) - 1))
        fake = types.SimpleNamespace(
            config={
                "max_url_length": 512,
                "max_results": 100,
                "include_unattributed": True,
            },
            context=types.SimpleNamespace(layers={"edge_layer": layer}),
            _progress_callback=None,
            _selected_processes=lambda: [proc],
            _vad_sections=MODULE.ChromiumHistory._vad_sections,
            _containing_section=MODULE.ChromiumHistory._containing_section,
        )
        with mock.patch.object(MODULE.utility, "array_to_string", lambda x: str(x)):
            records = list(MODULE.ChromiumHistory._memory_records(fake, set()))

        self.assertEqual({record.source for record in records}, {"MemoryOnly"})
        self.assertEqual({record.process for record in records}, {"msedge.exe"})
        self.assertEqual(
            {record.url for record in records},
            {"https://private.example/one", wide_text},
        )

    def test_regular_process_url_is_not_discarded(self):
        base = 0x4000
        url = b"https://regular.example/visited\x00"
        data = bytearray(b"\x00" * 0x1000)
        data[0x180 : 0x180 + len(url)] = url
        layer = FakeLayer(base, bytes(data), [(base + 0x180, b"https://")])
        proc = FakeProc(FakeVad(base, base + len(data) - 1))
        fake = types.SimpleNamespace(
            config={
                "max_url_length": 512,
                "max_results": 100,
                "include_unattributed": True,
            },
            context=types.SimpleNamespace(layers={"edge_layer": layer}),
            _progress_callback=None,
            _selected_processes=lambda: [proc],
            _vad_sections=MODULE.ChromiumHistory._vad_sections,
            _containing_section=MODULE.ChromiumHistory._containing_section,
            _private_mode=lambda _proc: (
                "Regular", "Mock regular renderer context"
            ),
        )
        with mock.patch.object(MODULE.utility, "array_to_string", lambda x: str(x)):
            records = list(MODULE.ChromiumHistory._memory_records(fake, set()))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].url, "https://regular.example/visited")
        self.assertEqual(records[0].browsing_mode, "Regular")

    def test_closed_session_url_flows_through_physical_fallback(self):
        url = b"https://www.bing.com/search?q=pear\x00"
        data = bytearray(b"\x00" * 0x1000)
        data[0x200 : 0x200 + len(url)] = url
        physical = FakeLayer(0, bytes(data), [(0x200, b"https://")])
        kernel_layer = types.SimpleNamespace(config={"memory_layer": "physical"})
        context = types.SimpleNamespace(
            modules={"kernel": types.SimpleNamespace(layer_name="kernel_layer")},
            layers={"kernel_layer": kernel_layer, "physical": physical},
        )
        fake = types.SimpleNamespace(
            config={
                "kernel": "kernel",
                "max_url_length": 512,
                "max_results": 100,
                "memory_only": True,
            },
            context=context,
            _progress_callback=None,
        )
        records = list(MODULE.ChromiumHistory._physical_records(fake, set()))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source, "PhysicalMemoryOnly")
        self.assertEqual(records[0].pid, -1)
        self.assertEqual(records[0].url, "https://www.bing.com/search?q=pear")


if __name__ == "__main__":
    unittest.main(verbosity=2)
