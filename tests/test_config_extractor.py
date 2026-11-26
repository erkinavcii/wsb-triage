"""config_extractor.py: carving programs out of memory dumps so CAPE parsers (pefile at offset 0) can read them.
Runs without the CAPE environment: parsers and rules are faked, pefile comes from the main environment."""
import glob
import os
from types import SimpleNamespace

import pytest

import config_extractor as ce
from conftest import windows_only

pefile = pytest.importorskip("pefile")


def _pe_with_different_alignments():
    """A real Windows program whose file layout differs from its loaded layout (FileAlignment 0x200)."""
    for src in sorted(glob.glob(r"C:\Windows\System32\*.exe"))[:400]:
        try:
            raw = open(src, "rb").read()
            pe = pefile.PE(data=raw, fast_load=True)
        except Exception:
            continue
        text = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
        if (len(raw) < 2_000_000 and text and text.PointerToRawData != text.VirtualAddress
                and pe.OPTIONAL_HEADER.FileAlignment != pe.OPTIONAL_HEADER.SectionAlignment):
            return raw, pe, text.get_data()[:4096]
    pytest.skip("no suitable system program")


@windows_only
def test_carve_finds_loaded_and_file_layout_programs_in_a_dump():
    raw, pe, want = _pe_with_different_alignments()
    mapped = pe.get_memory_mapped_image()
    dump = os.urandom(5000) + mapped + os.urandom(3000) + raw + os.urandom(1000)
    got = {(o, lay): b for o, lay, b in ce.carve_pes(dump)}
    assert (5000, "mapped") in got and (5000 + len(mapped) + 3000, "file") in got

    def text_of(buf):
        p = pefile.PE(data=buf)
        return next(s for s in p.sections if s.Name.rstrip(b"\x00") == b".text").get_data()[:4096]
    assert text_of(got[(5000, "mapped")]) == want                    # loaded image, unmapped
    assert text_of(got[(5000 + len(mapped) + 3000, "file")]) == want  # file copy, as is
    assert text_of(got[(5000, "file")]) != want                       # the wrong treatment would not read


@windows_only
def test_analyze_dump_gives_parsers_a_buffer_that_starts_with_mz():
    raw, pe, _ = _pe_with_different_alignments()
    dump = os.urandom(4096) + pe.get_memory_mapped_image()
    seen = []

    def extract_config(data):
        seen.append(data[:2])
        pefile.PE(data=data)                    # what most CAPE parsers do first
        return {"C2": ["c2.example:443"]}
    parsers = {"lumma": ("Lumma", SimpleNamespace(extract_config=extract_config))}
    rules = SimpleNamespace(match=lambda data, timeout=60: [SimpleNamespace(rule="Lumma", meta={"cape_type": "Lumma Payload"})])
    out = ce.analyze_dump(dump, rules, parsers)
    assert out["families"] == ["Lumma"] and out["carved"] >= 1
    assert out["configs"]["Lumma"] == {"C2": ["c2.example:443"]}
    assert seen and all(s == b"MZ" for s in seen)
    assert out["config_from"]["Lumma"].startswith("0x1000")
