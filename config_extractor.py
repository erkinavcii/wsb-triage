"""Malware family detection + configuration (C2) extraction with the CAPE sandbox parsers.

Runs in its own Python 3.12+ environment (CAPE-parsers needs it; the panel runs on 3.11) and as a separate
process, because it reads suspicious files with third-party parsers. Started by pipeline.run_config_extractor:

    <extractor-venv>/python.exe -I config_extractor.py   < request.json   > result.json

request: {"rules_dir": "...", "files": [{"label": "...", "path": "...", "xor_key": "<hex>"?}], "max_bytes": N}
  xor_key: the file is a SafeBox memory dump (XOR-encoded); decoded here, in memory only.
result:  {"ok": true, "parsers": N, "rules": N, "results": [{"label", "families", "rules", "configs", "errors"}]}

The family YARA rules come from CAPEv2 (data/yara/CAPE, GPLv3) and live outside this repository, next to the
environment (see futures.md / fable.md). This file only uses them.
"""
import glob
import importlib
import json
import os
import re
import sys

GENERIC_RULE_TYPES = {"obfuscar", "pafish"}      # tools, not malware families: .NET obfuscator, anti-VM test tool
MAX_STR = 300
MAX_ITEMS = 50


def _xor_decode(data: bytes, key: bytes) -> bytes:
    if not data or not key:
        return data
    stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


MAX_CARVED = 40
MAX_CARVED_SIZE = 32 * 1024 * 1024


def carve_pes(data: bytes):
    """Programs (PE images) inside a memory dump, each as a buffer that starts with its own MZ header.

    A SafeBox dump is the process's private + executable regions written one after another, so an unpacked or
    injected payload sits somewhere in the middle. Most CAPE parsers open the buffer with pefile.PE(data=...),
    which needs the header at offset 0 and reads sections at PointerToRawData. A payload can be in two layouts:
      - "mapped": loaded by a loader, sections at their RVA. Cut SizeOfImage bytes and rewrite the section table
        to PointerToRawData = VirtualAddress, SizeOfRawData = VirtualSize (the usual "unmap" of a memory image);
      - "file": a copy of the file still in memory (e.g. an embedded resource). Cut up to the last raw section.
    Both are offered; a parser keeps whichever it can read. Yields (offset, layout, buffer)."""
    import struct
    pos, n = 0, 0
    while n < MAX_CARVED:
        i = data.find(b"MZ", pos)
        if i < 0 or i + 0x40 > len(data):
            return
        pos = i + 2
        e_lfanew = struct.unpack_from("<I", data, i + 0x3C)[0]
        pe = i + e_lfanew
        if not (0x40 <= e_lfanew <= 0x1000) or pe + 0x18 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
            continue
        n_sections = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 0x14)[0]
        opt = pe + 0x18
        if not (1 <= n_sections <= 96) or opt + opt_size > len(data):
            continue
        if struct.unpack_from("<H", data, opt)[0] not in (0x10B, 0x20B):
            continue
        size_of_image = struct.unpack_from("<I", data, opt + 0x38)[0]
        sec = opt + opt_size
        if not (0x200 <= size_of_image <= MAX_CARVED_SIZE) or sec + n_sections * 40 > len(data):
            continue
        headers = [struct.unpack_from("<IIII", data, sec + k * 40 + 8) for k in range(n_sections)]  # vsize, va, rawsize, rawptr
        n += 1
        mapped = bytearray(data[i:i + size_of_image])
        rel = sec - i
        for k, (vsize, va, _rs, _rp) in enumerate(headers):
            if rel + k * 40 + 24 <= len(mapped):
                struct.pack_into("<II", mapped, rel + k * 40 + 16, vsize, va)   # SizeOfRawData, PointerToRawData
        yield i, "mapped", bytes(mapped)
        raw_end = max((rp + rs for _vs, _va, rs, rp in headers if rp and rs), default=0)
        if 0x200 <= raw_end <= MAX_CARVED_SIZE:
            yield i, "file", data[i:i + raw_end]


def _family_from_type(cape_type: str) -> str:
    """'AgentTesla Payload' -> 'AgentTesla'; CAPE names parsers this way (spaces -> underscores)."""
    t = re.sub(r"\s+(payload|config|loader)$", "", (cape_type or "").strip(), flags=re.I)
    return t.replace(" ", "_")


def _jsonable(v, depth=0):
    """Configs hold bytes, sets, nested dicts: make them small, plain JSON."""
    if depth > 4:
        return str(v)[:MAX_STR]
    if isinstance(v, (bytes, bytearray)):
        try:
            s = bytes(v).decode("utf-8")
            return s[:MAX_STR] if s.isprintable() else bytes(v)[:64].hex()
        except UnicodeDecodeError:
            return bytes(v)[:64].hex()
    if isinstance(v, dict):
        return {str(k)[:80]: _jsonable(x, depth + 1) for k, x in list(v.items())[:MAX_ITEMS]}
    if isinstance(v, (list, tuple, set)):
        return [_jsonable(x, depth + 1) for x in list(v)[:MAX_ITEMS]]
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    return str(v)[:MAX_STR]


def _load_parsers():
    import cape_parsers  # noqa: F401  (imported here: the module must load without the package for tests)
    root = os.path.join(os.path.dirname(cape_parsers.__file__), "CAPE")
    parsers = {}
    for sub in ("core", "community"):
        for f in glob.glob(os.path.join(root, sub, "[!_]*.py")):
            name = os.path.basename(f)[:-3]
            if name == "test_cape":
                continue
            try:
                mod = importlib.import_module(f"cape_parsers.CAPE.{sub}.{name}")
            except Exception:   # noqa: BLE001 - one broken parser must not stop the others
                continue
            if hasattr(mod, "extract_config"):
                parsers[name.lower()] = (name, mod)
    return parsers


def _load_rules(rules_dir):
    import yara
    sources = {}
    for f in sorted(glob.glob(os.path.join(rules_dir, "*.yar")) + glob.glob(os.path.join(rules_dir, "*.yara"))):
        sources[os.path.basename(f)] = f
    good = {}
    for ns, f in sources.items():
        try:
            yara.compile(filepath=f)
            good[ns] = f
        except Exception:   # noqa: BLE001
            continue
    return yara.compile(filepaths=good) if good else None, len(good)


def analyze(data: bytes, rules, parsers) -> dict:
    out = {"families": [], "generic": [], "rules": [], "configs": {}, "errors": []}
    matches = rules.match(data=data, timeout=60) if rules is not None else []
    for m in matches:
        cape_type = str((m.meta or {}).get("cape_type") or "")
        fam = _family_from_type(cape_type) if cape_type else ""
        out["rules"].append(m.rule)
        if not fam or fam == "-":
            continue
        bucket = "generic" if fam.lower() in GENERIC_RULE_TYPES else "families"
        if fam not in out[bucket]:
            out[bucket].append(fam)
    for fam in out["families"]:
        hit = parsers.get(fam.lower())
        if not hit:
            continue
        name, mod = hit
        try:
            cfg = mod.extract_config(data)
        except Exception as e:   # noqa: BLE001 - parsers fail on unusual builds; report, do not crash
            out["errors"].append(f"{name}: {type(e).__name__}: {str(e)[:120]}")
            continue
        if cfg:
            out["configs"][name] = _jsonable(cfg)
    return out


def analyze_dump(data: bytes, rules, parsers) -> dict:
    """Memory dump: families from the whole dump (YARA sees everything), configs from each carved program, since
    the parsers need a PE that starts at offset 0. A carved program's own rule hits count as families too."""
    out = analyze(data, rules, {})                       # families / rules only, no parser on the flat dump
    out["carved"] = 0
    for off, layout, buf in carve_pes(data):
        out["carved"] += 1
        sub = analyze(buf, rules, {})
        fams = list(dict.fromkeys(out["families"] + sub["families"]))
        for fam in sub["families"]:
            if fam not in out["families"]:
                out["families"].append(fam)
        for fam in fams:
            hit = parsers.get(fam.lower())
            if not hit or hit[0] in out["configs"]:
                continue
            name, mod = hit
            try:
                cfg = mod.extract_config(buf)
            except Exception:   # noqa: BLE001 - most carved images are not this family's payload
                continue
            if cfg:
                out["configs"][name] = _jsonable(cfg)
                out.setdefault("config_from", {})[name] = f"0x{off:x} ({layout})"
    return out


def main() -> int:
    req = json.loads(sys.stdin.read() or "{}")
    # Parsers print warnings ("Problem to import blzpack ...") to stdout: keep stdout for the one JSON result.
    real_stdout, sys.stdout = sys.stdout, sys.stderr

    def emit(obj) -> int:
        real_stdout.write(json.dumps(obj))
        real_stdout.flush()
        return 0
    max_bytes = int(req.get("max_bytes") or 64 * 1024 * 1024)
    try:
        parsers = _load_parsers()
        rules, n_rules = _load_rules(req.get("rules_dir") or "")
    except Exception as e:   # noqa: BLE001
        return emit({"ok": False, "error": f"{type(e).__name__}: {e}"})
    results = []
    for item in req.get("files") or []:
        label = str(item.get("label") or item.get("path"))
        res = {"label": label}
        try:
            with open(item["path"], "rb") as fh:
                data = fh.read(max_bytes)
            if item.get("xor_key"):
                data = _xor_decode(data, bytes.fromhex(item["xor_key"]))
                res.update(analyze_dump(data, rules, parsers))
            else:
                res.update(analyze(data, rules, parsers))
        except Exception as e:   # noqa: BLE001
            res["errors"] = [f"{type(e).__name__}: {str(e)[:160]}"]
        results.append(res)
    return emit({"ok": True, "parsers": len(parsers), "rules": n_rules, "results": results})


if __name__ == "__main__":
    sys.exit(main())
