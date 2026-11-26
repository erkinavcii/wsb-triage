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
            res.update(analyze(data, rules, parsers))
        except Exception as e:   # noqa: BLE001
            res["errors"] = [f"{type(e).__name__}: {str(e)[:160]}"]
        results.append(res)
    return emit({"ok": True, "parsers": len(parsers), "rules": n_rules, "results": results})


if __name__ == "__main__":
    sys.exit(main())
