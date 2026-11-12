"""YARA scanner for SafeBox: uses `yara-python` when installed, or an offline built-in parser for `.yar` rules."""
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import yara as _yara  # type: ignore
except ImportError:
    _yara = None

RULES_DIR = Path(__file__).parent.resolve() / "rules"
_CACHE_KEY: Optional[Tuple[Tuple[str, float, int], ...]] = None
_CACHE_RULES: Any = None


def _rule_files() -> List[Path]:
    if not RULES_DIR.is_dir():
        return []
    return sorted(p for p in RULES_DIR.iterdir() if p.is_file() and p.suffix.lower() in (".yar", ".yara"))


def _files_signature(files: List[Path]) -> Tuple[Tuple[str, float, int], ...]:
    sig = []
    for p in files:
        try:
            st = p.stat()
            sig.append((p.name, st.st_mtime, st.st_size))
        except OSError:
            pass
    return tuple(sig)


# ------------------------------------------------------------------ built-in .yar subset parser
_RULE_RX = re.compile(r"(?:^|\n)\s*rule\s+([A-Za-z_]\w*)\s*\{(.*?)\n\s*\}", re.S)


def _decode_yara_literal(raw: str) -> bytes:
    """Decodes escaped string literal content inside YARA double quotes."""
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in ("\\", '"', "'"):
                out.extend(nxt.encode("utf-8"))
                i += 2
                continue
            if nxt == "n":
                out.append(10)
                i += 2
                continue
            if nxt == "r":
                out.append(13)
                i += 2
                continue
            if nxt == "t":
                out.append(9)
                i += 2
                continue
            if nxt == "x" and i + 3 < len(raw):
                try:
                    out.append(int(raw[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
        out.extend(ch.encode("utf-8"))
        i += 1
    return bytes(out)


def _compile_string_variants(literal_bytes: bytes, mods: List[str]) -> List[re.Pattern]:
    use_nocase = "nocase" in mods
    flags = re.IGNORECASE if use_nocase else 0
    variants: List[bytes] = []
    has_ascii = "ascii" in mods or "wide" not in mods
    has_wide = "wide" in mods
    if has_ascii:
        variants.append(literal_bytes)
    if has_wide:
        try:
            variants.append(literal_bytes.decode("utf-8").encode("utf-16le"))
        except UnicodeDecodeError:
            pass
    return [re.compile(re.escape(v), flags) for v in variants if v]


def _parse_yar_file(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    # Strip // and /* */ comments outside literals cleanly enough for standard rules
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)

    parsed: List[Dict[str, Any]] = []
    for m in _RULE_RX.finditer(text):
        rule_name, body = m.group(1), m.group(2)
        sections = {"meta": "", "strings": "", "condition": ""}
        cur = None
        for line in body.splitlines():
            s = line.strip()
            low = s.lower()
            if low in ("meta:", "strings:", "condition:"):
                cur = low[:-1]
            elif cur:
                sections[cur] += s + "\n"

        meta: Dict[str, Any] = {}
        for line in sections["meta"].splitlines():
            mm = re.match(r'^([A-Za-z_]\w*)\s*=\s*"([^"]*)"', line)
            if mm:
                meta[mm.group(1)] = mm.group(2)
            else:
                mi = re.match(r"^([A-Za-z_]\w*)\s*=\s*(\d+)", line)
                if mi:
                    meta[mi.group(1)] = int(mi.group(2))

        patterns: Dict[str, List[re.Pattern]] = {}
        for line in sections["strings"].splitlines():
            sm = re.match(r'^(\$[A-Za-z_]\w*)\s*=\s*"((?:[^"\\]|\\.)*)"(.*)$', line)
            if sm:
                ident = sm.group(1)
                raw_bytes = _decode_yara_literal(sm.group(2))
                mods = [w.lower() for w in sm.group(3).split()]
                patterns[ident] = _compile_string_variants(raw_bytes, mods)
                continue
            hm = re.match(r"^(\$[A-Za-z_]\w*)\s*=\s*\{\s*([0-9A-Fa-f\s]+)\s*\}", line)
            if hm:
                try:
                    raw_hex = bytes.fromhex(hm.group(2))
                    patterns[hm.group(1)] = [re.compile(re.escape(raw_hex))]
                except ValueError:
                    pass

        cond = " ".join(sections["condition"].split())
        if cond and patterns:
            parsed.append({
                "name": rule_name,
                "source": path.name,
                "meta": meta,
                "patterns": patterns,
                "condition": cond,
            })
    return parsed


def _eval_builtin_condition(cond: str, hits: Dict[str, bool], all_ids: List[str]) -> bool:
    """Safely evaluates standard YARA boolean conditions (`any of`, `all of`, `N of`, `and`, `or`, `not`, `$var`)."""
    def resolve_set(spec: str) -> List[str]:
        spec = spec.strip()
        if spec == "them":
            return all_ids
        if spec.startswith("(") and spec.endswith(")"):
            inner = spec[1:-1]
            selected: List[str] = []
            for tok in inner.split(","):
                tok = tok.strip()
                if tok.endswith("*"):
                    pref = tok[:-1]
                    selected.extend(k for k in all_ids if k.startswith(pref))
                elif tok:
                    selected.append(tok)
            return selected
        return []

    def sub_quantifiers(match: re.Match) -> str:
        qty = match.group(1).lower()
        target = match.group(2)
        group_ids = resolve_set(target)
        cnt = sum(1 for gid in group_ids if hits.get(gid, False))
        if qty == "any":
            return " True " if cnt >= 1 else " False "
        if qty == "all":
            return " True " if (group_ids and cnt == len(group_ids)) else " False "
        try:
            need = int(qty)
            return " True " if cnt >= need else " False "
        except ValueError:
            return " False "

    expr = re.sub(r"\b(any|all|\d+)\s+of\s+(them|\([^)]+\))", sub_quantifiers, cond, flags=re.I)
    expr = re.sub(r"\$[A-Za-z_]\w*", lambda m: " True " if hits.get(m.group(0), False) else " False ", expr)
    # Whitelist strictly Boolean expression tokens before eval()
    cleaned = re.sub(r"\b(?:True|False|and|or|not)\b|[()\s]+", "", expr)
    if cleaned:
        return False
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return False


def _load_ruleset():
    global _CACHE_KEY, _CACHE_RULES
    files = _rule_files()
    sig = _files_signature(files)
    if sig == _CACHE_KEY and _CACHE_RULES is not None:
        return _CACHE_RULES
    if _yara is not None and files:
        compiled = _yara.compile(filepaths={p.stem: str(p) for p in files})
        _CACHE_RULES = ("yara-python", compiled, files)
    else:
        rules: List[Dict[str, Any]] = []
        for p in files:
            rules.extend(_parse_yar_file(p))
        _CACHE_RULES = ("builtin", rules, files)
    _CACHE_KEY = sig
    return _CACHE_RULES


def rules_status() -> Dict[str, Any]:
    engine, rules, files = _load_ruleset()
    count = sum(len(_parse_yar_file(p)) for p in files) if engine == "yara-python" else len(rules)
    return {
        "engine": engine,
        "rules_count": count,
        "files": [p.name for p in files],
    }


def scan_bytes(data: bytes, file_name: str = "") -> List[Dict[str, Any]]:
    """Scans buffer with all loaded `.yar` rules and returns structured match metadata."""
    if not data:
        return []
    engine, rules, _ = _load_ruleset()
    matches: List[Dict[str, Any]] = []
    if engine == "yara-python":
        for m in rules.match(data=data):
            meta = dict(getattr(m, "meta", {}) or {})
            matched_strs: List[str] = []
            for s in getattr(m, "strings", ()) or ():
                ident = getattr(s, "identifier", None) or (s[1] if isinstance(s, tuple) and len(s) >= 2 else "")
                if ident and ident not in matched_strs:
                    matched_strs.append(str(ident))
            matches.append({
                "rule": m.rule,
                "source": getattr(m, "namespace", "yara"),
                "description": str(meta.get("description") or m.rule),
                "severity": str(meta.get("severity") or "medium"),
                "score": int(meta.get("score") or 15),
                "strings": matched_strs[:8],
            })
        return matches

    for r in rules:
        hits: Dict[str, bool] = {}
        matched_ids: List[str] = []
        for ident, pats in r["patterns"].items():
            ok = any(p.search(data) for p in pats)
            hits[ident] = ok
            if ok:
                matched_ids.append(ident)
        if _eval_builtin_condition(r["condition"], hits, list(r["patterns"].keys())):
            meta = r["meta"]
            matches.append({
                "rule": r["name"],
                "source": r["source"],
                "description": str(meta.get("description") or r["name"]),
                "severity": str(meta.get("severity") or "medium"),
                "score": int(meta.get("score") or 15),
                "strings": matched_ids[:8],
            })
    return matches
