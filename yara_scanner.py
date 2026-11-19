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
# rule header: optional private/global, optional ": tag1 tag2"; body runs to the '}' that is followed by the next
# rule or the end of the file (bodies can contain '}' in hex strings, and rules may be written on one line).
_RULE_RX = re.compile(
    r"(?:^|(?<=[\s}]))(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w*)(?:\s*:\s*[A-Za-z_][\w ]*?)?\s*\{(.*?)\}"
    r"(?=\s*(?:(?:private|global)\s+)*rule\s|\s*\Z)",   # lookahead only: the next rule's text must stay unconsumed
    re.S,
)


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
    if "fullword" in mods:   # YARA: the match must not be preceded or followed by an alphanumeric character
        return [re.compile(rb"(?<![A-Za-z0-9])" + re.escape(v) + rb"(?![A-Za-z0-9])", flags) for v in variants if v]
    return [re.compile(re.escape(v), flags) for v in variants if v]


def _parse_yar_text(text: str, source_name: str = "<memory>") -> List[Dict[str, Any]]:
    # Strip // and /* */ comments only outside "..." strings and /.../ regex literals
    text = re.sub(
        r'("(?:[^"\\]|\\.)*"|/(?!\*)(?:[^/\\\n]|\\.)+/[is]*)|/\*.*?\*/|//[^\n]*',
        lambda m: m.group(1) or "",
        text,
        flags=re.S,
    )

    parsed: List[Dict[str, Any]] = []
    for m in _RULE_RX.finditer(text):
        rule_name, body = m.group(1), m.group(2)
        # put section keywords and each "$id =" on their own line, so one-line rules parse like multi-line ones
        body = re.sub(r"\b(meta|strings|condition)\s*:", r"\n\1:\n", body)
        body = re.sub(r"\s+(?=\$[A-Za-z_]\w*\s*=)", "\n", body)
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
        unsupported: List[str] = []
        for line in sections["strings"].splitlines():
            if not line.strip():
                continue
            sm = re.match(r'^(\$[A-Za-z_]\w*)\s*=\s*"((?:[^"\\]|\\.)*)"(.*)$', line)
            if sm:
                ident = sm.group(1)
                raw_bytes = _decode_yara_literal(sm.group(2))
                mods = [w.lower() for w in sm.group(3).split()]
                bad_mods = [w for w in mods if w not in _SUPPORTED_STRING_MODS]
                if bad_mods:
                    unsupported.append(f"{ident}: desteklenmeyen değiştirici {', '.join(bad_mods)}")
                    continue
                patterns[ident] = _compile_string_variants(raw_bytes, mods)
                continue
            hm = re.match(r"^(\$[A-Za-z_]\w*)\s*=\s*\{\s*([0-9A-Fa-f\s]+)\s*\}\s*$", line)
            if hm:
                try:
                    raw_hex = bytes.fromhex(hm.group(2))
                    patterns[hm.group(1)] = [re.compile(re.escape(raw_hex))]
                    continue
                except ValueError:
                    pass
            ident = (re.match(r"^(\$[A-Za-z_]\w*)", line) or [None, line[:30]])[1]
            unsupported.append(f"{ident}: hex joker/atlama/regex dizisi desteklenmiyor")

        cond = " ".join(sections["condition"].split())
        if cond:
            problem = _condition_problem(cond, list(patterns.keys()))
            if problem:
                unsupported.append(problem)
        if not patterns and not unsupported:
            unsupported.append("hiç dizi (string) yok")
        parsed.append({
            "name": rule_name,
            "source": source_name,
            "meta": meta,
            "patterns": patterns,
            "condition": cond,
            "unsupported": unsupported,   # non-empty -> the built-in engine skips the rule and says why
        })
    return parsed


def _parse_yar_file(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return _parse_yar_text(text, path.name)


_SUPPORTED_STRING_MODS = {"ascii", "wide", "nocase", "fullword", "private"}


def _condition_problem(cond: str, ids: List[str]) -> Optional[str]:
    """Why the built-in evaluator cannot run this condition faithfully, or None.
    It supports only $vars, 'any/all/N of (them|($a, $b*))', and/or/not and parentheses."""
    for ref in set(re.findall(r"\$[A-Za-z_]\w*\*?", cond)):
        base = ref.rstrip("*")
        if ref.endswith("*"):
            if not any(i.startswith(base) for i in ids):
                return f"koşul tanımsız diziye bakıyor: {ref}"
        elif base not in ids:
            return f"koşul tanımsız ya da desteklenmeyen diziye bakıyor: {ref}"
    probe = re.sub(r"\b(any|all|\d+)\s+of\s+(them|\([^)]+\))", " True ", cond, flags=re.I)
    probe = re.sub(r"\$[A-Za-z_]\w*", " True ", probe)
    leftover = re.sub(r"\b(?:True|False|and|or|not)\b|[()\s]+", "", probe)
    if leftover:
        return f"koşul desteklenmiyor (ör. filesize, uint16, #sayım, @konum, modüller): {cond[:80]}"
    return None


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
    sig = (_yara is not None, _files_signature(files))
    if sig == _CACHE_KEY and _CACHE_RULES is not None:
        return _CACHE_RULES
    global _LOAD_PROBLEMS
    problems: List[str] = []
    if _yara is not None and files:
        # one file at a time: a broken user rule file must not take down the panel or the static stage
        compiled_list = []
        for p in files:
            try:
                compiled_list.append(_yara.compile(filepath=str(p)))
            except Exception as e:   # yara.SyntaxError, yara.Error
                problems.append(f"{p.name}: derlenemedi, atlandı ({str(e)[:160]})")
        _CACHE_RULES = ("yara-python", compiled_list, files)
    else:
        rules: List[Dict[str, Any]] = []
        for p in files:
            try:
                for r in _parse_yar_file(p):
                    if r["unsupported"]:
                        problems.append(f"{p.name}/{r['name']}: yerleşik motor çalıştıramıyor, atlandı ({'; '.join(r['unsupported'])[:160]})")
                    else:
                        rules.append(r)
            except Exception as e:
                problems.append(f"{p.name}: okunamadı, atlandı ({str(e)[:160]})")
        _CACHE_RULES = ("builtin", rules, files)
    _LOAD_PROBLEMS = problems
    _CACHE_KEY = sig
    return _CACHE_RULES


_LOAD_PROBLEMS: List[str] = []


def rules_status() -> Dict[str, Any]:
    engine, rules, files = _load_ruleset()
    count = sum(len(list(c)) for c in rules) if engine == "yara-python" else len(rules)
    return {
        "engine": engine,
        "rules_count": count,
        "files": [p.name for p in files],
        "problems": list(_LOAD_PROBLEMS),   # skipped files/rules and why; shown in the panel
        "hint": "" if engine == "yara-python" else
                "yara-python kurulu değil: yerleşik motor sadece basit kuralları çalıştırır. 'pip install yara-python' önerilir.",
    }


def scan_bytes(data: bytes, file_name: str = "") -> List[Dict[str, Any]]:
    """Scans buffer with all loaded `.yar` rules and returns structured match metadata."""
    if not data:
        return []
    engine, rules, _ = _load_ruleset()
    matches: List[Dict[str, Any]] = []
    if engine == "yara-python":
        found = []
        for compiled in rules:
            try:
                found.extend(compiled.match(data=data, timeout=30))
            except Exception:   # a slow/odd rule must not fail the analysis
                continue
        for m in found:
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


# ------------------------------------------------------------------ rule file management (E17)
_SAFE_RULE_NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.yara?$", re.IGNORECASE)


def _validate_rule_name(name: str) -> str:
    clean = (name or "").strip()
    if not clean or ".." in clean or not _SAFE_RULE_NAME_RX.fullmatch(clean):
        raise ValueError("Geçersiz YARA dosya adı (.yar veya .yara ile bitmeli, harf/rakam/_/-/. kullanılmalı).")
    resolved = (RULES_DIR / clean).resolve()
    if resolved.parent != RULES_DIR.resolve():
        raise ValueError("Geçersiz YARA dosya yolu.")
    return clean


def list_rule_files() -> List[Dict[str, Any]]:
    files = _rule_files()
    out: List[Dict[str, Any]] = []
    for p in files:
        probs: List[str] = []
        rule_names: List[str] = []
        count = 0
        if _yara is not None:
            try:
                comp = _yara.compile(filepath=str(p))
                rule_names = [r.identifier for r in comp]
                count = len(rule_names)
            except Exception as e:
                probs.append(str(e)[:200])
        else:
            try:
                parsed = _parse_yar_file(p)
                for r in parsed:
                    if r["unsupported"]:
                        probs.append(f"{r['name']}: {'; '.join(r['unsupported'])[:160]}")
                    else:
                        rule_names.append(r["name"])
                count = len(rule_names)
            except Exception as e:
                probs.append(str(e)[:200])
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        out.append({
            "name": p.name,
            "size": size,
            "rules_count": count,
            "rules": rule_names,
            "builtin": p.name.lower() == "safebox_builtin.yar",
            "problems": probs,
        })
    return out


def read_rule_file(name: str) -> str:
    safe = _validate_rule_name(name)
    p = RULES_DIR / safe
    if not p.is_file():
        raise FileNotFoundError(f"Kural dosyası bulunamadı: {safe}")
    return p.read_text(encoding="utf-8", errors="replace")


def validate_rule_source(content: str) -> Tuple[int, List[str]]:
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Kural içeriği boş olamaz.")
    if len(content.encode("utf-8", errors="replace")) > 2 * 1024 * 1024:
        raise ValueError("Kural dosyası 2 MB sınırını aşıyor.")
    if _yara is not None:
        try:
            compiled = _yara.compile(source=content)
            cnt = len(list(compiled))
        except Exception as e:
            raise ValueError(f"YARA sözdizimi hatası: {e}") from e
        if cnt == 0:
            raise ValueError("Dosyada geçerli bir YARA kuralı bulunamadı.")
        return cnt, []
    parsed = _parse_yar_text(content, "<custom>")
    if not parsed:
        raise ValueError("Geçerli bir YARA kuralı bulunamadı.")
    probs = [f"{r['name']}: {'; '.join(r['unsupported'])}" for r in parsed if r["unsupported"]]
    supported = [r for r in parsed if not r["unsupported"]]
    if not supported:
        raise ValueError(f"Yerleşik motor bu kuralları çalıştıramıyor: {'; '.join(probs)[:200]}")
    return len(supported), probs


def save_custom_rule_file(name: str, content: str) -> Dict[str, Any]:
    global _CACHE_KEY, _CACHE_RULES
    safe = _validate_rule_name(name)
    if safe.lower() == "safebox_builtin.yar":
        raise ValueError("Yerleşik kural dosyası (safebox_builtin.yar) düzenlenemez.")
    count, probs = validate_rule_source(content)
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    (RULES_DIR / safe).write_text(content, encoding="utf-8")
    _CACHE_KEY = None
    _CACHE_RULES = None
    st = rules_status()
    return {"name": safe, "rules_count": count, "problems": probs, "status": st}


def delete_custom_rule_file(name: str) -> Dict[str, Any]:
    global _CACHE_KEY, _CACHE_RULES
    safe = _validate_rule_name(name)
    if safe.lower() == "safebox_builtin.yar":
        raise ValueError("Yerleşik kural dosyası (safebox_builtin.yar) silinemez.")
    p = RULES_DIR / safe
    if not p.is_file():
        raise FileNotFoundError(f"Kural dosyası bulunamadı: {safe}")
    p.unlink()
    _CACHE_KEY = None
    _CACHE_RULES = None
    return {"deleted": safe, "status": rules_status()}
