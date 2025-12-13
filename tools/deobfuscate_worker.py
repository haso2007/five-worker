import base64
import json
import re
from fractions import Fraction
from pathlib import Path

import jsbeautifier


WORKDIR = Path(__file__).resolve().parents[1]
INPUT = WORKDIR / "_worker.js"
OUTPUT = WORKDIR / "_worker.readable.js"


def _strip_exports(js: str) -> str:
    # QuickJS doesn't support ES module syntax. This worker ends with `export{u5 as default};`.
    js = re.sub(r"\bexport\s*\{[^}]*\}\s*;?\s*$", "", js)
    js = re.sub(r"\bexport\s+default\s+", "", js)
    return js


def _decode_js_string_literal(literal: str) -> str:
    # literal includes surrounding quotes.
    if len(literal) >= 2 and literal[0] == literal[-1] and literal[0] in ("'", '"'):
        q = literal[0]
        body = literal[1:-1]
    else:
        raise ValueError(f"Not a JS string literal: {literal[:30]!r}")

    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        esc = body[i]
        i += 1
        if esc == "x" and i + 2 <= len(body):
            out.append(chr(int(body[i : i + 2], 16)))
            i += 2
        elif esc == "u":
            # Handle \uNNNN. Ignore \u{...} (not expected in this obfuscation style).
            if i < len(body) and body[i] == "{":
                j = body.find("}", i + 1)
                if j == -1:
                    out.append("u")
                else:
                    out.append(chr(int(body[i + 1 : j], 16)))
                    i = j + 1
            else:
                out.append(chr(int(body[i : i + 4], 16)))
                i += 4
        elif esc == "n":
            out.append("\n")
        elif esc == "r":
            out.append("\r")
        elif esc == "t":
            out.append("\t")
        elif esc == "b":
            out.append("\b")
        elif esc == "f":
            out.append("\f")
        elif esc == "v":
            out.append("\v")
        elif esc == "0":
            out.append("\0")
        elif esc in ("\\", "'", '"'):
            out.append(esc)
        else:
            out.append(esc)

    return "".join(out)


def _extract_balanced(js: str, start: int, open_ch: str, close_ch: str) -> tuple[str, int]:
    if js[start] != open_ch:
        raise ValueError(f"Expected {open_ch} at {start}")
    depth = 0
    i = start
    in_str: str | None = None
    escape = False
    while i < len(js):
        ch = js[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue

        if ch in ("'", '"'):
            in_str = ch
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return js[start : i + 1], i + 1
        i += 1

    raise ValueError("Unbalanced brackets")


def _extract_bootstrap(js: str) -> dict:
    # Parse the first anti-tamper IIFE that rotates the string array.
    iife_start = js.find("(function(X,O){")
    if iife_start == -1:
        raise RuntimeError("Could not locate the bootstrap IIFE '(function(X,O){'")

    iife_expr, iife_end = _extract_balanced(js, iife_start, "(", ")")

    # Get array provider function name and target number from the invocation argument list.
    # Expected shape (minified): (function(X,O){...}(ARR_FN,0xDEAD))
    call_open = None
    for m in re.finditer(r"\}\(", iife_expr):
        call_open = m.start() + 1  # points to '(' after the last '}'
    if call_open is None:
        raise RuntimeError("Could not locate bootstrap IIFE invocation '}(...)'")

    arg_group, _ = _extract_balanced(iife_expr, call_open, "(", ")")
    args_str = arg_group[1:-1].strip()

    m_tail = re.fullmatch(r"([A-Za-z_$][\w$]*)\s*,\s*(0x[0-9a-fA-F]+)", args_str)
    if not m_tail:
        raise RuntimeError(f"Could not parse bootstrap IIFE call arguments: {args_str[:120]!r}")
    arr_fn_name = m_tail.group(1)
    target = int(m_tail.group(2), 16)

    # Find the local alias used for Q inside the IIFE: const un=Q;
    m_alias = re.search(r"const\s+([A-Za-z_$][\w$]*)\s*=\s*Q\s*,", iife_expr)
    if not m_alias:
        m_alias = re.search(r"const\s+([A-Za-z_$][\w$]*)\s*=\s*Q\s*;", iife_expr)
    alias = m_alias.group(1) if m_alias else "Q"

    # Extract K expression.
    m_k = re.search(r"const\s+K\s*=([^;]+);if\(K===O\)", iife_expr)
    if not m_k:
        # Some obfuscators omit semicolons; be more flexible.
        m_k = re.search(r"const\s+K\s*=([^;]+);?if\(K===O\)", iife_expr)
    if not m_k:
        raise RuntimeError("Could not extract bootstrap K expression")

    k_expr_js = m_k.group(1)
    return {
        "iife_end": iife_end,
        "arr_fn_name": arr_fn_name,
        "target": target,
        "alias": alias,
        "k_expr_js": k_expr_js,
    }


def _extract_function(js: str, fn_name: str) -> str:
    idx = js.find(f"function {fn_name}(")
    if idx == -1:
        raise RuntimeError(f"Could not find function {fn_name}(...)")
    brace = js.find("{", idx)
    if brace == -1:
        raise RuntimeError(f"Could not find opening brace for function {fn_name}")
    body, _ = _extract_balanced(js, brace, "{", "}")
    return js[idx : brace] + body


def _extract_q_offset(js: str) -> int:
    idx = js.find("function Q(")
    if idx == -1:
        raise RuntimeError("Could not find decoder function Q(...)")
    m_head = re.search(r"function\s+Q\(\s*([A-Za-z_$][\w$]*)", js[idx : idx + 200])
    if not m_head:
        raise RuntimeError("Could not parse Q() parameter list")
    arg0 = m_head.group(1)
    brace = js.find("{", idx)
    fn_body, _ = _extract_balanced(js, brace, "{", "}")

    # Most common form: <arg0>=<arg0>-0x123;
    m = re.search(rf"\b{re.escape(arg0)}\s*=\s*{re.escape(arg0)}\s*-\s*(0x[0-9a-fA-F]+)", fn_body)
    if m:
        return int(m.group(1), 16)

    # Fallback: find any -0x.... near the beginning.
    m2 = re.search(r"-\s*(0x[0-9a-fA-F]+)", fn_body)
    if m2:
        return int(m2.group(1), 16)

    raise RuntimeError("Could not determine Q() base offset")


def _extract_string_array(js: str, arr_fn_name: str) -> list[str]:
    fn_src = _extract_function(js, arr_fn_name)

    # Find the first array literal assigned to a const inside this function.
    m = re.search(r"\bconst\s+[A-Za-z_$][\w$]*\s*=\s*\[", fn_src)
    if not m:
        raise RuntimeError(f"Could not locate array literal in {arr_fn_name}()")
    array_start = m.end() - 1
    array_literal, _ = _extract_balanced(fn_src, array_start, "[", "]")

    # Parse elements.
    elements: list[str] = []
    i = 1
    while i < len(array_literal) - 1:
        # skip whitespace/commas
        while i < len(array_literal) - 1 and array_literal[i] in " \t\r\n,":
            i += 1
        if i >= len(array_literal) - 1:
            break
        ch = array_literal[i]
        if ch in ("'", '"'):
            # parse string literal
            j = i + 1
            esc = False
            while j < len(array_literal) - 1:
                cj = array_literal[j]
                if esc:
                    esc = False
                elif cj == "\\":
                    esc = True
                elif cj == ch:
                    break
                j += 1
            literal = array_literal[i : j + 1]
            elements.append(_decode_js_string_literal(literal))
            i = j + 1
        else:
            # non-string element, take until comma or end
            j = i
            while j < len(array_literal) - 1 and array_literal[j] not in ",]":
                j += 1
            elements.append(array_literal[i:j].strip())
            i = j

    return elements


def _collect_aliases(js: str) -> set[str]:
    # Find simple alias assignments like: const uv=Q; let un=uv; var X=Q;
    assign_re = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;"
    )

    edges: list[tuple[str, str]] = []
    for m in assign_re.finditer(js):
        edges.append((m.group(1), m.group(2)))

    aliases = {"Q"}
    changed = True
    while changed:
        changed = False
        for left, right in edges:
            if right in aliases and left not in aliases:
                aliases.add(left)
                changed = True

    return aliases


def main() -> None:
    src = INPUT.read_text("utf-8", errors="ignore")

    bootstrap = _extract_bootstrap(src)
    offset = _extract_q_offset(src)
    arr = _extract_string_array(src, bootstrap["arr_fn_name"])

    def decode(num: int) -> str:
        return arr[num - offset]

    # Rotate the array according to the bootstrap loop so Q(num) resolves correctly.
    k_expr = bootstrap["k_expr_js"].replace("parseInt", "parse_int").replace(bootstrap["alias"], "decode")

    def parse_int(x) -> Fraction:
        s = str(x).strip()
        m = re.match(r"^[+-]?(?:0x[0-9a-fA-F]+|\d+)", s)
        if not m:
            raise ValueError(f"parseInt could not parse: {s!r}")
        return Fraction(int(m.group(0), 0))

    env = {"__builtins__": {}, "parse_int": parse_int, "decode": decode, "Fraction": Fraction}
    target = Fraction(bootstrap["target"])
    max_iter = max(10_000, len(arr) * 5)
    for _ in range(max_iter):
        try:
            k_val = eval(k_expr, env)  # noqa: S307
            if k_val == target:
                break
        except Exception:
            pass
        arr.append(arr.pop(0))
    else:
        raise RuntimeError("Failed to rotate string table (bootstrap loop did not converge)")

    aliases = _collect_aliases(src)

    call_re = re.compile(r"\b([A-Za-z_$][\w$]*)\(\s*(0x[0-9a-fA-F]+)\s*\)")
    cache: dict[int, str] = {}

    def replace(m: re.Match) -> str:
        name = m.group(1)
        if name not in aliases:
            return m.group(0)

        num = int(m.group(2), 16)
        if num not in cache:
            cache[num] = decode(num)
        return json.dumps(cache[num], ensure_ascii=False)

    deobf = call_re.sub(replace, src)

    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.preserve_newlines = True
    opts.max_preserve_newlines = 2
    opts.wrap_line_length = 120
    pretty = jsbeautifier.beautify(deobf, opts)

    with OUTPUT.open("w", encoding="utf-8", errors="surrogatepass") as f:
        f.write(pretty)
    print(f"Wrote: {OUTPUT}")
    print(f"Decoded {len(cache)} unique string indices; aliases: {len(aliases)}")


if __name__ == "__main__":
    main()
