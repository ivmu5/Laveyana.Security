#!/usr/bin/env python3
"""Reject multiple top-level source types and undocumented public enum members.

This is an early, SDK-free structural check. It is NOT a substitute for compilation
or Roslyn's IDE0011/CS1591 diagnostics.
"""
from __future__ import annotations

import re
from pathlib import Path

from verify_repository import scrub_csharp

ROOT = Path(__file__).resolve().parent.parent
TYPES = re.compile(
    r"(?m)^[ \t]*(?:(?:public|internal|file|private|protected|static|sealed|abstract|readonly|partial|ref|unsafe|required|new)\s+)+"
    r"(?:class|interface|struct|enum|record(?:\s+(?:class|struct))?)\s+(?P<name>[A-Za-z_]\w*)"
)
DELEGATE = re.compile(
    r"(?m)^[ \t]*(?:public|internal)\s+delegate\s+[\w<>,?\[\]\s]+?\s+(?P<name>[A-Za-z_]\w*)\s*\("
)
BRACED_STATEMENTS = re.compile(r"\b(if|for|foreach|while|using|lock)\s*\(")


def validate_source(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8-sig")
    masked, _ = scrub_csharp(source)
    depth = 0
    levels = [0] * (len(masked) + 1)
    for pos, ch in enumerate(masked):
        levels[pos] = depth
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return [f"{path.name}: unbalanced braces"]
    if depth:
        return [f"{path.name}: unbalanced braces"]

    types = [m for expression in (TYPES, DELEGATE)
             for m in expression.finditer(masked) if levels[m.start()] == 0]
    types.sort(key=lambda m: m.start())
    problems = []
    if len(types) > 1:
        problems.append(f"{path.name}: multiple top-level types: " + ", ".join(t.group('name') for t in types))
    for item in types:
        name = item.group("name")
        if path.stem != name and not path.stem.startswith(name + "."):
            problems.append(f"{path.name}: declared top-level {name} differs from filename")
        if not re.search(r"\bpublic\b", item.group(0)):
            continue
        line_start = source.rfind("\n", 0, item.start()) + 1
        prefix = source[:line_start].rstrip().splitlines()
        # Allow attributes between XML docs and declaration.
        while prefix and prefix[-1].strip().startswith("["):
            prefix.pop()
        if not prefix or not prefix[-1].lstrip().startswith("///"):
            problems.append(f"{path.name}:{source.count(chr(10), 0, item.start()) + 1}: undocumented public type {name}")
        if "enum" not in item.group(0):
            continue
        start = masked.find("{", item.end())
        if start < 0:
            continue
        end = masked.find("}", start)
        if end < 0:
            continue
        base_line = source.count("\n", 0, start)
        enum_lines = source[start+1:end].splitlines()
        for ix, line in enumerate(enum_lines):
            item_match = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*(?:=[^,]*)?,?\s*", line)
            if item_match and (ix == 0 or not enum_lines[ix-1].strip().startswith("///")):
                problems.append(f"{path.name}:{base_line + ix + 2}: undocumented enum value {item_match.group(1)}")

    for m in BRACED_STATEMENTS.finditer(masked):
        bracket = masked.find("(", m.start())
        p = bracket + 1
        parens = 1
        while p < len(masked) and parens:
            if masked[p] == "(":
                parens += 1
            elif masked[p] == ")":
                parens -= 1
            p += 1
        if parens:
            continue
        while p < len(masked) and masked[p].isspace():
            p += 1
        if p < len(masked) and masked[p] not in "{;":
            problems.append(f"{path.name}:{source.count(chr(10), 0, m.start()) + 1}: braces missing after {m.group(1)}")
    return problems


def main() -> None:
    files = sorted(ROOT.glob("src/**/*.cs"))
    errors = [e for path in files for e in validate_source(path)]
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"PASS: {len(files)} C# files; one top-level type per file, public enum XML docs and braces verified")


if __name__ == "__main__":
    main()
