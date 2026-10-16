#!/usr/bin/env python3
"""Verify the foundational project graph and first-party C# source conventions."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANDATORY = {
    "Laveyana.Security.Abstractions",
    "Laveyana.Security",
    "Laveyana.Security.FileSystem",
    "Laveyana.Security.DependencyInjection",
    "Laveyana.Security.Tests",
    "Laveyana.Security.IntegrationTests",
}
PRODUCTION = {
    "Laveyana.Security.Abstractions",
    "Laveyana.Security",
    "Laveyana.Security.FileSystem",
    "Laveyana.Security.DependencyInjection",
    "Laveyana.Security.Windows",
}
FORBIDDEN = {
    "Laveyana.Security.Abstractions": {"Laveyana.Security", "Laveyana.Security.FileSystem", "Laveyana.Security.DependencyInjection", "Laveyana.Security.Windows"},
    "Laveyana.Security": {"Laveyana.Security.FileSystem", "Laveyana.Security.DependencyInjection", "Laveyana.Security.Windows"},
    "Laveyana.Security.FileSystem": {"Laveyana.Security", "Laveyana.Security.DependencyInjection", "Laveyana.Security.Windows"},
    "Laveyana.Security.Windows": {"Laveyana.Security", "Laveyana.Security.FileSystem", "Laveyana.Security.DependencyInjection"},
}
NON_ASCII = re.compile(r"[^\x00-\x7F]")
BLOCK_NAMESPACE = re.compile(r"(?m)^\s*namespace\s+[A-Za-z_][\w.]*\s*\{")


def scrub_csharp(text: str) -> tuple[str, list[str]]:
    """Return code without comments/string literals and all extracted comments."""
    output: list[str] = []
    comments: list[str] = []
    index = 0
    length = len(text)

    def blank(chunk: str) -> str:
        return ''.join('\n' if char == '\n' else ' ' for char in chunk)

    while index < length:
        if text.startswith('//', index):
            end = text.find('\n', index)
            if end == -1:
                end = length
            comments.append(text[index:end])
            output.append(blank(text[index:end]))
            index = end
            continue

        if text.startswith('/*', index):
            end = text.find('*/', index + 2)
            if end == -1:
                raise ValueError('Unterminated block comment')
            end += 2
            comments.append(text[index:end])
            output.append(blank(text[index:end]))
            index = end
            continue

        # C# raw strings can have 3 or more quote characters, with optional $ prefixes.
        raw_match = re.match(r'\$*"{3,}', text[index:])
        if raw_match:
            opener = raw_match.group()
            delimiter = '"' * len(opener.lstrip('$'))
            end = text.find(delimiter, index + len(opener))
            if end == -1:
                raise ValueError('Unterminated raw string literal')
            end += len(delimiter)
            output.append(blank(text[index:end]))
            index = end
            continue

        string_prefix = None
        for prefix in ('$@"', '@$"', '@"', '$"', '"', "'"):
            if text.startswith(prefix, index):
                string_prefix = prefix
                break

        if string_prefix is not None:
            quote = string_prefix[-1]
            verbatim = '@' in string_prefix
            end = index + len(string_prefix)
            while end < length:
                if verbatim and text.startswith('""', end):
                    end += 2
                    continue
                if not verbatim and text[end] == '\\':
                    end += 2
                    continue
                if text[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise ValueError('Unterminated string or char literal')
            output.append(blank(text[index:end]))
            index = end
            continue

        output.append(text[index])
        index += 1

    return ''.join(output), comments


def validate_sources(root: Path) -> list[str]:
    errors: list[str] = []
    for source in sorted((*root.glob('src/**/*.cs'), *root.glob('tests/**/*.cs'))):
        if any(part in {'bin', 'obj'} for part in source.parts):
            continue
        try:
            code, comments = scrub_csharp(source.read_text(encoding='utf-8-sig'))
        except (UnicodeError, ValueError) as exception:
            errors.append(f'{source.relative_to(root)}: {exception}')
            continue
        if BLOCK_NAMESPACE.search(code):
            errors.append(f'{source.relative_to(root)}: block-scoped namespace is prohibited')
        if any(NON_ASCII.search(comment) for comment in comments):
            errors.append(f'{source.relative_to(root)}: non-ASCII source comment (English-only source rule)')
    return errors


def validate_projects(root: Path) -> list[str]:
    errors: list[str] = []
    projects = {p.stem: p for p in [*root.glob('src/**/*.csproj'), *root.glob('tests/**/*.csproj')]}
    missing = MANDATORY - projects.keys()
    if missing:
        errors.append(f'Missing mandatory projects: {sorted(missing)}')
    if len(projects) != len(list(root.glob('src/**/*.csproj'))) + len(list(root.glob('tests/**/*.csproj'))):
        errors.append('Duplicate project file stem')
    dependencies: dict[str, set[str]] = {}

    for name, path in projects.items():
        if not name.startswith('Laveyana.Security'):
            errors.append(f'{name}: invalid project identity')
        try:
            tree = ET.parse(path)
        except ET.ParseError as exception:
            errors.append(f'{path.relative_to(root)}: invalid XML: {exception}')
            continue
        refs: set[str] = set()
        for node in tree.findall('.//ProjectReference'):
            include = node.get('Include', '')
            target = (path.parent / include.replace('\\', '/')).resolve()
            if not target.is_file():
                errors.append(f'{name}: missing ProjectReference {include}')
                continue
            refs.add(target.stem)
        for node in tree.findall('.//PackageReference'):
            if 'Version' in node.attrib:
                errors.append(f'{name}: PackageReference version is not centrally managed')
        dependencies[name] = refs
        bad = FORBIDDEN.get(name, set()) & refs
        if bad:
            errors.append(f'{name}: prohibited project references {sorted(bad)}')
        if name in PRODUCTION and not (path.parts[-3] == 'src'):
            errors.append(f'{name}: production project must live in src/')

    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(name: str) -> None:
        if name in visiting:
            errors.append(f'Project reference cycle detected at {name}')
            return
        if name in visited:
            return
        visiting.add(name)
        for child in dependencies.get(name, set()):
            walk(child)
        visiting.remove(name)
        visited.add(name)

    for project in dependencies:
        walk(project)

    return errors


def validate_build_policy(root: Path) -> list[str]:
    errors: list[str] = []
    required = {
        'TargetFramework': 'net10.0',
        'Nullable': 'enable',
        'GenerateDocumentationFile': 'true',
        'EnableNETAnalyzers': 'true',
        'EnforceCodeStyleInBuild': 'true',
        'TreatWarningsAsErrors': 'true',
    }
    props = ET.parse(root / 'Directory.Build.props').getroot()
    for name, expected in required.items():
        value = props.findtext(f'.//{name}')
        if value != expected:
            errors.append(f'Directory.Build.props: {name} should be {expected}')

    central = ET.parse(root / 'Directory.Packages.props').getroot()
    if central.findtext('.//ManagePackageVersionsCentrally') != 'true':
        errors.append('Central Package Management is not enabled')

    sdk = json.loads((root / 'global.json').read_text(encoding='utf-8'))
    if not sdk.get('sdk', {}).get('version', '').startswith('10.'):
        errors.append('global.json must select the .NET 10 SDK')

    solution = (root / 'Laveyana.Security.sln').read_text(encoding='utf-8')
    solution_projects = re.findall(
        r'^Project\("\{[^}]+\}"\) = "([^"]+)", "([^"]+)", "\{[^}]+\}"$',
        solution,
        flags=re.MULTILINE,
    )
    for name, path in solution_projects:
        expected_path = root / path.replace('\\', '/')
        if not expected_path.is_file() or expected_path.stem != name:
            errors.append(f'Solution project entry invalid: {name}: {path}')
    if set(name for name, _ in solution_projects) != {p.stem for p in [*root.glob("src/**/*.csproj"), *root.glob("tests/**/*.csproj")]}:
        errors.append("Solution projects do not match the repository projects")

    editor = (root / '.editorconfig').read_text(encoding='utf-8')
    if 'csharp_style_namespace_declarations = file_scoped:error' not in editor:
        errors.append('Missing file-scoped namespace preference')
    if 'dotnet_diagnostic.IDE0161.severity = error' not in editor:
        errors.append('Missing IDE0161 enforcement')

    for name in ('TechnicalSpecification', 'Architecture', 'DecisionLog', 'Roadmap'):
        for suffix in ('.md', '.ru.md'):
            path = root / 'docs' / 'design' / f'Laveyana.Security.{name}{suffix}'
            if not path.is_file():
                errors.append(f'Missing design baseline: {path.relative_to(root)}')
    return errors


def self_test() -> None:
    valid = '''namespace Laveyana.Security.Tests;\nstring path = "https://example.com/Русский"; // English comment\nstring literal = @"// Русский";\nstring raw = """/* Русский */""";'''
    code, comments = scrub_csharp(valid)
    assert len(comments) == 1
    assert not NON_ASCII.search(''.join(comments))
    assert not BLOCK_NAMESPACE.search(code)
    invalid = 'namespace Laveyana.Security.Tests { /* Русский комментарий */ }'
    code, comments = scrub_csharp(invalid)
    assert BLOCK_NAMESPACE.search(code)
    assert NON_ASCII.search(''.join(comments))
    print('Checker self-test passed: comments, strings and namespace rules')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    errors = validate_projects(ROOT) + validate_sources(ROOT) + validate_build_policy(ROOT)
    if errors:
        for error in errors:
            print(f'ERROR: {error}', file=sys.stderr)
        return 1
    project_count = len([*ROOT.glob('src/**/*.csproj'), *ROOT.glob('tests/**/*.csproj')])
    source_count = len([*ROOT.glob('src/**/*.cs'), *ROOT.glob('tests/**/*.cs')])
    print(f'PASS: {project_count} projects; {source_count} C# sources; architecture graph, build policy, EN/RU docs, and source conventions verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
