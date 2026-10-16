#!/usr/bin/env python3
"""Check documentation inventory, relative links, decision numbering, and critical status parity.

This is structural verification, NOT a semantic audit, .NET compilation, or security review.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / 'docs' / 'design'
DESIGN_NAMES = ('TechnicalSpecification', 'Architecture', 'Roadmap', 'DecisionLog',
                'HpkeGate', 'StreamingGate')
EXPECTED_SKIPPED_DECISIONS = {1, 2, 3, 26, 28, 29, 30}
PUBLIC_API_ANCHORS = (
    'IKeyStore', 'IKeyStoreProtector', 'ProviderRegistry',
    'SoftwareKeyProviderBackend', 'SensitiveMaterialLease',
    'AeadNoncePolicyEngine', 'EncryptedPayload',
    'IManagedMacBackend', 'IManagedSignatureBackend',
    'IManagedKeyAgreementBackend', 'IManagedDerivationBackend',
    'IStreamingMacBackend', 'ISecretProvider', 'SecretProviderRegistry',
    'SecurityCompositionBuilder', 'RotationEngine',
    'ProviderMigrationOrchestrator', 'SecurityObservability',
)


def docs() -> list[Path]:
    """Repository-facing Markdown documents. Internal instruction artifacts are not public docs."""
    return ([ROOT / 'README.md', ROOT / 'README.ru.md',
             ROOT / 'CHANGELOG.md', ROOT / 'CHANGELOG.ru.md'] +
            sorted((ROOT / 'docs').rglob('*.md')))


def links_in(text: str) -> list[str]:
    # Remove fenced examples; code snippets may deliberately include fake paths.
    stripped = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
    return re.findall(r'(?<!!)\[[^\]]+\]\(([^\)]+)\)', stripped)


def verify() -> list[str]:
    errors: list[str] = []
    for p in docs():
        if not p.is_file():
            errors.append(f'Missing document: {p.relative_to(ROOT)}')
            continue
        # Each human-readable Markdown document has an equally maintained language pair.
        counterpart = p.with_name(p.name[:-6] + '.md') if p.name.endswith('.ru.md') \
            else p.with_name(p.stem + '.ru.md')
        if not counterpart.is_file():
            errors.append(f'Missing language counterpart for {p.relative_to(ROOT)}')
        content = p.read_text(encoding='utf-8')
        if not content.startswith('# '):
            errors.append(f'Missing heading in {p.relative_to(ROOT)}')
        for target in links_in(content):
            dest = target.split('#')[0].strip()
            if dest and not dest.startswith(('http:', 'https:', 'mailto:')) and not (p.parent / dest).is_file():
                errors.append(f'Broken relative link in {p.relative_to(ROOT)}: {target}')

    source = '\n'.join(p.read_text(encoding='utf-8') for p in ROOT.glob('src/**/*.cs'))
    for token in PUBLIC_API_ANCHORS:
        if not re.search(r'\b(?:class|interface|struct|record)\s+' + token + r'\b', source):
            errors.append(f'Undeclared documented API symbol: {token}')

    decision_ids: list[set[int]] = []
    for suffix in ('.md', '.ru.md'):
        p = DESIGN / f'Laveyana.Security.DecisionLog{suffix}'
        if not p.is_file():
            continue
        text = p.read_text(encoding='utf-8')
        found = [int(n) for n in re.findall(r'^## D(\d+)\.', text, flags=re.MULTILINE)]
        if len(found) != len(set(found)):
            errors.append(f'Duplicate decision ID in {p.name}')
        missing = set(range(1, 58)) - set(found)
        if missing != EXPECTED_SKIPPED_DECISIONS:
            errors.append(f'Unexpected Decision Log coverage in {p.name}: {sorted(missing)}')
        decision_ids.append(set(found))
    if len(decision_ids) == 2 and decision_ids[0] != decision_ids[1]:
        errors.append('EN/RU Decision Log ID sets differ')

    for suffix in ('.md', '.ru.md'):
        p = DESIGN / f'Laveyana.Security.Roadmap{suffix}'
        if not p.is_file():
            continue
        contents = p.read_text(encoding='utf-8')
        phases = set(re.findall(r'^## Phase (\d+A?)\s+—', contents, re.MULTILINE))
        expected = {str(n) for n in range(1, 28)} | {'14A'}
        if not expected.issubset(phases):
            errors.append(f'Missing roadmap phase headings in {p.name}: {sorted(expected - phases)}')

    status_markers = {
        'README.md': ('Phase 27', 'pre-release', 'experimental', 'Windows', 'Ubuntu', 'MIT'),
        'README.ru.md': ('Phase 27', 'экспериментальным', 'Windows', 'Ubuntu', 'MIT'),
        'CHANGELOG.md': ('Phase 26', 'Phase 27', 'HPKE', 'AEAD', 'Unreleased'),
        'CHANGELOG.ru.md': ('Phase 26', 'Phase 27', 'HPKE', 'AEAD', 'Не выпущено'),
    }
    for name, markers in status_markers.items():
        p = ROOT / name
        if not p.is_file():
            continue
        text = p.read_text(encoding='utf-8')
        for marker in markers:
            if marker not in text:
                errors.append(f'Missing critical status marker {marker!r} in {name}')
    return errors


def self_test() -> None:
    assert links_in('[one](file.md) ![image](image.png) `code`') == ['file.md']
    assert links_in('```md\n[example](fake.md)\n```\n[real](real.md)') == ['real.md']
    assert set(range(1, 58)) - EXPECTED_SKIPPED_DECISIONS == {
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 27, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57}
    print('Documentation checker self-test passed')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test', action='store_true')
    args = p.parse_args()
    if args.self_test:
        self_test()
        return 0
    errors = verify()
    for error in errors:
        print('ERROR:', error, file=sys.stderr)
    if errors:
        return 1
    print('PASS: EN/RU docs, relative links, public symbols, decision coverage, roadmap phases, and critical statuses')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
