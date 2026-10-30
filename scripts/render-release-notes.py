#!/usr/bin/env python3
"""Render versioned EN/RU release notes and a separate exact-artifact provenance section."""
from pathlib import Path
import argparse
import hashlib
import re
import stat


def render(root, tag, source, producer, handoff, asset, archive_sha256):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('Stable version tag required')
    for value in (source, producer, handoff):
        if not re.fullmatch(r'[a-f0-9]{40}', value):
            raise ValueError('Exact commit identity required')
    if asset != f'foxhole-core-{tag}.tar.gz' or not re.fullmatch(r'[a-f0-9]{64}', archive_sha256):
        raise ValueError('Exact canonical archive identity required')
    sections = []
    hashes = []
    for language in ('en', 'ru'):
        relative = Path('docs/releases') / f'{tag}.{language}.md'
        path = root / relative
        if path.is_symlink():
            raise ValueError('Release notes must be a source file')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 65536:
            raise ValueError('Release notes exceed their bounded file role')
        raw = path.read_bytes()
        if len(raw) != info.st_size:
            raise ValueError('Release notes changed while reading')
        sections.append(raw.decode('utf-8').strip())
        hashes.append((relative.as_posix(), hashlib.sha256(raw).hexdigest()))
    provenance = [
        '## Provenance',
        '',
        f'- Delivery source commit: `{source}`',
        f'- Compiled producer commit: `{producer}`',
        f'- Owner-signed LAB handoff commit: `{handoff}`',
        f'- Verified archive: `{asset}`',
        f'- Archive SHA-256: `{archive_sha256}`',
    ]
    provenance.extend(f'- Notes `{path}` SHA-256: `{digest}`' for path, digest in hashes)
    return '\n\n---\n\n'.join([*sections, '\n'.join(provenance)]) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tag', 'source', 'producer', 'handoff', 'asset', 'archive-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    body = render(Path(__file__).resolve().parent.parent, args.tag, args.source, args.producer,
                  args.handoff, args.asset, args.archive_sha256)
    args.output.write_text(body, encoding='utf-8')


if __name__ == '__main__':
    main()
