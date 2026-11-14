#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fetch the official Nito Core release used by migration tests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile


TAG = 'v3.0.1'
# Published at https://github.com/NitoNetwork/Nito-core/releases/tag/v3.0.1
SHA256_SUMS = {
    'x86_64-linux-gnu': 'd12942540664e6968e7e6969084932813303680cf2382f3586c87eb62ed70235',
    'aarch64-linux-gnu': '2f7d81d2aeba5c551cc297b7c2d287204495f3f2850669ed51db20f3e712b0c7',
    'arm64-apple-darwin': '524f8b70c725b9b6cafb8edfb3995fdc925d4fb62c0c75f49868649e02f71871',
    'win64': 'ff585792bd6a835d082c192c4800522c0eb48702d2d7a600975079eb2e5dba0f',
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def native_platform():
    machine = platform.machine().lower()
    system = platform.system()
    if system == 'Windows' and machine in ('amd64', 'x86_64'):
        return 'win64'
    if system == 'Darwin' and machine in ('arm64', 'aarch64'):
        return 'arm64-apple-darwin'
    if system == 'Linux':
        return {'x86_64': 'x86_64-linux-gnu', 'aarch64': 'aarch64-linux-gnu'}.get(machine)
    return None


def download(args):
    target = args.target_dir.resolve()
    target.mkdir(parents=True, exist_ok=True)
    destination = target / TAG
    extension = '.exe' if args.platform == 'win64' else ''
    names = [name + extension for name in ('nitod', 'nito-cli', 'nito-tx', 'nito-util', 'nito-wallet')]
    expected = SHA256_SUMS[args.platform]
    manifest_path = destination / 'manifest.json'
    if destination.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if (manifest.get('tag') != TAG or manifest.get('platform') != args.platform or
                manifest.get('archive_sha256') != expected or set(manifest.get('binaries', {})) != set(names)):
            raise RuntimeError(f'{destination} contains a different release or platform')
        for name in names:
            if sha256(destination / 'bin' / name) != manifest['binaries'][name]:
                raise RuntimeError(f'Previously extracted binary changed: {name}')
        print(f'Verified existing {destination}')
        return

    suffix = '.zip' if args.platform == 'win64' else '.tar.gz'
    filename = f'nito-{TAG[1:]}-{args.platform}{suffix}'
    url = f'https://github.com/NitoNetwork/Nito-core/releases/download/{TAG}/{filename}'
    with tempfile.TemporaryDirectory(prefix='.nito-release-', dir=target) as temporary:
        work = Path(temporary).resolve()
        if work.parent != target:
            raise RuntimeError('Temporary release directory escaped target')
        archive_path = args.archive_dir / filename if args.archive_dir else work / filename
        if args.archive_dir is None:
            with urllib.request.urlopen(url, timeout=120) as response, archive_path.open('wb') as output:
                shutil.copyfileobj(response, output)
        if sha256(archive_path) != expected:
            raise RuntimeError(f'SHA256 mismatch for {filename}')
        staging = work / TAG
        binaries = staging / 'bin'
        binaries.mkdir(parents=True)
        copied = set()

        def copy_binary(name, source):
            basename = name.rsplit('/', 1)[-1]
            if basename not in names:
                return
            if basename in copied:
                raise RuntimeError(f'Duplicate binary in archive: {basename}')
            with (binaries / basename).open('wb') as output:
                shutil.copyfileobj(source, output)
            (binaries / basename).chmod(0o755)
            copied.add(basename)

        if suffix == '.zip':
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    if not member.is_dir() and member.filename.rsplit('/', 1)[-1] in names:
                        with archive.open(member) as source:
                            copy_binary(member.filename, source)
        else:
            with tarfile.open(archive_path) as archive:
                for member in archive:
                    if member.isfile() and member.name.rsplit('/', 1)[-1] in names:
                        with archive.extractfile(member) as source:
                            copy_binary(member.name, source)
        if copied != set(names):
            raise RuntimeError(f'Missing release binaries: {set(names) - copied}')
        manifest = {'tag': TAG, 'platform': args.platform, 'url': url, 'archive_sha256': expected,
                    'binaries': {name: sha256(binaries / name) for name in names}}
        (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        staging.rename(destination)
    print(f'Verified and extracted {destination}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-b', '--download-binary', action='store_true', help='Download the official binary archive (default)')
    parser.add_argument('-t', '--target-dir', type=Path, default=Path(os.getenv('PREVIOUS_RELEASES_DIR', 'releases')))
    parser.add_argument('--platform', choices=SHA256_SUMS, default=native_platform())
    parser.add_argument('--archive-dir', type=Path, help='Read a local archive and verify the same pinned checksum')
    parser.add_argument('tags', nargs='*', help=f'Supported release: {TAG}')
    args = parser.parse_args()
    if args.tags and args.tags != [TAG]:
        parser.error(f'Only the official Nito release {TAG} is supported')
    if args.platform is None:
        parser.error('No official archive for this host; select --platform explicitly')
    try:
        download(args)
    except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
