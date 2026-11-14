#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Package release sources and upstream notices from the pinned dependency set."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import tarfile


RELEASE_HOSTS = {
    'linux': 'x86_64-pc-linux-gnu',
    'windows': 'x86_64-w64-mingw32',
    'macos': 'arm64-apple-darwin',
}

NON_NOTICE_SOURCE_STEMS = {
    'copyright_check', 'copyright_header', 'licence_info', 'license_check',
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def is_notice(name):
    path = PurePosixPath(name)
    return (bool(re.match(r'^(licen[cs]e|copying|copyright|notice|authors|patents|ftl|lgpl[23]?|gpl[v23]*)([._-].*)?$',
                          path.name, re.IGNORECASE))
            or path.name == 'qt_attribution.json'
            or any(part.lower() in ('licenses', 'licences') for part in path.parts[:-1]))


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('Unsafe archive path: ' + name)
    return path


def dependency_metadata(repo, host='x86_64-pc-linux-gnu', package_set='all_packages'):
    if package_set not in ('all_packages', 'packages'):
        raise ValueError('Invalid depends package set: ' + package_set)
    # Recipes reference $(package) lazily. Expand each recipe while that
    # variable names its own package, just as depends' build stages do.
    fields = ('version', 'file_name', 'sha256_hash', 'download_path')
    record = '|'.join(['$(package)'] + ['$($(package)_' + field + ')' for field in fields])
    rule = "release-source-metadata: ; @$(foreach package,$(" + package_set + "),printf '%s\\n' '" + record + "';)"
    output = subprocess.check_output(
        ['make', '-s', '-C', str(repo / 'depends'), 'HOST=' + host,
         '--eval', rule, 'release-source-metadata'], text=True)
    records = [line.split('|') for line in output.splitlines()]
    if any(len(record) != len(fields) + 1 for record in records):
        raise ValueError('Invalid depends metadata output')
    return [dict(zip(('package',) + fields, record)) for record in records]


def render_attribution(data):
    """Render Qt attribution metadata as a stable, human-readable notice."""
    decoded = data.decode('utf-8-sig')
    try:
        value = json.loads(decoded)
    except json.JSONDecodeError:
        # Some upstream Qt attribution files use literal line breaks inside
        # strings. Preserve those human-readable records without rewriting them.
        return decoded
    entries = value if isinstance(value, list) else [value]
    rendered = []
    fields = ('Name', 'Description', 'QtUsage', 'Homepage', 'Version',
              'Copyright', 'License', 'LicenseId', 'LicenseFile')
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Invalid Qt attribution metadata')
        lines = []
        for field in fields:
            item = entry.get(field)
            if item:
                if isinstance(item, list):
                    item = '; '.join(str(part) for part in item)
                lines.append(field + ': ' + str(item))
        if not lines:
            raise ValueError('Empty Qt attribution metadata')
        rendered.append('\n'.join(lines))
    return '\n\n'.join(rendered) + '\n'


def binary_notice_paths(licenses, components, platform):
    """Return the applicable collected notices for one binary target."""
    selected = []
    available = {path.name for path in (licenses / 'depends').iterdir() if path.is_dir()}
    missing = sorted(set(components) - available)
    if missing:
        raise ValueError('Missing binary dependency notices: ' + ', '.join(missing))

    for component in sorted(components):
        root = licenses / 'depends' / component
        for path in sorted(root.rglob('*')):
            if not path.is_file():
                continue
            if component == 'qt':
                relative = path.relative_to(root)
                # The release recipe builds qtbase only. macOS additionally
                # ships QtBase translation catalogs sourced from qttranslations.
                if len(relative.parts) < 2:
                    continue
                module = relative.parts[1]
                allowed = {'LICENSES', 'qtbase'}
                if platform == 'macos':
                    allowed.add('qttranslations')
                if module not in allowed:
                    continue
            selected.append(path)

    for category in ('rust', 'nito'):
        root = licenses / category
        if not root.is_dir():
            raise ValueError('Missing binary notice category: ' + category)
        selected.extend(path for path in sorted(root.rglob('*')) if path.is_file())
    return selected


def write_binary_notices(licenses, components, platform, destination):
    """Consolidate applicable notices into one deterministic text file."""
    sections = {}
    for path in binary_notice_paths(licenses, components, platform):
        if path.name in ('Cargo.toml', 'index.json', 'provenance.json'):
            continue
        relative = path.relative_to(licenses).as_posix()
        stem = path.stem.lower()
        if (relative in ('nito/COPYING', 'nito/LICENSE')
                or stem in NON_NOTICE_SOURCE_STEMS
                or stem.startswith('copyright-fail')
                or path.name == 'AUTHORS.sh'):
            continue
        data = path.read_bytes()
        if path.name == 'qt_attribution.json':
            text = render_attribution(data)
        else:
            try:
                text = data.decode('utf-8-sig')
            except UnicodeDecodeError:
                text = data.decode('latin-1')
        text = text.replace('\r\n', '\n').replace('\r', '\n').strip()
        if not text:
            continue
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        section = sections.setdefault(digest, {'text': text, 'paths': []})
        section['paths'].append(relative)

    if not sections:
        raise ValueError('No binary notices selected for ' + platform)

    lines = [
        'Nito Core third-party licenses and notices',
        '============================================',
        '',
        'This file contains notices for third-party components included in the',
        platform + ' release binaries. The matching source archive is published with',
        'the same Nito Core release at https://github.com/NitoNetwork/Nito-core/releases.',
        '',
        'Nito Core uses the Qt framework. Qt and its use are covered by the GNU',
        'Lesser General Public License version 3; the GNU GPL and LGPL texts are',
        'included below. The matching source archive includes the Qt source, Nito',
        'application source and build files needed to rebuild and relink the work.',
        '',
    ]
    ordered = sorted(sections.values(), key=lambda section: section['paths'][0])
    for section in ordered:
        lines.extend([
            '-' * 76,
            'Applies to:',
            *('  - ' + path for path in section['paths']),
            '-' * 76,
            section['text'],
            '',
        ])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text('\n'.join(lines), encoding='utf-8', newline='\n')


def copy_notice(destination, name, data):
    target = destination / safe_name(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def archive_notices(archive, destination):
    count = 0
    referenced = set()
    with tarfile.open(archive, 'r:*') as source:
        for member in source:
            if member.isfile() and is_notice(member.name):
                if member.size > 16 * 1024 * 1024:
                    raise ValueError('Unexpectedly large notice: ' + member.name)
                with source.extractfile(member) as stream:
                    data = stream.read()
                copy_notice(destination, member.name, data)
                if PurePosixPath(member.name).name == 'qt_attribution.json':
                    for filename in re.findall(r'"LicenseFile"\s*:\s*"([^"]+)"', data.decode('utf-8')):
                        referenced.add(posixpath.normpath(str(PurePosixPath(member.name).parent / filename)))
                count += 1
            elif archive.name.startswith('sqlite-autoconf-') and member.isfile() and PurePosixPath(member.name).name == 'sqlite3.h':
                with source.extractfile(member) as stream:
                    header = stream.read(4096)
                if not header.startswith(b'/*') or b'*/' not in header:
                    raise ValueError('SQLite copyright header not found')
                copy_notice(destination, member.name + '.notice.txt', header.split(b'*/', 1)[0] + b'*/\n')
                count += 1
    missing = {name for name in referenced if not (destination / safe_name(name)).is_file()}
    if missing:
        with tarfile.open(archive, 'r:*') as source:
            for member in source:
                if member.name in missing and member.isfile():
                    with source.extractfile(member) as stream:
                        copy_notice(destination, member.name, stream.read())
                    missing.remove(member.name)
                    count += 1
        if missing:
            raise ValueError('Missing referenced license files: ' + ', '.join(sorted(missing)))
    if not count:
        raise ValueError('No upstream notices found in ' + str(archive))
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path, required=True, help='New output directory')
    parser.add_argument('--sources', type=Path, help='Pre-downloaded depends source cache')
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9]+)*', args.version):
        parser.error('Invalid release version')
    repo = args.repo.resolve()
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], cwd=repo, check=True)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=repo, text=True))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    staging = output / 'staging'
    root = staging / ('nito-' + args.version)
    root.mkdir(parents=True)
    exported = output / 'source.tar'
    subprocess.run(['git', 'archive', '--format=tar', '-o', str(exported), revision], cwd=repo, check=True)
    # Extract only Git's regular files and directories; a release source tree
    # must not redirect output through archive links.
    with tarfile.open(exported) as archive:
        for member in archive:
            target = root / safe_name(member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('wb') as dest:
                    shutil.copyfileobj(source, dest)
                target.chmod(member.mode & 0o777)
            else:
                raise ValueError('Unsupported Git archive entry: ' + member.name)
    exported.unlink()

    packages = dependency_metadata(repo)
    binary_components = {
        platform: {item['package'] for item in dependency_metadata(repo, host, 'packages')}
        for platform, host in RELEASE_HOSTS.items()
    }
    cache = (args.sources or repo / 'depends/sources').resolve()
    notices = output / 'notices'
    notices.mkdir()
    licenses = notices / 'licenses'
    license_index = []
    manifest = {
        'version': args.version,
        'commit': revision,
        'depends': [],
        'rust': [],
        'binary_notice_components': {
            platform: sorted(components) for platform, components in binary_components.items()
        },
    }
    # Native tools and target libraries may share one archive. Use its target
    # package name for notices so their location is independent of build order.
    notice_packages = {item['file_name']: item['package']
                       for item in sorted(packages, key=lambda item: item['package'])}
    copied_archives = set()
    for item in sorted(packages, key=lambda item: item['package']):
        package = item['package']
        print('Packaging sources and notices: ' + package, flush=True)
        name = item['file_name']
        if PurePosixPath(name).name != name or not re.fullmatch(r'[0-9a-f]{64}', item['sha256_hash']):
            raise ValueError('Invalid dependency metadata for ' + package)
        archive = cache / name
        if sha256(archive) != item['sha256_hash']:
            raise ValueError('Source checksum mismatch: ' + name)
        manifest['depends'].append(item)
        if name in copied_archives:
            continue
        copied_archives.add(name)
        destination = root / 'depends/sources' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(archive, destination)
        notice_package = notice_packages[name]
        count = archive_notices(archive, licenses / 'depends' / notice_package)
        license_index.append({'component': notice_package, 'source': name, 'notices': count})

    crate = root / 'src/private/orchard_ffi'
    vendor = crate / 'vendor'
    subprocess.run(['cargo', 'vendor', '--locked', '--offline', '--versioned-dirs', str(vendor)],
                   cwd=crate, stdout=subprocess.DEVNULL, check=True)
    # Cargo discovers configuration from the working directory. Both the root
    # build and direct crate builds use the same vendored dependency sources.
    for directory, relative in ((root, 'src/private/orchard_ffi/vendor'), (crate, 'vendor')):
        config = directory / '.cargo/config.toml'
        config.parent.mkdir(exist_ok=True)
        if config.exists():
            raise ValueError('Refusing to replace Cargo configuration: ' + str(config))
        config.write_text('[source.crates-io]\nreplace-with = "vendored-sources"\n'
                          '[source.vendored-sources]\ndirectory = "' + relative + '"\n', encoding='utf-8')
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--offline', '--format-version=1'], cwd=crate, text=True))
    extra_notices = json.loads((root / 'contrib/release/extra-notices.json').read_text(encoding='utf-8'))
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if not package.get('source'):
            continue
        location = Path(package['manifest_path']).parent
        if not location.is_relative_to(vendor):
            raise ValueError('Cargo package not vendored: ' + package['name'])
        count = 0
        for path in sorted(location.rglob('*')):
            if path.is_file() and is_notice(path.relative_to(location).as_posix()):
                copy_notice(licenses / 'rust' / location.name, path.relative_to(location).as_posix(), path.read_bytes())
                count += 1
        manifest['rust'].append({key: package.get(key) for key in ('name', 'version', 'license', 'source')})
        if not count:
            extra = extra_notices.get(location.name)
            if not extra:
                raise ValueError('Review missing upstream license notices for Rust crate: ' + location.name)
            vcs = json.loads((location / '.cargo_vcs_info.json').read_text(encoding='utf-8'))
            if vcs['git']['sha1'] != extra['commit'] or package['repository'] != extra['repository']:
                raise ValueError('Upstream license provenance mismatch: ' + location.name)
            for notice in extra['files']:
                source = root / safe_name(notice['path'])
                if sha256(source) != notice['sha256']:
                    raise ValueError('Supplemental notice checksum mismatch: ' + notice['path'])
                copy_notice(licenses / 'rust' / location.name, source.name, source.read_bytes())
                count += 1
            copy_notice(licenses / 'rust' / location.name, 'provenance.json',
                        (json.dumps(extra, indent=2) + '\n').encode('utf-8'))
        license_index.append({'component': location.name, 'source': 'src/private/orchard_ffi/vendor/' + location.name,
                              'license': package.get('license'), 'notices': count})
        # Preserve the crate's own license expression alongside its notices.
        copy_notice(licenses / 'rust' / location.name, 'Cargo.toml', (location / 'Cargo.toml').read_bytes())

    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=repo).decode().split('\0')
    for name in names:
        if name and is_notice(name):
            copy_notice(licenses / 'nito', name, (root / name).read_bytes())
    shutil.copyfile(root / 'COPYING', notices / 'COPYING')
    shutil.copyfile(root / 'doc/release-sources.md', notices / 'SOURCE.md')
    for platform, components in sorted(binary_components.items()):
        write_binary_notices(
            licenses,
            components,
            platform,
            notices / 'binary' / platform / 'THIRD_PARTY_LICENSES.txt',
        )
    (licenses / 'index.json').write_text(json.dumps(license_index, indent=2) + '\n', encoding='utf-8')
    manifest_text = json.dumps(manifest, indent=2) + '\n'
    (notices / 'source-manifest.json').write_text(manifest_text, encoding='utf-8')
    shutil.copytree(notices, root / 'release-notices')
    (root / 'SOURCE.md').write_text((notices / 'SOURCE.md').read_text(encoding='utf-8'), encoding='utf-8')

    def normalize(member):
        member.uid = member.gid = 0
        member.uname = member.gname = ''
        member.mtime = epoch
        return member

    archive = output / ('nito-' + args.version + '-sources.tar.gz')
    with tarfile.open(archive, 'w:gz', compresslevel=1) as target:
        target.add(root, arcname=root.name, filter=normalize)
    (output / ('nito-' + args.version + '-sources.sha256')).write_text(
        sha256(archive) + '  ' + archive.name + '\n', encoding='utf-8')
    with tarfile.open(output / 'release-notices.tar.gz', 'w:gz') as target:
        for path in sorted(notices.iterdir()):
            target.add(path, arcname=path.name, filter=normalize)
    print(json.dumps({'archive': str(archive), 'commit': revision, 'dependencies': len(packages),
                      'rust_crates': len(manifest['rust']), 'sha256': sha256(archive)}))
    # Only remove the staging tree created by this invocation; retain outputs.
    shutil.rmtree(staging)


if __name__ == '__main__':
    main()
