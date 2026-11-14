#!/usr/bin/env python3
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Enforce the locked, offline Orchard FFI build contract."""

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "src/private/orchard_ffi/Cargo.toml"
LOCKFILE = ROOT / "src/private/orchard_ffi/Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
RELEASE_WORKFLOW = ROOT / ".github/workflows/build-release.yml"

EXPECTED_DIRECT_DEPENDENCIES = {
    "chacha20": "0.9.1",
    "incrementalmerkletree": "0.8.2",
    "nonempty": "0.11.0",
    "orchard": "0.15.0",
    "rand_core": "0.6.4",
    "zcash_note_encryption": "0.4.1",
}


def fail(message: str) -> None:
    print(f"lint-cargo-reproducibility.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(pattern: str, text: str, context: str) -> None:
    if re.search(pattern, text, flags=re.MULTILINE) is None:
        fail(f"missing {context}")


def workflow_job(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        fail(f"missing {name} release workflow job")
    return match.group("body")


def require_locked_fetch_before_offline_build(job: str, context: str) -> None:
    fetch_marker = "- name: Fetch locked Orchard dependencies"
    build_marker = "- name: Build Nito"
    fetch_position = job.find(fetch_marker)
    build_position = job.find(build_marker)
    if fetch_position < 0:
        fail(f"missing explicit locked Cargo fetch for {context}")
    if build_position < 0:
        fail(f"missing Nito build step for {context}")
    if fetch_position > build_position:
        fail(f"locked Cargo fetch must precede the {context} build")

    fetch_step = job[fetch_position:build_position]
    require(
        r"cargo fetch --locked --manifest-path src/private/orchard_ffi/Cargo\.toml",
        fetch_step,
        f"network-enabled locked Cargo fetch command for {context}",
    )
    if "--target" in fetch_step:
        fail(f"{context} Cargo fetch must include host and target dependencies")

    next_step = job.find("\n      - name:", build_position + len(build_marker))
    build_step = job[build_position:] if next_step < 0 else job[build_position:next_step]
    require(
        r'^\s+CARGO_NET_OFFLINE:\s*"true"\s*$',
        build_step,
        f"offline Cargo environment for {context}",
    )


if not TOOLCHAIN.is_file():
    fail("rust-toolchain.toml is required at the repository root")

toolchain = TOOLCHAIN.read_text(encoding="utf-8")
require(r'^channel\s*=\s*"1\.97\.0"\s*$', toolchain, "pinned Rust 1.97.0 channel")
require(r'^profile\s*=\s*"minimal"\s*$', toolchain, "minimal Rust profile")
require(r'^components\s*=\s*\[\s*"rustfmt"\s*\]\s*$', toolchain, "rustfmt component")

manifest = MANIFEST.read_text(encoding="utf-8")
lockfile = LOCKFILE.read_text(encoding="utf-8")
require(
    r'(?ms)^\[profile\.release\]\s*$.*?^panic\s*=\s*"unwind"\s*$',
    manifest,
    'release panic strategy "unwind"',
)
for variable in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
    flags = os.environ.get(variable, "").replace("\x1f", " ")
    if re.search(r"(?:^|\s)-C\s*panic=abort(?:\s|$)", flags):
        fail(f"{variable} must not override the release panic strategy with panic=abort")
for name, version in EXPECTED_DIRECT_DEPENDENCIES.items():
    manifest_pattern = rf'^{re.escape(name)}\s*=.*(?:version\s*=\s*)?"={re.escape(version)}"'
    require(manifest_pattern, manifest, f"exact {name} {version} manifest pin")
    lock_pattern = (
        rf'(?ms)^\[\[package\]\]\s*\nname\s*=\s*"{re.escape(name)}"\s*\n'
        rf'version\s*=\s*"{re.escape(version)}"\s*$'
    )
    require(lock_pattern, lockfile, f"locked {name} {version} package")

makefile = (ROOT / "src/Makefile.am").read_text(encoding="utf-8")
require(
    r'^NITO_ORCHARD_FFI_CARGO_ENV=env -u CARGO_MAKEFLAGS -u MAKEFLAGS -u MFLAGS$',
    makefile,
    "Autotools Cargo isolation from the Make jobserver",
)
require(
    r'\$\(NITO_ORCHARD_FFI_CARGO_ENV\) cargo fetch --locked',
    makefile,
    "complete locked Autotools Cargo fetch outside the Make jobserver",
)
require(
    r'\$\(NITO_ORCHARD_FFI_CARGO_ENV\) cargo build --jobs 1 '
    r'--release --locked --offline \$\(NITO_ORCHARD_FFI_CARGO_TARGET_ARG\)',
    makefile,
    "single-job locked offline Autotools Cargo build outside the Make jobserver",
)
require(
    r'\$\(top_srcdir\)/rust-toolchain\.toml',
    makefile,
    "Autotools dependency on rust-toolchain.toml",
)

msvc = (ROOT / "build_msvc/common.init.vcxproj.in").read_text(encoding="utf-8")
require(r'cargo fetch --locked', msvc, "locked MSVC Cargo fetch")
require(
    r'cargo build --release --locked --offline',
    msvc,
    "locked offline MSVC Cargo build",
)
require(r'rust-toolchain\.toml', msvc, "MSVC dependency on rust-toolchain.toml")

top_makefile = (ROOT / "Makefile.am").read_text(encoding="utf-8")
require(r'^\s*rust-toolchain\.toml\s*(?:\\)?$', top_makefile, "toolchain in source distribution")

release_workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
linux_job = workflow_job(release_workflow, "linux")
require(r"target:\s+linux-x86_64", linux_job, "Linux x86_64 release target")
require(r"target:\s+linux-aarch64", linux_job, "Linux aarch64 release target")
require_locked_fetch_before_offline_build(linux_job, "Linux x86_64/aarch64")

windows_job = workflow_job(release_workflow, "windows")
require_locked_fetch_before_offline_build(windows_job, "Windows x86_64")

macos_job = workflow_job(release_workflow, "macos-arm64")
require_locked_fetch_before_offline_build(macos_job, "macOS arm64")
