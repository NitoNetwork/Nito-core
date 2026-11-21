#!/usr/bin/env bash
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying file COPYING.

set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "usage: $0 TAG VERSION EXPECTED_COMMIT [ALLOWED_SIGNERS_FILE]" >&2
    exit 2
fi

tag_name="$1"
version="$2"
expected_commit="$3"
allowed_signers="${4:-contrib/release/nito-core-tag-signers}"

fail() {
    echo "release tag verification failed: $*" >&2
    exit 1
}

[ "$tag_name" = "v${version}" ] || \
    fail "tag ${tag_name} does not match version ${version}"
[ -s "$allowed_signers" ] || \
    fail "allowed signers file is missing or empty: ${allowed_signers}"

tag_ref="refs/tags/${tag_name}"
tag_type="$(git cat-file -t "$tag_ref" 2>/dev/null || true)"
[ "$tag_type" = "tag" ] || \
    fail "${tag_name} must be an annotated tag object"

tag_object="$(git rev-parse "${tag_ref}^{tag}")"
tag_commit="$(git rev-parse "${tag_ref}^{commit}")"
expected_commit="$(git rev-parse "${expected_commit}^{commit}")"
[ "$tag_commit" = "$expected_commit" ] || \
    fail "${tag_name} targets ${tag_commit}, expected ${expected_commit}"

verification_output="$(
    git \
        -c gpg.format=ssh \
        -c gpg.ssh.allowedSignersFile="$allowed_signers" \
        verify-tag --raw "$tag_ref" 2>&1
)" || {
    printf '%s\n' "$verification_output" >&2
    fail "${tag_name} is unsigned or was signed by an unexpected key"
}
printf '%s\n' "$verification_output"
printf 'Verified annotated release tag %s\n' "$tag_name"
printf 'Tag object: %s\n' "$tag_object"
printf 'Tag commit: %s\n' "$tag_commit"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        printf 'tag_object=%s\n' "$tag_object"
        printf 'tag_commit=%s\n' "$tag_commit"
    } >> "$GITHUB_OUTPUT"
fi
