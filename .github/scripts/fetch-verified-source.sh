#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <output-file> <expected-sha256> <url> [url...]" >&2
  exit 2
fi

output_file="$1"
expected_sha256="$2"
shift 2

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi

  echo "ERROR: neither sha256sum nor shasum is available" >&2
  exit 2
}

rm -f "$output_file"

for url in "$@"; do
  echo "Fetching ${url}"
  if curl \
    --fail \
    --location \
    --show-error \
    --silent \
    --retry 6 \
    --retry-delay 5 \
    --retry-all-errors \
    --connect-timeout 30 \
    --max-time 300 \
    --proto '=https' \
    --tlsv1.2 \
    -o "$output_file" \
    "$url"; then
    actual_sha256="$(sha256_file "$output_file")"
    if [ "$actual_sha256" = "$expected_sha256" ]; then
      echo "Verified ${output_file}: ${actual_sha256}"
      exit 0
    fi

    echo "ERROR: SHA256 mismatch for ${output_file}" >&2
    echo "  expected: ${expected_sha256}" >&2
    echo "  actual:   ${actual_sha256}" >&2
    rm -f "$output_file"
    exit 1
  fi

  echo "Fetch failed from ${url}" >&2
  rm -f "$output_file"
done

echo "ERROR: failed to download ${output_file}" >&2
exit 1
