#!/usr/bin/env bash
# This script is intentionally locale dependent by not setting "export LC_ALL=C"
set -euo pipefail

log_file="${WARNING_CLEAN_LOG:-build.log}"
scan_file="${log_file}.warning-scan"
diagnostic_scan_file="${scan_file}.diagnostics"
rm -f "$log_file"
rm -f "$scan_file"
rm -f "$diagnostic_scan_file"
trap 'rm -f "$scan_file" "$diagnostic_scan_file"' EXIT

set +e
"$@" 2>&1 | tee "$log_file"
pipeline_status=("${PIPESTATUS[@]}")
set -e

if [ "${pipeline_status[0]}" -ne 0 ]; then
  exit "${pipeline_status[0]}"
fi

if [ "${pipeline_status[1]}" -ne 0 ]; then
  echo "::error title=Incomplete build log::Cannot verify diagnostics because tee failed to preserve the command output. See ${log_file}." >&2
  exit "${pipeline_status[1]}"
fi

# Cargo and several compilers color diagnostic labels. Strip only ANSI terminal
# control sequences in the temporary scan copy; keep the original log intact.
LC_ALL=C sed $'s/\033\[[0-9;]*m//g' "$log_file" > "$scan_file"

# curl reports a recovered HTTP or timeout retry as a warning even when the
# download ultimately succeeds. Keep it in the original log, but do not
# classify that exact transport notice as a compiler/build diagnostic. A failed
# download is still fatal through the command status checked above.
# With --retry-all-errors the notice switches to a generic wording and wraps
# across two lines ("... N retries " / "Warning: left."); both physical lines
# are excluded with strict anchors so any other diagnostic still fails the run.
LC_ALL=C sed -E \
  -e '/^Warning: Problem : (HTTP error|timeout)\. Will retry in [0-9]+ seconds?\. [0-9]+ (retry|retries) left\.$/d' \
  -e '/^Warning: Problem \(retrying all errors\)\. Will retry in [0-9]+ seconds?\. [0-9]+ retries $/d' \
  -e '/^Warning: left\.$/d' \
  "$scan_file" > "$diagnostic_scan_file"

if grep -nEi '(^|[[:space:]:])warn(ing)?s?:|[0-9]+ warnings? generated\.|^[[:space:]]*CMake (Deprecation )?Warning|^[[:space:]]*fatal:' "$diagnostic_scan_file"; then
  echo "::error title=Build emitted diagnostics::This release path must not emit warnings or fatal diagnostics. See ${log_file} lines above."
  exit 1
fi

if grep -nE 'Detected locale ".+" with character encoding ".+", which is not UTF-8\.|Qt depends on a UTF-8 locale' "$scan_file"; then
  echo "::error title=Build emitted locale noise::Qt tools must run with a UTF-8 locale. See ${log_file} lines above."
  exit 1
fi
