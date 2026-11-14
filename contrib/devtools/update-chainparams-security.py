#!/usr/bin/env python3
#
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify release security chainparams from signed P2P observer attestations.

Example:
  contrib/devtools/nito-chain-observer.py observe \
      --peer seed.nito.network --peer seed.nitopool.online \
      --observer-id observer-a --signing-key-stdin \
      --output observer-a.json < observer-a-key.hex

  contrib/devtools/update-chainparams-security.py \
      --attestation observer-a.json \
      --attestation observer-b.json \
      --attestation observer-c.json \
      --observer-key observer-a=<ed25519-public-key-hex> \
      --observer-key observer-b=<ed25519-public-key-hex> \
      --observer-key observer-c=<ed25519-public-key-hex> \
      --output chainparams-security.json
"""

import argparse
import datetime as _datetime
import json
import os
import re
import sys

from nito_chain_observer import AttestationError, aggregate_attestations, parse_observer_key


DEFAULT_CHAINPARAMS_PATH = os.path.join("src", "kernel", "chainparams.cpp")


def _read_current_minimum_chainwork(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    match = re.search(r"consensus\.nMinimumChainWork\s*=\s*uint256S\(\"0x([0-9a-fA-F]+)\"\)", text)
    if match is None:
        return None
    return match.group(1).lower().rjust(64, "0")


def _load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_report(report, output):
    text = json.dumps(report, indent=2, sort_keys=True)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)


def _trusted_observer_keys(parsed_keys):
    trusted_keys = {}
    for observer_id, public_key in parsed_keys:
        if observer_id in trusted_keys:
            raise AttestationError(f"duplicate trusted observer id {observer_id!r}")
        trusted_keys[observer_id] = public_key
    return trusted_keys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", action="append", required=True, help="Signed P2P observer attestation JSON file. Repeat for each known observer attestation.")
    parser.add_argument("--observer-key", action="append", type=parse_observer_key, required=True, help="Trusted known observer as OBSERVER_ID=PUBLIC_KEY_HEX. Repeat for the full known observer set.")
    parser.add_argument("--min-agree", type=int, help="Optional stricter observer agreement. It cannot be lower than ceil(2/3 of known observer keys).")
    parser.add_argument("--max-attestation-age", type=int, default=24 * 60 * 60, help="Maximum signed attestation age in seconds; use -1 to disable.")
    parser.add_argument("--minimum-chainwork", help="Reject signed P2P consensus below this chainwork hex value. Defaults to current src/kernel/chainparams.cpp when available.")
    parser.add_argument("--current-chainparams", default=DEFAULT_CHAINPARAMS_PATH, help=f"Path used to read the current nMinimumChainWork rollback guard, default {DEFAULT_CHAINPARAMS_PATH}.")
    parser.add_argument("--allow-chainwork-decrease", action="store_true", help="Disable the current-chainwork rollback guard.")
    parser.add_argument("--output", help="Optional JSON report path.")
    args = parser.parse_args()

    if args.min_agree is not None and args.min_agree < 1:
        parser.error("--min-agree must be positive")

    try:
        trusted_keys = _trusted_observer_keys(args.observer_key)
        minimum_chainwork = args.minimum_chainwork
        if minimum_chainwork is None and not args.allow_chainwork_decrease:
            minimum_chainwork = _read_current_minimum_chainwork(args.current_chainparams)
        report = aggregate_attestations(
            [_load_json_file(path) for path in args.attestation],
            trusted_keys,
            min_agree=args.min_agree,
            max_age=args.max_attestation_age,
            minimum_chainwork=minimum_chainwork,
        )
    except (AttestationError, OSError, json.JSONDecodeError) as exc:
        report = {
            "generated_at_utc": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
            "source": "signed-p2p-attestations",
            "consensus": None,
            "error": str(exc),
        }
        _write_report(report, args.output)
        print(f"ERROR: cannot verify signed P2P observer consensus: {exc}", file=sys.stderr)
        return 1

    _write_report(report, args.output)
    if report.get("mismatches"):
        print("WARNING: signed observers did not all agree; accepted the configured 2/3 threshold", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
