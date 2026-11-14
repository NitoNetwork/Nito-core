#!/usr/bin/env python3
#
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import copy
import socket
import threading
import time
import unittest

import nito_chain_observer as observer


def make_payload(observer_id, *, height=100, block_hash=None, chainwork=None, peer_count=2, min_peer_agreement=None, generated_at=None):
    block_hash = block_hash or "00" * 31 + f"{height:02x}"
    chainwork = chainwork or f"{height + 1000:064x}"
    generated_at = int(time.time()) if generated_at is None else generated_at
    if min_peer_agreement is None:
        min_peer_agreement = observer.two_thirds_threshold(peer_count)
    peer_observations = [
        {
            "peer": f"127.0.0.{index}:8820",
            "height": height,
            "hash": block_hash,
            "chainwork": chainwork,
            "time": 1724234444 + height * 60,
            "nbits": "1d00ffff",
        }
        for index in range(1, peer_count + 1)
    ]
    return {
        "schema": observer.ATTESTATION_SCHEMA,
        "network": "mainnet",
        "observer_id": observer_id,
        "generated_at_unix": generated_at,
        "generated_at_utc": "2026-05-15T00:00:00+00:00",
        "selection": {"height_source": "manual", "selected_height": height},
        "peer_threshold_model": "ceil(2/3 of known P2P peers)",
        "known_peer_count": peer_count,
        "known_peers": [item["peer"] for item in peer_observations],
        "minimum_required_peer_agreement": min_peer_agreement,
        "peer_observations": peer_observations,
        "tip_observations": [],
        "peer_mismatches": False,
        "agreement": {
            "peer_count": peer_count,
            "peer_names": [item["peer"] for item in peer_observations],
            "height": height,
            "hash": block_hash,
            "chainwork": chainwork,
            "time": 1724234444 + height * 60,
            "nbits": "1d00ffff",
        },
    }


class SignedP2PObserverTests(unittest.TestCase):
    def setUp(self):
        self.keys = {
            "observer-a": observer.generate_keypair(),
            "observer-b": observer.generate_keypair(),
            "observer-c": observer.generate_keypair(),
        }
        self.trusted = {name: keypair["public_key"] for name, keypair in self.keys.items()}

    def sign(self, observer_id, **kwargs):
        return observer.sign_payload(make_payload(observer_id, **kwargs), self.keys[observer_id]["private_key"])

    def test_valid_signature_and_two_of_three_agreement(self):
        attestations = [
            self.sign("observer-a"),
            self.sign("observer-b"),
            self.sign("observer-c", height=99),
        ]
        report = observer.aggregate_attestations(attestations, self.trusted, max_age=60)
        self.assertEqual(report["consensus"]["agreement_count"], 2)
        self.assertEqual(report["consensus"]["observer_ids"], ["observer-a", "observer-b"])
        self.assertTrue(report["mismatches"])

    def test_networks_cannot_be_mixed(self):
        payload = make_payload('observer-b')
        payload['network'] = 'testnet3'
        wrong_network = observer.sign_payload(payload, self.keys['observer-b']['private_key'])
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations([self.sign('observer-a'), wrong_network], self.trusted)

    def test_aliases_cannot_count_one_signer_twice(self):
        trusted = {'observer-a': self.trusted['observer-a'], 'alias': self.trusted['observer-a']}
        alias = observer.sign_payload(make_payload('alias'), self.keys['observer-a']['private_key'])
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations([self.sign('observer-a'), alias], trusted)

    def test_invalid_signed_anchor_fields_are_rejected(self):
        for field, value in [('hash', 'x' * 64), ('chainwork', '-1'), ('height', True), ('time', 1.5), ('nbits', 'zzzzzzzz')]:
            payload = make_payload('observer-a')
            payload['agreement'][field] = value
            attestation = observer.sign_payload(payload, self.keys['observer-a']['private_key'])
            with self.subTest(field=field), self.assertRaises(observer.AttestationError):
                observer.aggregate_attestations([attestation], {'observer-a': self.trusted['observer-a']})

    def test_v4_header_client_services(self):
        peer = observer.PeerAddress('127.0.0.1', 8820)
        info = observer.parse_version_payload(observer.build_version_payload(peer))
        self.assertEqual(info['version'], 70017)
        self.assertTrue(info['services'] & observer.NODE_NITO_PRIVATE)
        self.assertFalse(info['services'] & observer.NODE_NETWORK)

    def test_regtest_minimum_difficulty_precedes_no_retargeting(self):
        network = observer.NETWORKS['regtest']
        previous = observer.genesis_state(network)
        self.assertEqual(observer.next_work_required(previous, None, previous.time + 121, network), 0x207fffff)

    def test_observer_threshold_is_two_thirds_of_known_keys(self):
        fourth = observer.generate_keypair()
        trusted = dict(self.trusted)
        trusted["observer-d"] = fourth["public_key"]
        attestations = [
            self.sign("observer-a"),
            self.sign("observer-b"),
            self.sign("observer-c", height=99),
        ]
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(attestations, trusted, max_age=60)
        attestations.append(observer.sign_payload(make_payload("observer-d"), fourth["private_key"]))
        report = observer.aggregate_attestations(attestations, trusted, max_age=60)
        self.assertEqual(report["minimum_required_observer_agreement"], 3)
        self.assertEqual(report["consensus"]["agreement_count"], 3)

    def test_cannot_lower_observer_threshold_below_two_thirds(self):
        fourth = observer.generate_keypair()
        trusted = dict(self.trusted)
        trusted["observer-d"] = fourth["public_key"]
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations([self.sign("observer-a"), self.sign("observer-b")], trusted, min_agree=2, max_age=60)

    def test_bad_signature_is_rejected(self):
        attestation = self.sign("observer-a")
        tampered = copy.deepcopy(attestation)
        tampered["payload"]["agreement"]["hash"] = "11" * 32
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations([tampered], {"observer-a": self.trusted["observer-a"]}, min_agree=1, max_age=60)

    def test_stale_attestation_is_rejected(self):
        old = int(time.time()) - 10_000
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [self.sign("observer-a", generated_at=old)],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
            )

    def test_disagreement_without_two_of_three_is_rejected(self):
        attestations = [
            self.sign("observer-a", height=100),
            self.sign("observer-b", height=101),
            self.sign("observer-c", height=102),
        ]
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(attestations, self.trusted, max_age=60)

    def test_chainwork_rollback_is_rejected(self):
        attestation = self.sign("observer-a", chainwork=f"{100:064x}")
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
                minimum_chainwork=f"{101:064x}",
            )

    def test_insufficient_peer_agreement_is_rejected(self):
        attestation = self.sign("observer-a", peer_count=1, min_peer_agreement=2)
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
                min_peer_agree=2,
            )

    def test_peer_threshold_is_two_thirds_of_known_peers(self):
        attestation = self.sign("observer-a", peer_count=4, min_peer_agreement=2)
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
            )

    def test_cannot_lower_peer_threshold_below_two_thirds(self):
        attestation = self.sign("observer-a", peer_count=4)
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
                min_peer_agree=2,
            )

    def test_known_peer_count_must_match_observations(self):
        payload = make_payload("observer-a", peer_count=4)
        payload["known_peer_count"] = 2
        payload["minimum_required_peer_agreement"] = 2
        attestation = observer.sign_payload(payload, self.keys["observer-a"]["private_key"])
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
            )

    def test_peer_agreement_is_recomputed_from_observations(self):
        payload = make_payload("observer-a", peer_count=4)
        payload["peer_observations"][0]["height"] = 99
        attestation = observer.sign_payload(payload, self.keys["observer-a"]["private_key"])
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
            )

    def test_duplicate_peer_observations_are_rejected(self):
        payload = make_payload("observer-a", peer_count=3)
        payload["peer_observations"][1]["peer"] = payload["peer_observations"][0]["peer"]
        attestation = observer.sign_payload(payload, self.keys["observer-a"]["private_key"])
        with self.assertRaises(observer.AttestationError):
            observer.aggregate_attestations(
                [attestation],
                {"observer-a": self.trusted["observer-a"]},
                min_agree=1,
                max_age=60,
            )

    def test_duplicate_trusted_observer_keys_are_rejected(self):
        with self.assertRaises(observer.AttestationError):
            observer.parse_trusted_observer_keys([
                f"observer-a={self.trusted['observer-a']}",
                f"observer-a={self.trusted['observer-a']}",
            ])

    def test_pow_helpers_match_genesis_target(self):
        network = observer.NETWORKS["mainnet"]
        state = observer.genesis_state(network)
        self.assertEqual(state.hash_hex, network.genesis_hash)
        self.assertGreater(state.chainwork, 0)
        self.assertTrue(observer.check_proof_of_work(state.hash_int, state.bits, network))

    def test_observe_peer_reads_and_validates_headers(self):
        network = observer.NetworkConfig(
            name="localtest",
            magic=b"\xfa\xbf\xb5\xda",
            default_port=0,
            genesis_hash="0" * 64,
            genesis_time=1_724_000_000,
            genesis_bits=0x207FFFFF,
            pow_limit=observer.target_from_compact(0x207FFFFF)[0],
            target_spacing=60,
            allow_min_difficulty=True,
            no_retargeting=True,
        )
        header = solve_easy_header(network)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        ready = threading.Event()
        errors = []

        def server():
            ready.set()
            try:
                conn, _addr = listener.accept()
                with conn:
                    conn.settimeout(5)
                    command, _payload = observer.read_message(conn, network)
                    self.assertEqual(command, "version")
                    peer = observer.PeerAddress("127.0.0.1", port)
                    observer.send_message(conn, "version", observer.build_version_payload(peer), network)
                    command, _payload = observer.read_message(conn, network)
                    self.assertEqual(command, "verack")
                    observer.send_message(conn, "verack", b"", network)
                    command, _payload = observer.read_message(conn, network)
                    self.assertEqual(command, "getheaders")
                    payload = observer.ser_compact_size(1) + header + observer.ser_compact_size(0)
                    observer.send_message(conn, "headers", payload, network)
            except Exception as exc:  # pragma: no cover - surfaced after join
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=server)
        thread.start()
        self.assertTrue(ready.wait(5))
        result = observer.observe_peer(observer.PeerAddress("127.0.0.1", port), network, timeout=5, stop_height=1)
        thread.join(5)
        self.assertFalse(errors)
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["headers_downloaded"], 1)


def solve_easy_header(network):
    bits = 0x207FFFFF
    nonce = 0
    while True:
        raw = (
            (1).to_bytes(4, "little", signed=True)
            + (0).to_bytes(32, "little")
            + (0).to_bytes(32, "little")
            + (network.genesis_time + 60).to_bytes(4, "little")
            + bits.to_bytes(4, "little")
            + nonce.to_bytes(4, "little")
        )
        *_unused, hash_int, _hash_hex = observer.parse_header(raw)
        if observer.check_proof_of_work(hash_int, bits, network):
            return raw
        nonce += 1


if __name__ == "__main__":
    unittest.main()
