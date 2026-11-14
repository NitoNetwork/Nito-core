#!/usr/bin/env python3
#
# Copyright (c) 2026 The Nito Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2P chain observer and signed-attestation verifier for Nito release anchors.

The observer deliberately uses the public P2P protocol, not JSON-RPC. It
downloads headers from independent peers, verifies header proof-of-work and
Nito's one-block difficulty adjustment, recomputes chainwork, then signs a
canonical attestation. Release tooling requires agreement from at least
ceil(2/3) of the configured trusted observer set before refreshing
nMinimumChainWork and defaultAssumeValid.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import ipaddress
import json
import random
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


ATTESTATION_SCHEMA = "nito-chain-observer-attestation-v1"
SIGNATURE_ALGORITHM = "ed25519"
P2P_VERSION = 70017
NODE_NETWORK = 1 << 0
NODE_WITNESS = 1 << 3
NODE_NITO_PRIVATE = 1 << 24
# V4-aware header client; it does not advertise full block serving.
OBSERVER_SERVICES = NODE_WITNESS | NODE_NITO_PRIVATE
MAX_PROTOCOL_MESSAGE_LENGTH = 4_000_000
MAX_HEADERS_RESULTS = 2000
DEFAULT_CONFIRMATIONS = 100
DEFAULT_MAX_TIP_LAG = 120
DEFAULT_TIMEOUT = 30


class ObserverError(RuntimeError):
    pass


class AttestationError(RuntimeError):
    pass


@dataclass(frozen=True)
class NetworkConfig:
    name: str
    magic: bytes
    default_port: int
    genesis_hash: str
    genesis_time: int
    genesis_bits: int
    pow_limit: int
    target_spacing: int
    allow_min_difficulty: bool
    no_retargeting: bool


NETWORKS: Dict[str, NetworkConfig] = {
    "mainnet": NetworkConfig(
        name="mainnet",
        magic=bytes.fromhex("b6c0c0b6"),
        default_port=8820,
        genesis_hash="00000000103d1acbedc9bb8ff2af8cb98a751965e784b4e1f978f3d5544c6c3c",
        genesis_time=1724234444,
        genesis_bits=0x1D00FFFF,
        pow_limit=int("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
        target_spacing=60,
        allow_min_difficulty=False,
        no_retargeting=False,
    ),
    "testnet3": NetworkConfig(
        name="testnet3",
        magic=bytes.fromhex("b6b6b6db"),
        default_port=8840,
        genesis_hash="00000000ddbcc1487e98d0e27fcc235129c543e6b6066df0cc0d157a0e02312b",
        genesis_time=1723939322,
        genesis_bits=0x1D00FFFF,
        pow_limit=int("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
        target_spacing=60,
        allow_min_difficulty=True,
        no_retargeting=False,
    ),
    "regtest": NetworkConfig(
        name="regtest",
        magic=bytes.fromhex("fabfb5da"),
        default_port=18444,
        genesis_hash="00000000883439521559eaee4bf336fa07101ccecbd1a1d9eb095f60954f5c0c",
        genesis_time=1723968610,
        genesis_bits=0x1D00FFFF,
        pow_limit=int("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
        target_spacing=60,
        allow_min_difficulty=True,
        no_retargeting=True,
    ),
}


@dataclass(frozen=True)
class HeaderState:
    height: int
    hash_hex: str
    hash_int: int
    prev_hash_int: int
    time: int
    bits: int
    chainwork: int


@dataclass(frozen=True)
class PeerAddress:
    host: str
    port: int

    def label(self) -> str:
        return f"{self.host}:{self.port}"


def utc_now_iso() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def ser_compact_size(size: int) -> bytes:
    if size < 0:
        raise ValueError("compact size must be non-negative")
    if size < 253:
        return size.to_bytes(1, "little")
    if size <= 0xFFFF:
        return b"\xfd" + size.to_bytes(2, "little")
    if size <= 0xFFFFFFFF:
        return b"\xfe" + size.to_bytes(4, "little")
    return b"\xff" + size.to_bytes(8, "little")


def deser_compact_size(payload: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset >= len(payload):
        raise ObserverError("truncated compact-size integer")
    first = payload[offset]
    offset += 1
    if first < 253:
        return first, offset
    if first == 253:
        width = 2
    elif first == 254:
        width = 4
    else:
        width = 8
    if offset + width > len(payload):
        raise ObserverError("truncated compact-size payload")
    return int.from_bytes(payload[offset:offset + width], "little"), offset + width


def ser_string(value: bytes) -> bytes:
    return ser_compact_size(len(value)) + value


def uint256_to_wire(value: int) -> bytes:
    return value.to_bytes(32, "little")


def hash_hex_to_int(value: str) -> int:
    return int(value, 16)


def hash_int_to_hex(value: int) -> str:
    return f"{value:064x}"


def target_from_compact(nbits: int) -> Tuple[int, bool, bool]:
    size = nbits >> 24
    word = nbits & 0x007FFFFF
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    negative = bool(word and (nbits & 0x00800000))
    overflow = bool(word and (size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32)))
    return target, negative, overflow


def compact_from_target(target: int, negative: bool = False) -> int:
    if target < 0:
        raise ValueError("target must be non-negative")
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    compact &= 0x007FFFFF
    compact |= size << 24
    if negative and compact & 0x007FFFFF:
        compact |= 0x00800000
    return compact


def cxx_div(numerator: int, denominator: int) -> int:
    if denominator == 0:
        raise ZeroDivisionError("division by zero")
    sign = -1 if (numerator < 0) ^ (denominator < 0) else 1
    return sign * (abs(numerator) // abs(denominator))


def block_proof(nbits: int) -> int:
    target, negative, overflow = target_from_compact(nbits)
    if negative or overflow or target <= 0:
        return 0
    return ((1 << 256) - 1 - target) // (target + 1) + 1


def check_proof_of_work(hash_int: int, nbits: int, network: NetworkConfig) -> bool:
    target, negative, overflow = target_from_compact(nbits)
    if negative or overflow or target <= 0 or target > network.pow_limit:
        return False
    return hash_int <= target


def next_work_required(previous: HeaderState, previous_previous: Optional[HeaderState], candidate_time: int, network: NetworkConfig) -> int:
    pow_limit_bits = compact_from_target(network.pow_limit)
    if network.allow_min_difficulty and candidate_time > previous.time + network.target_spacing * 2:
        return pow_limit_bits
    if network.no_retargeting:
        return previous.bits

    retarget_timespan = network.target_spacing
    if previous.height + 1 == 1:
        first = previous
    else:
        first = previous_previous or previous

    nito_timespan = previous.time - first.time
    adjusted_timespan = retarget_timespan + cxx_div(nito_timespan - retarget_timespan, 8)
    min_timespan = retarget_timespan - 15
    max_timespan = retarget_timespan + 30
    adjusted_timespan = max(min_timespan, min(max_timespan, adjusted_timespan))

    current_target, negative, overflow = target_from_compact(previous.bits)
    if negative or overflow or current_target <= 0:
        raise ObserverError(f"invalid previous nBits {previous.bits:08x} at height {previous.height}")
    new_target = current_target * adjusted_timespan // retarget_timespan
    if new_target > network.pow_limit:
        new_target = network.pow_limit
    return compact_from_target(new_target)


def parse_header(raw: bytes) -> Tuple[int, int, int, int, int, int, int, str]:
    if len(raw) != 80:
        raise ObserverError(f"invalid header length {len(raw)}")
    version = int.from_bytes(raw[0:4], "little", signed=True)
    prev_hash_int = int.from_bytes(raw[4:36], "little")
    merkle_root_int = int.from_bytes(raw[36:68], "little")
    block_time = int.from_bytes(raw[68:72], "little")
    bits = int.from_bytes(raw[72:76], "little")
    nonce = int.from_bytes(raw[76:80], "little")
    digest = sha256d(raw)
    hash_int = int.from_bytes(digest, "little")
    return version, prev_hash_int, merkle_root_int, block_time, bits, nonce, hash_int, hash_int_to_hex(hash_int)


def parse_peer(value: str, default_port: int) -> PeerAddress:
    if value.count(":") == 1 and not value.startswith("["):
        host, port_text = value.rsplit(":", 1)
        return PeerAddress(host, int(port_text))
    if value.startswith("["):
        host, rest = value[1:].split("]", 1)
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return PeerAddress(host, port)
    return PeerAddress(value, default_port)


def _ip_to_legacy_address(host: str, port: int) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = ipaddress.ip_address("0.0.0.0")
    if ip.version == 4:
        raw_ip = b"\x00" * 10 + b"\xff\xff" + ip.packed
    else:
        raw_ip = ip.packed
    return (NODE_NETWORK | NODE_WITNESS).to_bytes(8, "little") + raw_ip + port.to_bytes(2, "big")


def build_version_payload(peer: PeerAddress) -> bytes:
    payload = b""
    payload += P2P_VERSION.to_bytes(4, "little", signed=True)
    payload += OBSERVER_SERVICES.to_bytes(8, "little")
    payload += int(time.time()).to_bytes(8, "little", signed=True)
    payload += _ip_to_legacy_address(peer.host, peer.port)
    payload += _ip_to_legacy_address("0.0.0.0", 0)
    payload += random.getrandbits(64).to_bytes(8, "little")
    payload += ser_string(b"/nito-chain-observer:1.0/")
    payload += (0).to_bytes(4, "little", signed=True)
    payload += b"\x00"
    return payload


def build_message(command: str, payload: bytes, network: NetworkConfig) -> bytes:
    command_bytes = command.encode("ascii")
    if len(command_bytes) > 12:
        raise ValueError("P2P command is too long")
    checksum = sha256d(payload)[:4]
    return network.magic + command_bytes + b"\x00" * (12 - len(command_bytes)) + len(payload).to_bytes(4, "little") + checksum + payload


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ObserverError("peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_message(sock: socket.socket, network: NetworkConfig) -> Tuple[str, bytes]:
    header = _recv_exact(sock, 24)
    if header[:4] != network.magic:
        raise ObserverError(f"magic bytes mismatch: got {header[:4].hex()}, expected {network.magic.hex()}")
    command = header[4:16].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    payload_len = int.from_bytes(header[16:20], "little")
    if payload_len > MAX_PROTOCOL_MESSAGE_LENGTH:
        raise ObserverError(f"{command} payload too large: {payload_len}")
    checksum = header[20:24]
    payload = _recv_exact(sock, payload_len)
    if sha256d(payload)[:4] != checksum:
        raise ObserverError(f"{command} checksum mismatch")
    return command, payload


def send_message(sock: socket.socket, command: str, payload: bytes, network: NetworkConfig) -> None:
    sock.sendall(build_message(command, payload, network))


def parse_version_payload(payload: bytes) -> Dict[str, object]:
    if len(payload) < 86:
        raise ObserverError("truncated version message")
    offset = 0
    version = int.from_bytes(payload[offset:offset + 4], "little", signed=True)
    offset += 4
    services = int.from_bytes(payload[offset:offset + 8], "little")
    offset += 8
    timestamp = int.from_bytes(payload[offset:offset + 8], "little", signed=True)
    offset += 8 + 26 + 26
    nonce = int.from_bytes(payload[offset:offset + 8], "little")
    offset += 8
    subver_len, offset = deser_compact_size(payload, offset)
    if offset + subver_len > len(payload):
        raise ObserverError("truncated version user-agent")
    subver = payload[offset:offset + subver_len].decode("utf-8", errors="replace")
    offset += subver_len
    starting_height = None
    if offset + 4 <= len(payload):
        starting_height = int.from_bytes(payload[offset:offset + 4], "little", signed=True)
    return {
        "version": version,
        "services": services,
        "time": timestamp,
        "nonce": nonce,
        "user_agent": subver,
        "starting_height": starting_height,
    }


def handle_control_message(sock: socket.socket, command: str, payload: bytes, network: NetworkConfig) -> None:
    if command == "ping":
        send_message(sock, "pong", payload, network)


def open_p2p_connection(peer: PeerAddress, network: NetworkConfig, timeout: int) -> Tuple[socket.socket, Dict[str, object]]:
    sock = socket.create_connection((peer.host, peer.port), timeout=timeout)
    try:
        return handshake(sock, peer, network, timeout)
    except BaseException:
        sock.close()
        raise


def handshake(sock: socket.socket, peer: PeerAddress, network: NetworkConfig, timeout: int) -> Tuple[socket.socket, Dict[str, object]]:
    sock.settimeout(timeout)
    send_message(sock, "version", build_version_payload(peer), network)
    peer_info: Dict[str, object] = {}
    sent_verack = False
    got_verack = False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        command, payload = read_message(sock, network)
        if command == "version":
            peer_info = parse_version_payload(payload)
            send_message(sock, "verack", b"", network)
            sent_verack = True
        elif command == "verack":
            got_verack = True
        else:
            handle_control_message(sock, command, payload, network)
        if peer_info and sent_verack and got_verack:
            return sock, peer_info
    raise ObserverError(f"timed out during handshake with {peer.label()}")


def build_getheaders_payload(locator_hashes: Sequence[int]) -> bytes:
    payload = P2P_VERSION.to_bytes(4, "little", signed=True)
    payload += ser_compact_size(len(locator_hashes))
    for locator_hash in locator_hashes:
        payload += uint256_to_wire(locator_hash)
    payload += uint256_to_wire(0)
    return payload


def read_headers_response(sock: socket.socket, network: NetworkConfig, timeout: int) -> List[bytes]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        command, payload = read_message(sock, network)
        if command == "headers":
            count, offset = deser_compact_size(payload, 0)
            if count > MAX_HEADERS_RESULTS:
                raise ObserverError("headers message exceeded the protocol limit")
            headers = []
            for _ in range(count):
                if offset + 80 > len(payload):
                    raise ObserverError("truncated headers payload")
                headers.append(payload[offset:offset + 80])
                offset += 80
                tx_count, offset = deser_compact_size(payload, offset)
                if tx_count != 0:
                    raise ObserverError("headers message contained transactions")
            if offset != len(payload):
                raise ObserverError("headers message has trailing data")
            return headers
        handle_control_message(sock, command, payload, network)
    raise ObserverError("timed out waiting for headers")


def genesis_state(network: NetworkConfig) -> HeaderState:
    return HeaderState(
        height=0,
        hash_hex=network.genesis_hash,
        hash_int=hash_hex_to_int(network.genesis_hash),
        prev_hash_int=0,
        time=network.genesis_time,
        bits=network.genesis_bits,
        chainwork=block_proof(network.genesis_bits),
    )


def observe_peer(peer: PeerAddress, network: NetworkConfig, *, timeout: int = DEFAULT_TIMEOUT, stop_height: Optional[int] = None) -> Dict[str, object]:
    previous = genesis_state(network)
    previous_previous: Optional[HeaderState] = None
    if stop_height == 0:
        return header_observation(peer, previous, {}, 0)

    sock, peer_info = open_p2p_connection(peer, network, timeout)
    headers_downloaded = 0
    try:
        while True:
            send_message(sock, "getheaders", build_getheaders_payload([previous.hash_int]), network)
            raw_headers = read_headers_response(sock, network, timeout)
            if not raw_headers:
                return header_observation(peer, previous, peer_info, headers_downloaded)
            for raw_header in raw_headers:
                version, prev_hash_int, _merkle_root_int, block_time, bits, _nonce, hash_int, hash_hex = parse_header(raw_header)
                if prev_hash_int != previous.hash_int:
                    raise ObserverError(
                        f"{peer.label()} sent non-contiguous header at height {previous.height + 1}: "
                        f"prev={hash_int_to_hex(prev_hash_int)} expected={previous.hash_hex}"
                    )
                expected_bits = next_work_required(previous, previous_previous, block_time, network)
                if bits != expected_bits:
                    raise ObserverError(
                        f"{peer.label()} sent invalid nBits at height {previous.height + 1}: "
                        f"got {bits:08x}, expected {expected_bits:08x}"
                    )
                if not check_proof_of_work(hash_int, bits, network):
                    raise ObserverError(f"{peer.label()} sent header with invalid PoW at height {previous.height + 1}")
                current = HeaderState(
                    height=previous.height + 1,
                    hash_hex=hash_hex,
                    hash_int=hash_int,
                    prev_hash_int=prev_hash_int,
                    time=block_time,
                    bits=bits,
                    chainwork=previous.chainwork + block_proof(bits),
                )
                previous_previous = previous
                previous = current
                headers_downloaded += 1
                if stop_height is not None and previous.height >= stop_height:
                    return header_observation(peer, previous, peer_info, headers_downloaded)
            if len(raw_headers) < MAX_HEADERS_RESULTS:
                return header_observation(peer, previous, peer_info, headers_downloaded)
    finally:
        sock.close()


def header_observation(peer: PeerAddress, header: HeaderState, peer_info: Dict[str, object], headers_downloaded: int) -> Dict[str, object]:
    user_agent = str(peer_info.get("user_agent", ""))
    return {
        "peer": peer.label(),
        "height": header.height,
        "hash": header.hash_hex,
        "chainwork": f"{header.chainwork:064x}",
        "time": header.time,
        "nbits": f"{header.bits:08x}",
        "headers_downloaded": headers_downloaded,
        "peer_protocol_version": peer_info.get("version"),
        "peer_services": peer_info.get("services"),
        "peer_starting_height": peer_info.get("starting_height"),
        "peer_user_agent_sha256": hashlib.sha256(user_agent.encode("utf-8")).hexdigest() if user_agent else None,
    }


OBSERVATION_KEY_FIELDS = ("height", "hash", "chainwork", "time", "nbits")


def observation_key(observation: Dict[str, object]) -> str:
    return json.dumps({
        field: observation[field] for field in OBSERVATION_KEY_FIELDS
    }, sort_keys=True, separators=(",", ":"))


def validate_peer_observation_set(observations: Sequence[Dict[str, object]], context: str) -> List[str]:
    if not observations:
        raise AttestationError(f"{context} has no peer observations")
    seen = set()
    peers = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise AttestationError(f"{context} peer observation #{index + 1} is not an object")
        peer = observation.get("peer")
        if not isinstance(peer, str) or not peer:
            raise AttestationError(f"{context} peer observation #{index + 1} has no peer label")
        if peer in seen:
            raise AttestationError(f"{context} contains duplicate peer {peer!r}")
        for field in OBSERVATION_KEY_FIELDS:
            if field not in observation:
                raise AttestationError(f"{context} peer {peer!r} is missing {field!r}")
        seen.add(peer)
        peers.append(peer)
    return peers


def int_payload_field(value: object, field_name: str, observer_id: str) -> int:
    if isinstance(value, bool):
        raise AttestationError(f"observer {observer_id!r} has invalid {field_name}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AttestationError(f"observer {observer_id!r} has invalid {field_name}") from exc
    if parsed < 0:
        raise AttestationError(f"observer {observer_id!r} has negative {field_name}")
    return parsed


def two_thirds_threshold(known_count: int) -> int:
    if known_count < 1:
        raise AttestationError("known set must not be empty")
    return (known_count * 2 + 2) // 3


def resolve_threshold(kind: str, known_count: int, requested: Optional[int]) -> int:
    required = two_thirds_threshold(known_count)
    if requested is None:
        return required
    if requested < required:
        raise AttestationError(
            f"{kind} agreement cannot be below 2/3 of the known set: requested={requested}, "
            f"known={known_count}, required={required}"
        )
    if requested > known_count:
        raise AttestationError(f"{kind} agreement cannot exceed known set size: requested={requested}, known={known_count}")
    return requested


def choose_observation_group(observations: Sequence[Dict[str, object]], min_agree: int) -> Tuple[List[Dict[str, object]], bool]:
    groups: Dict[str, List[Dict[str, object]]] = {}
    for observation in observations:
        groups.setdefault(observation_key(observation), []).append(observation)
    if not groups:
        raise ObserverError("no usable peer observations")
    best_group = max(groups.values(), key=len)
    if len(best_group) < min_agree:
        raise ObserverError(f"not enough P2P peer agreement: best={len(best_group)}, required={min_agree}")
    return best_group, len(groups) > 1


def build_attestation_payload(
    *,
    network: str,
    observer_id: str,
    selected_observations: Sequence[Dict[str, object]],
    tip_observations: Sequence[Dict[str, object]],
    selection: Dict[str, object],
    min_peer_agree: Optional[int],
) -> Dict[str, object]:
    known_peers = validate_peer_observation_set(selected_observations, "observer")
    known_peer_count = len(known_peers)
    required_peer_agree = resolve_threshold("peer", known_peer_count, min_peer_agree)
    best_group, mismatches = choose_observation_group(selected_observations, required_peer_agree)
    sample = best_group[0]
    now = int(time.time())
    return {
        "schema": ATTESTATION_SCHEMA,
        "network": network,
        "observer_id": observer_id,
        "generated_at_unix": now,
        "generated_at_utc": _datetime.datetime.fromtimestamp(now, _datetime.timezone.utc).isoformat(),
        "selection": selection,
        "peer_threshold_model": "ceil(2/3 of known P2P peers)",
        "known_peer_count": known_peer_count,
        "known_peers": known_peers,
        "minimum_required_peer_agreement": required_peer_agree,
        "peer_observations": list(selected_observations),
        "tip_observations": list(tip_observations),
        "peer_mismatches": mismatches,
        "agreement": {
            "peer_count": len(best_group),
            "peer_names": [item["peer"] for item in best_group],
            "height": sample["height"],
            "hash": sample["hash"],
            "chainwork": sample["chainwork"],
            "time": sample["time"],
            "nbits": sample["nbits"],
        },
    }


def _load_cryptography_ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise AttestationError("Ed25519 signing requires the Python 'cryptography' package") from exc
    return ed25519, serialization


def generate_keypair() -> Dict[str, str]:
    ed25519, serialization = _load_cryptography_ed25519()
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "private_key": private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex(),
    }


def public_key_from_private(private_key_hex: str) -> str:
    ed25519, serialization = _load_cryptography_ed25519()
    private_bytes = bytes.fromhex(private_key_hex)
    if len(private_bytes) != 32:
        raise AttestationError("Ed25519 private key must be 32 raw bytes encoded as hex")
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def sign_payload(payload: Dict[str, object], private_key_hex: str) -> Dict[str, object]:
    ed25519, _serialization = _load_cryptography_ed25519()
    private_bytes = bytes.fromhex(private_key_hex)
    if len(private_bytes) != 32:
        raise AttestationError("Ed25519 private key must be 32 raw bytes encoded as hex")
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_key = public_key_from_private(private_key_hex)
    signature = private_key.sign(canonical_json_bytes(payload)).hex()
    return {
        "payload": payload,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "public_key": public_key,
            "signature": signature,
        },
    }


def verify_attestation(attestation: Dict[str, object], trusted_keys: Dict[str, str]) -> Dict[str, object]:
    ed25519, _serialization = _load_cryptography_ed25519()
    payload = attestation.get("payload")
    signature = attestation.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise AttestationError("attestation must contain payload and signature objects")
    if payload.get("schema") != ATTESTATION_SCHEMA:
        raise AttestationError(f"unsupported attestation schema {payload.get('schema')!r}")
    observer_id = payload.get("observer_id")
    if not isinstance(observer_id, str) or not observer_id:
        raise AttestationError("attestation payload has no observer_id")
    expected_public_key = trusted_keys.get(observer_id)
    if expected_public_key is None:
        raise AttestationError(f"observer {observer_id!r} is not trusted")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise AttestationError(f"unsupported signature algorithm {signature.get('algorithm')!r}")
    if signature.get("public_key") != expected_public_key:
        raise AttestationError(f"observer {observer_id!r} public key does not match trusted registry")
    try:
        verifier = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_public_key))
        verifier.verify(bytes.fromhex(str(signature["signature"])), canonical_json_bytes(payload))
    except Exception as exc:
        raise AttestationError(f"invalid signature for observer {observer_id!r}") from exc
    return payload


def parse_observer_key(value: str) -> Tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("observer keys must use OBSERVER_ID=PUBLIC_KEY_HEX")
    observer_id, public_key = value.split("=", 1)
    observer_id = observer_id.strip()
    public_key = public_key.strip().lower()
    if not observer_id:
        raise argparse.ArgumentTypeError("observer id must not be empty")
    try:
        public_bytes = bytes.fromhex(public_key)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("observer public key must be hex") from exc
    if len(public_bytes) != 32:
        raise argparse.ArgumentTypeError("observer public key must be 32 raw Ed25519 bytes encoded as hex")
    return observer_id, public_key


def parse_trusted_observer_keys(values: Sequence[str]) -> Dict[str, str]:
    trusted_keys: Dict[str, str] = {}
    for value in values:
        observer_id, public_key = parse_observer_key(value)
        if observer_id in trusted_keys:
            raise AttestationError(f"duplicate trusted observer id {observer_id!r}")
        trusted_keys[observer_id] = public_key
    return trusted_keys


def aggregate_attestations(
    attestations: Sequence[Dict[str, object]],
    trusted_keys: Dict[str, str],
    *,
    min_agree: Optional[int] = None,
    max_age: int = 24 * 60 * 60,
    min_peer_agree: Optional[int] = None,
    minimum_chainwork: Optional[str] = None,
    now: Optional[int] = None,
    network: str = "mainnet",
) -> Dict[str, object]:
    if not attestations:
        raise AttestationError("no attestations supplied")
    if not trusted_keys:
        raise AttestationError("no trusted observer public keys supplied")
    if network not in NETWORKS:
        raise AttestationError("unknown attestation network")
    if len(set(key.lower() for key in trusted_keys.values())) != len(trusted_keys):
        raise AttestationError("trusted observers must have distinct public keys")
    required = resolve_threshold("observer", len(trusted_keys), min_agree)
    current_time = int(time.time()) if now is None else now
    verified_payloads = []
    seen_observers = set()
    failures = []
    peer_requirements = []
    for attestation in attestations:
        try:
            payload = verify_attestation(attestation, trusted_keys)
            if payload.get("network") != network:
                raise AttestationError("attestation belongs to a different network")
            observer_id = payload["observer_id"]
            if observer_id in seen_observers:
                raise AttestationError(f"duplicate attestation for observer {observer_id!r}")
            seen_observers.add(observer_id)
            generated_at = int(payload.get("generated_at_unix", 0))
            if max_age >= 0 and current_time - generated_at > max_age:
                raise AttestationError(f"observer {observer_id!r} attestation is stale")
            if generated_at - current_time > 300:
                raise AttestationError(f"observer {observer_id!r} attestation is from the future")
            agreement = payload.get("agreement")
            if not isinstance(agreement, dict):
                raise AttestationError(f"observer {observer_id!r} has no agreement object")
            for field, length in (("hash", 64), ("chainwork", 64), ("nbits", 8)):
                if not isinstance(agreement.get(field), str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", agreement[field]):
                    raise AttestationError(f"observer {observer_id!r} has invalid {field}")
            for field in ("height", "time"):
                if type(agreement.get(field)) is not int or agreement[field] < 0:
                    raise AttestationError(f"observer {observer_id!r} has invalid {field}")
            peer_observations = payload.get("peer_observations")
            if not isinstance(peer_observations, list):
                raise AttestationError(f"observer {observer_id!r} has invalid peer observations")
            peer_names = validate_peer_observation_set(peer_observations, f"observer {observer_id!r}")
            known_peer_count = int_payload_field(
                payload.get("known_peer_count", len(peer_observations)),
                "known_peer_count",
                observer_id,
            )
            if known_peer_count != len(peer_observations):
                raise AttestationError(
                    f"observer {observer_id!r} known_peer_count mismatch: "
                    f"declared={known_peer_count}, observed={len(peer_observations)}"
                )
            known_peers = payload.get("known_peers")
            if not isinstance(known_peers, list) or any(not isinstance(peer, str) or not peer for peer in known_peers):
                raise AttestationError(f"observer {observer_id!r} has invalid known_peers")
            if len(known_peers) != known_peer_count or set(known_peers) != set(peer_names):
                raise AttestationError(f"observer {observer_id!r} known_peers do not match peer observations")
            payload_peer_required = int_payload_field(
                payload.get("minimum_required_peer_agreement", 0),
                "minimum_required_peer_agreement",
                observer_id,
            )
            two_thirds_peer_required = two_thirds_threshold(known_peer_count)
            if payload_peer_required < two_thirds_peer_required:
                raise AttestationError(
                    f"observer {observer_id!r} used a weak peer threshold: "
                    f"required={payload_peer_required}, known={known_peer_count}, "
                    f"minimum_2_3={two_thirds_peer_required}"
                )
            external_peer_required = resolve_threshold("peer", known_peer_count, min_peer_agree) if min_peer_agree is not None else two_thirds_peer_required
            required_peer_agree = max(payload_peer_required, external_peer_required)
            peer_groups: Dict[str, List[Dict[str, object]]] = {}
            for observation in peer_observations:
                peer_groups.setdefault(observation_key(observation), []).append(observation)
            actual_agreement_group = peer_groups.get(observation_key(agreement), [])
            declared_peer_count = int_payload_field(agreement.get("peer_count", 0), "agreement.peer_count", observer_id)
            declared_peer_names = agreement.get("peer_names")
            actual_peer_names = [item["peer"] for item in actual_agreement_group]
            if declared_peer_count != len(actual_agreement_group):
                raise AttestationError(
                    f"observer {observer_id!r} peer agreement does not match observations: "
                    f"declared={declared_peer_count}, observed={len(actual_agreement_group)}"
                )
            if (
                not isinstance(declared_peer_names, list)
                or len(declared_peer_names) != len(actual_peer_names)
                or set(declared_peer_names) != set(actual_peer_names)
            ):
                raise AttestationError(f"observer {observer_id!r} peer_names do not match observations")
            if len(actual_agreement_group) < required_peer_agree:
                raise AttestationError(
                    f"observer {observer_id!r} has insufficient peer agreement: "
                    f"got={len(actual_agreement_group)}, required={required_peer_agree}"
                )
            peer_requirements.append({
                "observer_id": observer_id,
                "known_peer_count": known_peer_count,
                "minimum_required_peer_agreement": required_peer_agree,
            })
            verified_payloads.append(payload)
        except Exception as exc:
            failures.append(str(exc))

    groups: Dict[str, List[Dict[str, object]]] = {}
    for payload in verified_payloads:
        agreement = payload["agreement"]
        key = json.dumps({
            "height": agreement["height"],
            "hash": agreement["hash"],
            "chainwork": agreement["chainwork"],
            "time": agreement["time"],
            "nbits": agreement["nbits"],
        }, sort_keys=True, separators=(",", ":"))
        groups.setdefault(key, []).append(payload)
    best_group = max(groups.values(), key=len) if groups else []
    consensus = None
    if len(best_group) >= required:
        sample = best_group[0]["agreement"]
        if minimum_chainwork is not None and int(str(sample["chainwork"]), 16) < int(minimum_chainwork, 16):
            raise AttestationError(
                f"signed observer consensus would reduce chainwork from {minimum_chainwork} to {sample['chainwork']}"
            )
        consensus = {
            "agreement_count": len(best_group),
            "observer_ids": [payload["observer_id"] for payload in best_group],
            "height": sample["height"],
            "hash": sample["hash"],
            "chainwork": sample["chainwork"],
            "time": sample["time"],
            "nbits": sample["nbits"],
            "chainparams": {
                "nMinimumChainWork": f'uint256S("0x{sample["chainwork"]}")',
                "defaultAssumeValid": f'uint256S("0x{sample["hash"]}")',
            },
        }

    report = {
        "generated_at_utc": utc_now_iso(),
        "network": network,
        "source": "signed-p2p-attestations",
        "schema": ATTESTATION_SCHEMA,
        "trusted_observer_count": len(trusted_keys),
        "observer_threshold_model": "ceil(2/3 of trusted observer keys)",
        "minimum_required_observer_agreement": required,
        "peer_threshold_model": "ceil(2/3 of known P2P peers per observer)",
        "peer_requirements": peer_requirements,
        "minimum_chainwork_guard": minimum_chainwork,
        "verified_attestation_count": len(verified_payloads),
        "failed_attestations": failures,
        "attestations": verified_payloads,
        "consensus": consensus,
        "mismatches": len(groups) > 1,
    }
    canonical = canonical_json_bytes(report)
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    if consensus is None:
        raise AttestationError(
            f"not enough matching signed observer attestations: best={len(best_group)}, required={required}"
        )
    return report


def load_json_file(path: str) -> object:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def write_json_or_stdout(value: object, output: Optional[str]) -> None:
    text = json.dumps(value, indent=2, sort_keys=True)
    if output:
        with open(output, "w", encoding="utf-8") as file:
            file.write(text + "\n")
    print(text)


def observe_command(args: argparse.Namespace) -> int:
    network = NETWORKS[args.network]
    peers = [parse_peer(peer, network.default_port) for peer in args.peer]
    if args.height is not None and args.height < 0:
        raise ObserverError("--height must be non-negative")
    if args.confirmations < 0:
        raise ObserverError("--confirmations must be non-negative")
    try:
        min_peer_agree = resolve_threshold("peer", len(peers), args.min_peer_agree)
    except AttestationError as exc:
        raise ObserverError(str(exc)) from exc

    if args.height is None:
        tip_observations = [observe_peer(peer, network, timeout=args.timeout) for peer in peers]
        tip_heights = [int(item["height"]) for item in tip_observations]
        lowest_tip = min(tip_heights)
        highest_tip = max(tip_heights)
        lag = highest_tip - lowest_tip
        if args.max_tip_lag >= 0 and lag > args.max_tip_lag:
            raise ObserverError(f"P2P peer tips are too far apart: lowest={lowest_tip}, highest={highest_tip}, lag={lag}")
        selected_height = lowest_tip - args.confirmations
        if selected_height < 0:
            raise ObserverError(f"not enough height for --confirmations={args.confirmations}: lowest tip is {lowest_tip}")
        selection = {
            "height_source": "auto",
            "confirmations": args.confirmations,
            "lowest_tip_height": lowest_tip,
            "highest_tip_height": highest_tip,
            "tip_lag": lag,
            "selected_height": selected_height,
        }
    else:
        tip_observations = []
        selected_height = args.height
        selection = {
            "height_source": "manual",
            "selected_height": selected_height,
        }

    selected_observations = [observe_peer(peer, network, timeout=args.timeout, stop_height=selected_height) for peer in peers]
    payload = build_attestation_payload(
        network=args.network,
        observer_id=args.observer_id,
        selected_observations=selected_observations,
        tip_observations=tip_observations,
        selection=selection,
        min_peer_agree=min_peer_agree,
    )
    signing_key = sys.stdin.read().strip() if args.signing_key_stdin else args.signing_key
    attestation = sign_payload(payload, signing_key)
    write_json_or_stdout(attestation, args.output)
    return 0


def verify_command(args: argparse.Namespace) -> int:
    trusted_keys = parse_trusted_observer_keys(args.observer_key)
    attestations = [load_json_file(path) for path in args.attestation]
    report = aggregate_attestations(
        attestations,
        trusted_keys,
        min_agree=args.min_agree,
        max_age=args.max_age,
        min_peer_agree=args.min_peer_agree,
        minimum_chainwork=args.minimum_chainwork,
        network=args.network,
    )
    write_json_or_stdout(report, args.output)
    return 0


def generate_key_command(_args: argparse.Namespace) -> int:
    write_json_or_stdout(generate_keypair(), None)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate-key", help="Generate a raw Ed25519 observer keypair.")
    generate_parser.set_defaults(func=generate_key_command)

    observe_parser = subparsers.add_parser("observe", help="Observe P2P peers and create a signed attestation.")
    observe_parser.add_argument("--network", choices=sorted(NETWORKS), default="mainnet")
    observe_parser.add_argument("--peer", action="append", required=True, help="Peer host[:port]. Repeat for independent peers.")
    observe_parser.add_argument("--height", type=int, help="Specific height to attest. If omitted, use lowest observed tip minus confirmations.")
    observe_parser.add_argument("--confirmations", type=int, default=DEFAULT_CONFIRMATIONS)
    observe_parser.add_argument("--max-tip-lag", type=int, default=DEFAULT_MAX_TIP_LAG, help="Maximum allowed tip lag for automatic height selection; -1 disables.")
    observe_parser.add_argument("--min-peer-agree", type=int, help="Optional stricter peer agreement. It cannot be lower than ceil(2/3 of peers passed with --peer).")
    observe_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    observe_parser.add_argument("--observer-id", required=True)
    signing = observe_parser.add_mutually_exclusive_group(required=True)
    signing.add_argument("--signing-key", help="Raw Ed25519 private key hex; prefer --signing-key-stdin to keep it out of process arguments.")
    signing.add_argument("--signing-key-stdin", action="store_true", help="Read the raw Ed25519 private key hex from standard input.")
    observe_parser.add_argument("--output")
    observe_parser.set_defaults(func=observe_command)

    verify_parser = subparsers.add_parser("verify", help="Verify signed attestations and require ceil(2/3) observer agreement.")
    verify_parser.add_argument("--network", choices=sorted(NETWORKS), default="mainnet")
    verify_parser.add_argument("--attestation", action="append", required=True, help="Signed attestation JSON file. Repeat for each observer.")
    verify_parser.add_argument("--observer-key", action="append", required=True, help="Trusted observer as OBSERVER_ID=PUBLIC_KEY_HEX.")
    verify_parser.add_argument("--min-agree", type=int, help="Optional stricter observer agreement. It cannot be lower than ceil(2/3 of the full known trusted key set).")
    verify_parser.add_argument("--min-peer-agree", type=int, help="Optional stricter peer agreement for every attestation. It cannot be lower than ceil(2/3 of that attestation's known peers).")
    verify_parser.add_argument("--max-age", type=int, default=24 * 60 * 60, help="Maximum attestation age in seconds; -1 disables.")
    verify_parser.add_argument("--minimum-chainwork", help="Reject consensus below this chainwork hex value.")
    verify_parser.add_argument("--output")
    verify_parser.set_defaults(func=verify_command)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ObserverError, AttestationError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
