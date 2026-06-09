#!/usr/bin/env python3
"""Bootstrap a Marmot dm-agent account for Hermes phone testing."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


PROTOCOL = "marmot.agent-control.v1"
DEFAULT_HOME = "/data/marmot-agent"
DEFAULT_LABEL = "hermes-agent"
DEFAULT_RELAYS = [
    "wss://relay.eu.whiteniose.chat",
    "wss://relay.us.whitenoise.chat",
]
DEFAULT_QUIC_CANDIDATE = "quic://quic-broker.ipf.dev:4450"
MAX_FRAME_BYTES = 1024 * 1024
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class BootstrapError(RuntimeError):
    pass


class AgentControlClient:
    def __init__(self, socket_path: Path, *, auth_token: str | None, timeout: float):
        self.socket_path = socket_path
        self.auth_token = auth_token
        self.timeout = timeout

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        envelope = {
            "marmot_agent_control": PROTOCOL,
            "id": request_id,
            **payload,
        }
        if self.auth_token:
            envelope["auth_token"] = self.auth_token
        frame = json.dumps(envelope, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(frame) > MAX_FRAME_BYTES:
            raise BootstrapError("agent control request frame is too large")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout)
            try:
                client.connect(str(self.socket_path))
                client.sendall(frame)
                response = self._read_frame(client)
            except OSError as exc:
                raise BootstrapError(f"control socket request failed: {exc}") from exc

        if response.get("marmot_agent_control") != PROTOCOL:
            raise BootstrapError(f"wrong control protocol: {response.get('marmot_agent_control')!r}")
        if response.get("id") != request_id:
            raise BootstrapError("control response id mismatch")
        if response.get("type") == "error":
            code = response.get("code") or "agent_control_error"
            message = response.get("message") or "agent control error"
            raise BootstrapError(f"{code}: {message}")
        return response

    def _read_frame(self, client: socket.socket) -> dict[str, Any]:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = client.recv(4096)
            if not chunk:
                raise BootstrapError("control socket closed before response")
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FRAME_BYTES:
                raise BootstrapError("agent control response frame is too large")
            if b"\n" in chunk:
                break
        raw = b"".join(chunks).split(b"\n", 1)[0]
        return json.loads(raw.decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = resolve_config(args)
        wait_for_socket(config["socket"], args.wait_for_socket)
        client = AgentControlClient(
            config["socket"],
            auth_token=config["auth_token"],
            timeout=args.request_timeout,
        )
        result = bootstrap_agent_account(
            client,
            label=args.label,
            account_id_hex=args.account_id_hex,
            create_if_missing=not args.no_create,
            publish_key_package=not args.no_publish_key_package,
        )
        result.update(
            {
                "socket": str(config["socket"]),
                "relays": config["relays"],
                "quic_candidates": config["quic_candidates"],
            }
        )
        result["npub"] = npub_for_account_id(result["account_id_hex"])
        result["nprofile"] = nprofile_for_account_id(
            result["account_id_hex"],
            config["relays"],
        )
        result["qr_payload"] = result["nprofile"]
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print_human_result(result)
            if args.qr:
                render_qr(result["qr_payload"])
        return 0
    except BootstrapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create or reuse a local Marmot agent account and print phone bootstrap details."
    )
    parser.add_argument("--home", help=f"Marmot agent home (default: MARMOT_HOME or {DEFAULT_HOME})")
    parser.add_argument("--socket", help="dm-agent Unix control socket")
    parser.add_argument("--label", default=DEFAULT_LABEL, help=f"agent account label (default: {DEFAULT_LABEL})")
    parser.add_argument("--account-id-hex", help="reuse this local signing account instead of selecting by label")
    parser.add_argument("--auth-token", help="control-plane auth token")
    parser.add_argument("--auth-token-file", help="control-plane auth token file")
    parser.add_argument("--relay", action="append", dest="relays", help="public Nostr relay; may be repeated")
    parser.add_argument("--quic-candidate", action="append", dest="quic_candidate", help="QUIC preview candidate")
    parser.add_argument("--quic-candidates", dest="quic_candidates_csv", help="comma-separated QUIC preview candidates")
    parser.add_argument("--no-quic", action="store_true", help="omit default QUIC preview candidate from output")
    parser.add_argument("--no-create", action="store_true", help="fail instead of creating an account when missing")
    parser.add_argument(
        "--no-publish-key-package",
        action="store_true",
        help="skip KeyPackage publish/repair during bootstrap",
    )
    parser.add_argument("--qr", action="store_true", help="render invite URI as a terminal QR code using qrencode")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON only")
    parser.add_argument("--wait-for-socket", type=float, default=15.0, help="seconds to wait for dm-agent socket")
    parser.add_argument("--request-timeout", type=float, default=30.0, help="seconds per control socket request")
    return parser.parse_args(argv)


def resolve_config(args: argparse.Namespace) -> dict[str, Any]:
    home = Path(args.home or os.environ.get("MARMOT_HOME") or DEFAULT_HOME).expanduser()
    socket_path = Path(
        args.socket
        or os.environ.get("MARMOT_AGENT_SOCKET")
        or home.joinpath("dev", "dm-agent.sock")
    ).expanduser()
    return {
        "home": home,
        "socket": socket_path,
        "auth_token": read_auth_token(args, home),
        "relays": resolve_relays(args),
        "quic_candidates": resolve_quic_candidates(args),
    }


def read_auth_token(args: argparse.Namespace, home: Path) -> str | None:
    if args.auth_token:
        return non_empty_token(args.auth_token, "--auth-token")
    if os.environ.get("MARMOT_AGENT_AUTH_TOKEN"):
        return non_empty_token(os.environ["MARMOT_AGENT_AUTH_TOKEN"], "MARMOT_AGENT_AUTH_TOKEN")

    explicit_path = args.auth_token_file or os.environ.get("MARMOT_AGENT_AUTH_TOKEN_FILE")
    token_path = Path(explicit_path).expanduser() if explicit_path else home / "control.token"
    if not token_path.exists():
        if explicit_path:
            raise BootstrapError(f"auth token file not found: {token_path}")
        return None
    return non_empty_token(token_path.read_text(encoding="utf-8"), str(token_path))


def non_empty_token(value: str, source: str) -> str:
    token = value.strip()
    if not token:
        raise BootstrapError(f"{source} is empty")
    return token


def resolve_relays(args: argparse.Namespace) -> list[str]:
    relays = args.relays
    if relays is None:
        relays = csv_values(os.environ.get("MARMOT_RELAYS") or os.environ.get("MARMOT_RELAY"))
    return clean_values(relays) or DEFAULT_RELAYS


def resolve_quic_candidates(args: argparse.Namespace) -> list[str]:
    if args.no_quic:
        return []
    candidates = list(args.quic_candidate or [])
    candidates.extend(csv_values(args.quic_candidates_csv))
    if not candidates:
        candidates = csv_values(os.environ.get("MARMOT_QUIC_CANDIDATES"))
    return clean_values(candidates) or [DEFAULT_QUIC_CANDIDATE]


def csv_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def clean_values(values: list[str] | None) -> list[str]:
    cleaned: list[str] = []
    for value in values or []:
        value = str(value).strip()
        if value:
            cleaned.append(value)
    return cleaned


def wait_for_socket(socket_path: Path, wait_seconds: float) -> None:
    deadline = time.monotonic() + max(wait_seconds, 0.0)
    while True:
        if socket_path.exists():
            return
        if time.monotonic() >= deadline:
            raise BootstrapError(f"dm-agent socket not found: {socket_path}")
        time.sleep(0.1)


def bootstrap_agent_account(
    client: AgentControlClient,
    *,
    label: str,
    account_id_hex: str | None,
    create_if_missing: bool,
    publish_key_package: bool,
) -> dict[str, Any]:
    accounts_response = client.request({"type": "account_list"})
    if accounts_response.get("type") != "account_list":
        raise BootstrapError(f"expected account_list response, got {accounts_response.get('type')!r}")
    accounts = [account for account in accounts_response.get("accounts", []) if account.get("local_signing")]
    account = select_account(accounts, account_id_hex=account_id_hex, label=label)
    created = False
    key_package_bytes = None

    if account is None:
        if not create_if_missing:
            raise BootstrapError("no local signing agent account found")
        create_response = client.request(
            {
                "type": "account_create",
                "label": label,
                "publish_key_package": publish_key_package,
            }
        )
        if create_response.get("type") != "account_created":
            raise BootstrapError(f"expected account_created response, got {create_response.get('type')!r}")
        account = create_response.get("account") or {}
        created = True
    elif publish_key_package:
        publish_response = client.request(
            {
                "type": "account_publish_key_package",
                "account_id_hex": normalize_account_id_hex(account["account_id_hex"]),
            }
        )
        if publish_response.get("type") != "key_package_published":
            raise BootstrapError(
                f"expected key_package_published response, got {publish_response.get('type')!r}"
            )
        key_package_bytes = publish_response.get("key_package_bytes")

    account_id = normalize_account_id_hex(account.get("account_id_hex", ""))
    return {
        "account_id_hex": account_id,
        "label": str(account.get("label") or label),
        "local_signing": bool(account.get("local_signing")),
        "created": created,
        "key_package_published": publish_key_package,
        "key_package_bytes": key_package_bytes,
    }


def select_account(
    accounts: list[dict[str, Any]],
    *,
    account_id_hex: str | None,
    label: str,
) -> dict[str, Any] | None:
    if account_id_hex:
        normalized = normalize_account_id_hex(account_id_hex)
        matches = [account for account in accounts if account.get("account_id_hex") == normalized]
        if not matches:
            raise BootstrapError(f"local signing account not found: {normalized}")
        return matches[0]

    label_matches = [account for account in accounts if account.get("label") == label]
    if len(label_matches) == 1:
        return label_matches[0]
    if len(label_matches) > 1:
        raise BootstrapError(f"multiple local signing accounts use label {label!r}; pass --account-id-hex")
    if len(accounts) == 1:
        return accounts[0]
    if len(accounts) > 1:
        labels = ", ".join(f"{account.get('label')}={account.get('account_id_hex')}" for account in accounts)
        raise BootstrapError(f"multiple local signing accounts exist; pass --account-id-hex ({labels})")
    return None


def normalize_account_id_hex(value: str) -> str:
    normalized = str(value).strip().lower()
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise BootstrapError(f"invalid account pubkey hex: {value!r}") from exc
    if len(raw) != 32:
        raise BootstrapError(f"invalid account pubkey length: expected 32 bytes, got {len(raw)}")
    return normalized


def npub_for_account_id(account_id_hex: str) -> str:
    raw = bytes.fromhex(normalize_account_id_hex(account_id_hex))
    return bech32_encode("npub", raw)


def nprofile_for_account_id(account_id_hex: str, relays: list[str]) -> str:
    raw = bytes.fromhex(normalize_account_id_hex(account_id_hex))
    tlv = bytearray()
    append_tlv(tlv, 0, raw)
    for relay in relays:
        append_tlv(tlv, 1, relay.encode("utf-8"))
    return bech32_encode("nprofile", bytes(tlv))


def append_tlv(out: bytearray, tlv_type: int, value: bytes) -> None:
    if len(value) > 255:
        raise BootstrapError("nprofile relay hint is too long")
    out.append(tlv_type)
    out.append(len(value))
    out.extend(value)


def bech32_encode(hrp: str, raw: bytes) -> str:
    data = convert_bits(raw, 8, 5, pad=True)
    checksum = bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in data + checksum)


def convert_bits(data: bytes, from_bits: int, to_bits: int, *, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise BootstrapError("invalid bech32 data")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise BootstrapError("invalid bech32 padding")
    return ret


def bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]


def bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                chk ^= generator
    return chk


def print_human_result(result: dict[str, Any]) -> None:
    action = "created" if result["created"] else "reused"
    print("Marmot agent bootstrap complete")
    print(f"Status: {action}")
    print(f"Agent label: {result['label']}")
    print(f"Agent account hex: {result['account_id_hex']}")
    print(f"Agent npub: {result['npub']}")
    print(f"Agent nprofile: {result['nprofile']}")
    print(f"Relay(s): {', '.join(result['relays'])}")
    if result["quic_candidates"]:
        print(f"QUIC candidate(s): {', '.join(result['quic_candidates'])}")
    else:
        print("QUIC candidate(s): none")
    print(f"KeyPackage: {'published or repaired' if result['key_package_published'] else 'skipped'}")
    print(f"QR payload: {result['qr_payload']}")


def render_qr(payload: str) -> None:
    qrencode = shutil.which("qrencode")
    print()
    if not qrencode:
        print("QR code: qrencode is not installed; use the QR payload above.")
        return
    print("QR code:")
    subprocess.run([qrencode, "-t", "ANSIUTF8", payload], check=True)


if __name__ == "__main__":
    raise SystemExit(main())
