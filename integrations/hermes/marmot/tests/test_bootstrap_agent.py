import asyncio
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT_PATH = REPO_ROOT / "scripts" / "hermes_marmot_bootstrap_agent.py"
ACCOUNT_ID = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4"
NPUB = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy"
DEFAULT_RELAYS = [
    "wss://relay.eu.whiteniose.chat",
    "wss://relay.us.whitenoise.chat",
]


async def read_json_line(reader):
    raw = await reader.readline()
    return json.loads(raw.decode("utf-8"))


async def write_json_line(writer, value):
    writer.write(json.dumps(value).encode("utf-8") + b"\n")
    await writer.drain()


class BootstrapAgentScriptTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.socket_path = str(Path(self.tempdir.name) / "dm-agent.sock")
        self.server = None

    async def asyncTearDown(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        self.tempdir.cleanup()

    async def start_server(self, handler):
        self.server = await asyncio.start_unix_server(handler, path=self.socket_path)

    async def run_script(self, *args, env=None):
        command = [
            sys.executable,
            str(SCRIPT_PATH),
            "--socket",
            self.socket_path,
            "--wait-for-socket",
            "0.1",
            *args,
        ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await process.communicate()
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout.decode("utf-8"),
            stderr.decode("utf-8"),
        )

    async def test_creates_agent_account_when_none_exists(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            if request["type"] == "account_list":
                response = {"type": "account_list", "accounts": []}
            else:
                self.assertEqual(request["type"], "account_create")
                self.assertEqual(request["label"], "hermes-agent")
                self.assertTrue(request["publish_key_package"])
                response = {
                    "type": "account_created",
                    "account": {
                        "account_id_hex": ACCOUNT_ID,
                        "label": "hermes-agent",
                        "local_signing": True,
                    },
                }
            await write_json_line(
                writer,
                {"marmot_agent_control": "marmot.agent-control.v1", "id": request["id"], **response},
            )
            writer.close()

        await self.start_server(handler)

        result = await self.run_script("--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["created"])
        self.assertEqual(output["account_id_hex"], ACCOUNT_ID)
        self.assertEqual(output["npub"], NPUB)
        self.assertEqual(output["relays"], DEFAULT_RELAYS)
        self.assertIn("quic://quic-broker.ipf.dev:4450", output["quic_candidates"])
        self.assertIn(f"account={ACCOUNT_ID}", output["invite_uri"])
        self.assertEqual([request["type"] for request in requests], ["account_list", "account_create"])

    async def test_reuses_existing_agent_account_and_repairs_key_package(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            if request["type"] == "account_list":
                response = {
                    "type": "account_list",
                    "accounts": [
                        {
                            "account_id_hex": ACCOUNT_ID,
                            "label": "hermes-agent",
                            "local_signing": True,
                        }
                    ],
                }
            else:
                self.assertEqual(request["type"], "account_publish_key_package")
                self.assertEqual(request["account_id_hex"], ACCOUNT_ID)
                response = {
                    "type": "key_package_published",
                    "account_id_hex": ACCOUNT_ID,
                    "key_package_bytes": 1234,
                }
            await write_json_line(
                writer,
                {"marmot_agent_control": "marmot.agent-control.v1", "id": request["id"], **response},
            )
            writer.close()

        await self.start_server(handler)

        result = await self.run_script("--json")

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertFalse(output["created"])
        self.assertTrue(output["key_package_published"])
        self.assertEqual(output["key_package_bytes"], 1234)
        self.assertEqual([request["type"] for request in requests], ["account_list", "account_publish_key_package"])

    async def test_accepts_repeated_and_csv_quic_candidates(self):
        async def handler(reader, writer):
            request = await read_json_line(reader)
            if request["type"] == "account_list":
                response = {
                    "type": "account_list",
                    "accounts": [
                        {
                            "account_id_hex": ACCOUNT_ID,
                            "label": "hermes-agent",
                            "local_signing": True,
                        }
                    ],
                }
            else:
                response = {
                    "type": "key_package_published",
                    "account_id_hex": ACCOUNT_ID,
                    "key_package_bytes": 12,
                }
            await write_json_line(
                writer,
                {"marmot_agent_control": "marmot.agent-control.v1", "id": request["id"], **response},
            )
            writer.close()

        await self.start_server(handler)

        result = await self.run_script(
            "--json",
            "--relay",
            "wss://relay.one",
            "--quic-candidate",
            "quic://one",
            "--quic-candidates",
            "quic://two, quic://three",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["relays"], ["wss://relay.one"])
        self.assertEqual(output["quic_candidates"], ["quic://one", "quic://two", "quic://three"])

    async def test_qr_mode_renders_with_qrencode_when_available(self):
        async def handler(reader, writer):
            request = await read_json_line(reader)
            if request["type"] == "account_list":
                response = {
                    "type": "account_list",
                    "accounts": [
                        {
                            "account_id_hex": ACCOUNT_ID,
                            "label": "hermes-agent",
                            "local_signing": True,
                        }
                    ],
                }
            else:
                response = {
                    "type": "key_package_published",
                    "account_id_hex": ACCOUNT_ID,
                    "key_package_bytes": 12,
                }
            await write_json_line(
                writer,
                {"marmot_agent_control": "marmot.agent-control.v1", "id": request["id"], **response},
            )
            writer.close()

        fake_bin = Path(self.tempdir.name) / "bin"
        fake_bin.mkdir()
        qrencode = fake_bin / "qrencode"
        qrencode.write_text("#!/usr/bin/env sh\nprintf 'FAKE-QR:%s\\n' \"$3\"\n", encoding="utf-8")
        qrencode.chmod(qrencode.stat().st_mode | stat.S_IXUSR)
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"

        await self.start_server(handler)

        result = await self.run_script("--qr", env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Agent account hex: {ACCOUNT_ID}", result.stdout)
        self.assertIn(f"Agent npub: {NPUB}", result.stdout)
        self.assertIn("FAKE-QR:marmot-agent:v1?", result.stdout)


if __name__ == "__main__":
    unittest.main()
