import asyncio
from contextlib import suppress
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path


PLUGIN_DIR = Path(__file__).resolve().parents[1]
ADAPTER_PATH = PLUGIN_DIR / "adapter.py"


def install_fake_hermes_modules():
    gateway = types.ModuleType("gateway")
    gateway_platforms = types.ModuleType("gateway.platforms")
    gateway_base = types.ModuleType("gateway.platforms.base")
    gateway_config = types.ModuleType("gateway.config")

    class MessageType:
        TEXT = "text"

    @dataclass
    class SendResult:
        success: bool
        message_id: str | None = None
        error: str | None = None
        raw_response: object = None
        retryable: bool = False
        continuation_message_ids: tuple = ()

    @dataclass
    class SessionSource:
        platform: object
        chat_id: str
        chat_name: str | None = None
        chat_type: str = "dm"
        user_id: str | None = None
        user_name: str | None = None
        thread_id: str | None = None
        message_id: str | None = None

    @dataclass
    class MessageEvent:
        text: str
        message_type: object = MessageType.TEXT
        source: object = None
        raw_message: object = None
        message_id: str | None = None
        media_urls: list = field(default_factory=list)
        media_types: list = field(default_factory=list)

    class Platform:
        def __init__(self, value):
            self.value = value

    @dataclass
    class PlatformConfig:
        enabled: bool = True
        token: str | None = None
        api_key: str | None = None
        home_channel: object = None
        reply_to_mode: str = "first"
        gateway_restart_notification: bool = True
        extra: dict = field(default_factory=dict)

    class BasePlatformAdapter:
        def __init__(self, config, platform):
            self.config = config
            self.platform = platform
            self._running = False
            self.events = []

        @property
        def enforces_own_access_policy(self):
            return False

        def _mark_connected(self):
            self._running = True

        def _mark_disconnected(self):
            self._running = False

        def build_source(self, **kwargs):
            return SessionSource(platform=self.platform, **kwargs)

        async def handle_message(self, event):
            self.events.append(event)

    gateway_base.BasePlatformAdapter = BasePlatformAdapter
    gateway_base.MessageEvent = MessageEvent
    gateway_base.MessageType = MessageType
    gateway_base.SendResult = SendResult
    gateway_config.Platform = Platform
    gateway_config.PlatformConfig = PlatformConfig

    sys.modules["gateway"] = gateway
    sys.modules["gateway.platforms"] = gateway_platforms
    sys.modules["gateway.platforms.base"] = gateway_base
    sys.modules["gateway.config"] = gateway_config
    return PlatformConfig


def load_adapter_module():
    for name in [
        "marmot_hermes_adapter",
        "gateway",
        "gateway.platforms",
        "gateway.platforms.base",
        "gateway.config",
    ]:
        sys.modules.pop(name, None)
    install_fake_hermes_modules()
    spec = importlib.util.spec_from_file_location("marmot_hermes_adapter", ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["marmot_hermes_adapter"] = module
    spec.loader.exec_module(module)
    return module


async def read_json_line(reader):
    raw = await reader.readline()
    return json.loads(raw.decode("utf-8"))


async def write_json_line(writer, value):
    writer.write(json.dumps(value).encode("utf-8") + b"\n")
    await writer.drain()


class AgentControlClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter = load_adapter_module()
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

    async def test_send_final_writes_protocol_envelope_and_reads_response(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "final_sent",
                    "message_ids_hex": ["aa", "bb"],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        response = await client.send_final(
            "11" * 32,
            "22" * 32,
            "hello",
            reply_to_message_id_hex="33" * 32,
        )

        self.assertEqual(response["type"], "final_sent")
        self.assertEqual(response["message_ids_hex"], ["aa", "bb"])
        self.assertEqual(requests[0]["marmot_agent_control"], "marmot.agent-control.v1")
        self.assertEqual(requests[0]["type"], "send_final")
        self.assertEqual(requests[0]["account_id_hex"], "11" * 32)
        self.assertEqual(requests[0]["group_id_hex"], "22" * 32)
        self.assertEqual(requests[0]["reply_to_message_id_hex"], "33" * 32)

    async def test_auth_token_is_written_when_configured(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "account_list",
                    "accounts": [],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, auth_token="test-token")

        response = await client.account_list()

        self.assertEqual(response["type"], "account_list")
        self.assertEqual(requests[0]["auth_token"], "test-token")

    async def test_account_publish_profile_writes_public_profile_request(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "profile_published",
                    "account_id_hex": request["account_id_hex"],
                    "name": request["name"],
                    "display_name": request["display_name"],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        response = await client.account_publish_profile("11" * 32, "Hermes", "Hermes Agent")

        self.assertEqual(response["type"], "profile_published")
        self.assertEqual(requests[0]["type"], "account_publish_profile")
        self.assertEqual(requests[0]["account_id_hex"], "11" * 32)
        self.assertEqual(requests[0]["name"], "Hermes")
        self.assertEqual(requests[0]["display_name"], "Hermes Agent")

    async def test_send_agent_operation_event_writes_typed_operation_request(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "app_event_sent",
                    "message_ids_hex": ["22" * 32],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        response = await client.send_agent_operation_event(
            "11" * 32,
            "22" * 32,
            event_type="tool_call",
            status="started",
            operation_id="call-1",
            run_id="run-1",
            turn_id="turn-1",
            name="search",
            text="search: glp-1",
            preview="glp-1",
            details={"args": {"query": "glp-1"}},
            sequence=3,
            reply_to_message_id_hex="33" * 32,
        )

        self.assertEqual(response["type"], "app_event_sent")
        self.assertEqual(requests[0]["type"], "send_agent_operation_event")
        self.assertEqual(requests[0]["event_type"], "tool_call")
        self.assertEqual(requests[0]["operation_id"], "call-1")
        self.assertEqual(requests[0]["run_id"], "run-1")
        self.assertEqual(requests[0]["turn_id"], "turn-1")
        self.assertEqual(requests[0]["name"], "search")
        self.assertEqual(requests[0]["preview"], "glp-1")
        self.assertEqual(requests[0]["details"], {"args": {"query": "glp-1"}})
        self.assertEqual(requests[0]["sequence"], 3)
        self.assertEqual(requests[0]["reply_to_message_id_hex"], "33" * 32)

    async def test_inbound_subscription_requires_ack_then_yields_events(self):
        async def handler(reader, writer):
            request = await read_json_line(reader)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "ack",
                },
            )
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "inbound_message",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "22" * 32,
                    "message_id_hex": "33" * 32,
                    "sender_account_id_hex": "44" * 32,
                    "text": "ping",
                },
            )
            await writer.drain()
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        events = client.inbound_events(account_id_hex="11" * 32)
        event = await anext(events)
        await events.aclose()

        self.assertEqual(event["type"], "inbound_message")
        self.assertEqual(event["text"], "ping")

    async def test_inbound_subscription_waits_without_request_timeout_after_ack(self):
        release_event = asyncio.Event()

        async def handler(reader, writer):
            request = await read_json_line(reader)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "ack",
                },
            )
            await release_event.wait()
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "inbound_message",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "22" * 32,
                    "message_id_hex": "33" * 32,
                    "sender_account_id_hex": "44" * 32,
                    "text": "after idle",
                },
            )
            await writer.drain()
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)
        events = client.inbound_events(account_id_hex="11" * 32)

        pending_event = asyncio.create_task(anext(events))
        try:
            await asyncio.sleep(0.05)
            self.assertFalse(pending_event.done())

            release_event.set()
            event = await asyncio.wait_for(pending_event, timeout=1.0)

            self.assertEqual(event["type"], "inbound_message")
            self.assertEqual(event["text"], "after idle")
        finally:
            release_event.set()
            if not pending_event.done():
                pending_event.cancel()
                with suppress(asyncio.CancelledError):
                    await pending_event
            await events.aclose()

    async def test_request_timeout_is_retryable_agent_control_error(self):
        release = asyncio.Event()

        async def handler(reader, writer):
            await read_json_line(reader)
            await release.wait()
            writer.close()
            await writer.wait_closed()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)

        try:
            with self.assertRaises(self.adapter.AgentControlError) as raised:
                await client.account_list()
        finally:
            release.set()
            await asyncio.sleep(0)

        self.assertEqual(raised.exception.code, "timeout")
        self.assertTrue(raised.exception.retryable)

    async def test_write_timeout_is_retryable_agent_control_error(self):
        class SlowWriter:
            def write(self, _frame):
                pass

            async def drain(self):
                await asyncio.sleep(1)

        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)

        with self.assertRaises(self.adapter.AgentControlError) as raised:
            await client._write_envelope(
                SlowWriter(),
                {"type": "account_list"},
                request_id="req-timeout",
            )

        self.assertEqual(raised.exception.code, "timeout")
        self.assertTrue(raised.exception.retryable)


class TranscriptTests(unittest.TestCase):
    def setUp(self):
        self.adapter = load_adapter_module()

    def test_quic_varint_encoder_matches_rfc9000_boundaries(self):
        cases = {
            0: "00",
            32: "20",
            63: "3f",
            64: "4040",
            16383: "7fff",
            16384: "80004000",
            1073741823: "bfffffff",
            1073741824: "c000000040000000",
            4611686018427387903: "ffffffffffffffff",
        }

        for value, expected_hex in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.adapter._encode_quic_varint(value).hex(), expected_hex)

        with self.assertRaises(ValueError):
            self.adapter._encode_quic_varint(-1)
        with self.assertRaises(ValueError):
            self.adapter._encode_quic_varint(4611686018427387904)

    def test_transcript_matches_rust_status_hash_fixture(self):
        # Mirrors crates/cgka-conformance-simulator/tests/agent_text_stream_vectors.rs:
        # fixed stream_id 0x40..0x5f, fixed start_event_id 0xc0..0xdf,
        # record type 1 text_delta "hello", then record type 3 status "thinking".
        transcript = self.adapter.AgentTextStreamTranscript(
            stream_id_hex=bytes(range(0x40, 0x60)).hex(),
            start_message_id_hex=bytes(range(0xC0, 0xE0)).hex(),
            chunk_bytes=1024,
        )

        self.assertEqual(
            transcript.hash_hex,
            "e4ef961892a7425c1c279f747920ac18d55810732f2aa6b20b330f2666714c78",
        )
        transcript.append_text("hello")
        transcript.append_status("thinking")

        self.assertEqual(transcript.chunk_count, 2)
        self.assertEqual(
            transcript.hash_hex,
            "c0bc23a83a5607f29babfd40464c454306674b82b4653c88fd6f8dbb77e1415c",
        )

    def test_default_stream_chunking_matches_connector_compose_default(self):
        self.assertEqual(self.adapter.DEFAULT_STREAM_CHUNK_BYTES, 1024)

        transcript = self.adapter.AgentTextStreamTranscript(
            stream_id_hex="11" * 32,
            start_message_id_hex="22" * 32,
            chunk_bytes=self.adapter.DEFAULT_STREAM_CHUNK_BYTES,
        )
        transcript.append_text("a" * (self.adapter.DEFAULT_STREAM_CHUNK_BYTES + 1))

        self.assertEqual(transcript.chunk_count, 2)
        self.assertEqual(
            [len(chunk) for chunk in self.adapter.split_text_deltas("a" * 1025, 1024)],
            [1024, 1],
        )

    def test_append_only_delta_rejects_replacements(self):
        state = self.adapter.AppendOnlyTextState()

        self.assertEqual(state.suffix_for("hello"), "hello")
        self.assertEqual(state.suffix_for("hello world"), " world")
        with self.assertRaises(self.adapter.NonAppendOnlyUpdate):
            state.suffix_for("goodbye")

    def test_profile_name_reply_parser_normalizes_names_and_skip_replies(self):
        parse = self.adapter.parse_profile_name_reply

        self.assertEqual(parse('  "Hermes Agent"  '), ("name", "Hermes Agent", ""))
        self.assertEqual(parse("skip")[0], "skip")
        self.assertEqual(parse(" \n ")[0], "invalid")
        self.assertEqual(parse("x" * 81)[0], "invalid")

    def test_plain_two_word_message_is_not_legacy_tool_progress(self):
        self.assertEqual(self.adapter._tool_events_from_progress_text("hello world"), [])


class MarmotPlatformAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_chat_info_uses_marmot_group_metadata(self):
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=object(),
        )

        info = await adapter.get_chat_info("22" * 32)

        self.assertEqual(
            info,
            {
                "name": "Marmot 222222222222",
                "type": "group",
                "id": "22" * 32,
            },
        )

    async def test_invalid_explicit_account_hex_is_rejected(self):
        with self.assertRaisesRegex(
            self.adapter_module.AgentControlError,
            "MARMOT_ACCOUNT_ID_HEX must be hexadecimal",
        ):
            self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "not-hex"}),
                client=object(),
            )

    async def test_adapter_reads_auth_token_file_for_control_client(self):
        with tempfile.TemporaryDirectory() as tempdir:
            token_file = Path(tempdir) / "control.token"
            token_file.write_text("file-token\n", encoding="utf-8")
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "socket_path": str(Path(tempdir) / "dm-agent.sock"),
                        "auth_token_file": str(token_file),
                    }
                )
            )

        self.assertEqual(adapter.client.auth_token, "file-token")

    async def test_send_maps_hermes_chat_to_marmot_send_final(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.calls.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {
                    "type": "final_sent",
                    "message_ids_hex": ["aa", "bb", "cc"],
                }

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

        result = await adapter.send(
            chat_id="22" * 32,
            content="pong",
            reply_to="33" * 32,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "cc")
        self.assertEqual(result.continuation_message_ids, ("aa", "bb"))
        self.assertEqual(fake_client.calls, [("11" * 32, "22" * 32, "pong", "33" * 32)])

    async def test_tool_progress_send_maps_to_agent_operation_event(self):
        class FakeClient:
            def __init__(self):
                self.tool_events = []
                self.final_sends = []

            async def send_agent_operation_event(self, account_id_hex, group_id_hex, **kwargs):
                self.tool_events.append((account_id_hex, group_id_hex, kwargs))
                return {
                    "type": "app_event_sent",
                    "message_ids_hex": ["44" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

        result = await adapter.send(
            chat_id="22" * 32,
            content='* search: "glp-1"',
            reply_to="33" * 32,
        )

        self.assertTrue(result.success)
        self.assertTrue(result.message_id.startswith("marmot-tool-progress:"))
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.tool_events), 1)
        account_id, group_id, kwargs = fake_client.tool_events[0]
        self.assertEqual(account_id, "11" * 32)
        self.assertEqual(group_id, "22" * 32)
        self.assertEqual(kwargs["event_type"], "tool_call")
        self.assertEqual(kwargs["status"], "started")
        self.assertEqual(kwargs["name"], "search")
        self.assertEqual(kwargs["preview"], "glp-1")
        self.assertEqual(kwargs["reply_to_message_id_hex"], "33" * 32)

    async def test_tool_progress_retry_resends_failed_event(self):
        class FakeClient:
            def __init__(self):
                self.tool_events = []
                self.final_sends = []
                self.fail_next = True

            async def send_agent_operation_event(self, account_id_hex, group_id_hex, **kwargs):
                self.tool_events.append((account_id_hex, group_id_hex, kwargs))
                if self.fail_next:
                    self.fail_next = False
                    raise RuntimeError("temporary send failure")
                return {
                    "type": "app_event_sent",
                    "message_ids_hex": ["44" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

        first = await adapter.send(
            chat_id="22" * 32,
            content='* search: "glp-1"',
            reply_to="33" * 32,
        )
        self.assertFalse(first.success)
        self.assertTrue(first.message_id.startswith("marmot-tool-progress:"))

        retry = await adapter.edit_message(
            chat_id="22" * 32,
            message_id=first.message_id,
            content='* search: "glp-1"\u2589',
        )

        self.assertTrue(retry.success)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.tool_events), 2)
        self.assertEqual(fake_client.tool_events[0][0:2], fake_client.tool_events[1][0:2])
        self.assertEqual(fake_client.tool_events[0][2], fake_client.tool_events[1][2])
        self.assertEqual(fake_client.tool_events[1][2]["reply_to_message_id_hex"], "33" * 32)

    async def test_disconnect_clears_tool_progress_dedupe_cache(self):
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=object(),
        )
        adapter._tool_progress_events["marmot-tool-progress:test"] = {"event"}
        adapter._tool_progress_replies["marmot-tool-progress:test"] = "33" * 32

        await adapter.disconnect()

        self.assertEqual(adapter._tool_progress_events, {})
        self.assertEqual(adapter._tool_progress_replies, {})

    async def test_inbound_event_is_forwarded_to_hermes_message_event(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "ping",
            }
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        await adapter._consume_inbound_once(drain=True)

        self.assertEqual(len(adapter.events), 1)
        event = adapter.events[0]
        self.assertEqual(event.text, "ping")
        self.assertEqual(event.message_id, "33" * 32)
        self.assertEqual(event.source.chat_id, "22" * 32)
        self.assertEqual(event.source.chat_type, "group")
        self.assertEqual(event.source.user_id, "44" * 32)

    async def test_resync_required_event_raises_to_force_reconnect(self):
        # Regression for darkmatter#210: a resync_required event (emitted when the connector
        # dropped inbound messages on broadcast lag and could not auto-replay them) must NOT be
        # silently ignored. It must raise so the consume loop reconnects, re-running the
        # connector's catch-up and storage-backed replay to recover the missed messages.
        events = [
            {
                "type": "resync_required",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "dropped_events": 1500,
            }
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        with self.assertRaises(self.adapter_module._ResyncRequired):
            await adapter._consume_inbound_once()
        # The resync signal is not delivered to the agent as a message.
        self.assertEqual(adapter.events, [])

    async def test_consume_loop_reconnects_after_resync_then_delivers(self):
        # The consume loop must survive a resync_required (reconnect) and then deliver the
        # message recovered on the fresh subscription, rather than crashing or dropping it.
        attempts = {"n": 0}

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                attempts["n"] += 1
                # Yield control so the event loop can run the test's poll/cancel between
                # reconnect attempts (the consume loop reconnects in a tight cycle otherwise).
                await asyncio.sleep(0)
                if attempts["n"] == 1:
                    yield {
                        "type": "resync_required",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": "22" * 32,
                        "dropped_events": 3,
                    }
                elif attempts["n"] == 2:
                    yield {
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": "22" * 32,
                        "message_id_hex": "33" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "recovered after resync",
                    }
                else:
                    # No further events; idle so the loop parks instead of busy-spinning.
                    await asyncio.sleep(3600)
                    return

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        # Drive the loop just long enough to reconnect once and deliver the recovered message.
        loop_task = asyncio.ensure_future(adapter._consume_inbound_loop())
        try:
            for _ in range(300):
                if adapter.events:
                    break
                await asyncio.sleep(0.01)
        finally:
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        self.assertGreaterEqual(attempts["n"], 2, "loop should reconnect after resync")
        self.assertEqual(len(adapter.events), 1)
        self.assertEqual(adapter.events[0].text, "recovered after resync")

    async def test_slow_group_turn_does_not_block_dispatch_for_other_groups(self):
        # darkmatter#513: inbound was dispatched serially (async for -> await handle_message),
        # so a slow/hung turn in one group blocked dispatch for every group. With per-group
        # serialization, a stuck turn in group A must NOT prevent group B's turn from running.
        group_a = "aa" * 32
        group_b = "bb" * 32

        def make_event(group_id_hex, message_id_hex, text):
            return {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": group_id_hex,
                "message_id_hex": message_id_hex,
                "sender_account_id_hex": "44" * 32,
                "text": text,
            }

        events = [
            make_event(group_a, "01" * 32, "slow group A"),
            make_event(group_b, "02" * 32, "fast group B"),
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event
                # Keep the subscription open after yielding so the consume loop parks on the
                # next event instead of draining the queue (which would serialize the turns).
                await asyncio.sleep(3600)

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        release_a = asyncio.Event()
        completed = []

        async def handle_message(event):
            chat_id = event.source.chat_id
            if chat_id == group_a:
                # Group A's turn is "slow/hung": it blocks until the test releases it.
                await release_a.wait()
            completed.append(chat_id)

        adapter.handle_message = handle_message

        loop_task = asyncio.ensure_future(adapter._consume_inbound_once())
        try:
            # Group B should complete while group A is still blocked: no head-of-line blocking.
            for _ in range(200):
                if group_b in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(
                group_b,
                completed,
                "group B turn must dispatch while group A's turn is still in flight",
            )
            self.assertNotIn(
                group_a,
                completed,
                "group A turn must still be blocked (it was not released yet)",
            )

            # Releasing group A lets its turn finish too — nothing was dropped.
            release_a.set()
            for _ in range(200):
                if group_a in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(group_a, completed, "group A turn must complete once released")
        finally:
            loop_task.cancel()
            with suppress(asyncio.CancelledError):
                await loop_task
            await adapter._inbound_queue.cancel_all()

    async def test_same_group_turns_dispatch_in_fifo_order(self):
        # Per-group ordering must be preserved: two messages for the SAME group run strictly
        # in arrival order, with the second turn waiting for the first to finish.
        group = "cc" * 32

        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": group,
                "message_id_hex": "01" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "first",
            },
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": group,
                "message_id_hex": "02" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "second",
            },
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        order = []

        async def handle_message(event):
            text = event.text
            order.append(f"start:{text}")
            if text == "first":
                # Yield control after the first turn starts so that, if ordering were broken,
                # the second turn would have a chance to interleave before "first" finishes.
                await asyncio.sleep(0.05)
            order.append(f"end:{text}")

        adapter.handle_message = handle_message

        await adapter._consume_inbound_once(drain=True)

        # Strict FIFO: first fully completes before second starts.
        self.assertEqual(
            order,
            ["start:first", "end:first", "start:second", "end:second"],
        )

    async def test_first_inbound_message_prompts_for_public_profile_name(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "hello",
            }
        ]

        class FakeClient:
            def __init__(self):
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": "11" * 32,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(Path(tempdir) / "profile-state.json"),
                    }
                ),
                client=fake_client,
            )

            await adapter._consume_inbound_once(drain=True)

        self.assertEqual(adapter.events, [])
        self.assertEqual(len(fake_client.final_sends), 1)
        account_id, group_id, text, reply_to = fake_client.final_sends[0]
        self.assertEqual(account_id, "11" * 32)
        self.assertEqual(group_id, "22" * 32)
        self.assertIn("public Nostr profile name", text)
        self.assertEqual(reply_to, "33" * 32)

    async def test_profile_name_reply_publishes_profile_and_acknowledges(self):
        account_id = "11" * 32
        group_id = "22" * 32
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": account_id,
                "group_id_hex": group_id,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "  Hermes Agent  ",
            }
        ]

        class FakeClient:
            def __init__(self):
                self.published_profiles = []
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

            async def account_publish_profile(self, account_id_hex, name, display_name=None):
                self.published_profiles.append((account_id_hex, name, display_name))
                return {
                    "type": "profile_published",
                    "account_id_hex": account_id_hex,
                    "name": name,
                    "display_name": display_name,
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            state_path = Path(tempdir) / "profile-state.json"
            store = self.adapter_module.ProfileNameOnboardingStore(state_path)
            await store.mark_prompted(account_id, group_id)
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account_id,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(state_path),
                    }
                ),
                client=fake_client,
            )

            await adapter._consume_inbound_once(drain=True)

        self.assertEqual(adapter.events, [])
        self.assertEqual(fake_client.published_profiles, [(account_id, "Hermes Agent", "Hermes Agent")])
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertIn('published this agent', fake_client.final_sends[0][2])
        self.assertEqual(fake_client.final_sends[0][3], "33" * 32)

    async def test_hung_group_does_not_block_reconnect_for_other_groups(self):
        # darkmatter#513 (adversarial follow-up): the inline-dispatch fix kept the happy path
        # unblocked, but draining the per-group queue on stream end re-introduced head-of-line
        # blocking on the RECONNECT path. The queue is long-lived (owned by the adapter) and must
        # survive resync: a hung turn in group A must not hold the resync hostage, or group B —
        # delivered only on the fresh post-resync subscription — never runs.
        group_a = "aa" * 32
        group_b = "bb" * 32
        attempts = {"n": 0}

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                attempts["n"] += 1
                await asyncio.sleep(0)
                if attempts["n"] == 1:
                    # First subscription: a slow/hung group-A turn, then a resync forces reconnect.
                    yield {
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_a,
                        "message_id_hex": "01" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "slow group A",
                    }
                    yield {
                        "type": "resync_required",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_a,
                        "dropped_events": 3,
                    }
                elif attempts["n"] == 2:
                    # Fresh subscription after resync delivers group B's message.
                    yield {
                        "type": "inbound_message",
                        "account_id_hex": "11" * 32,
                        "group_id_hex": group_b,
                        "message_id_hex": "02" * 32,
                        "sender_account_id_hex": "44" * 32,
                        "text": "fast group B",
                    }
                else:
                    await asyncio.sleep(3600)
                    return

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "profile_name_onboarding": False,
                }
            ),
            client=FakeClient(),
        )

        release_a = asyncio.Event()
        completed = []

        async def handle_message(event):
            chat_id = event.source.chat_id
            if chat_id == group_a:
                await release_a.wait()  # group A's turn is hung until the test releases it
            completed.append(chat_id)

        adapter.handle_message = handle_message

        loop_task = asyncio.ensure_future(adapter._consume_inbound_loop())
        try:
            # Group B must complete even though group A's turn is still hung AND a resync had to
            # reconnect the subscription in between. If the loop joined the queue on stream end,
            # the resync (and therefore group B) would be stuck behind hung group A forever.
            for _ in range(300):
                if group_b in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(
                group_b,
                completed,
                "group B must dispatch after resync-reconnect even while group A is hung",
            )
            self.assertNotIn(
                group_a,
                completed,
                "group A turn must still be blocked (it was not released yet)",
            )
            self.assertGreaterEqual(attempts["n"], 2, "loop should reconnect after resync")

            # Releasing group A lets its turn finish too — nothing was dropped.
            release_a.set()
            for _ in range(300):
                if group_a in completed:
                    break
                await asyncio.sleep(0.01)
            self.assertIn(group_a, completed, "group A turn must complete once released")
        finally:
            loop_task.cancel()
            with suppress(asyncio.CancelledError):
                await loop_task
            await adapter._inbound_queue.cancel_all()

    async def test_concurrent_first_messages_prompt_once_and_consume_one(self):
        # darkmatter#513 (adversarial follow-up): under the new per-group concurrency, two first
        # messages for the SAME account in DIFFERENT groups could both read empty onboarding state
        # before either wrote "prompted", so both sent a prompt and both original user messages
        # were swallowed. The atomic try_claim_prompt() must let exactly one group win the prompt;
        # the other group's message must fall through to a normal agent turn (not be consumed).
        account = "11" * 32
        group_a = "aa" * 32
        group_b = "bb" * 32

        def make_event(group_id_hex, message_id_hex, text):
            return {
                "type": "inbound_message",
                "account_id_hex": account,
                "group_id_hex": group_id_hex,
                "message_id_hex": message_id_hex,
                "sender_account_id_hex": "44" * 32,
                "text": text,
            }

        class FakeClient:
            def __init__(self):
                self.final_sends = []
                self._prompt_started = asyncio.Event()
                self._release = asyncio.Event()

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                if False:  # pragma: no cover - generator shape only
                    yield {}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                # Make the first prompt-send slow so both groups are in flight concurrently:
                # the race window is widest when one send is suspended mid-flight.
                first = not self._prompt_started.is_set()
                if first:
                    self._prompt_started.set()
                    await self._release.wait()
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(Path(tempdir) / "profile-state.json"),
                    }
                ),
                client=fake_client,
            )

            turns = []

            async def handle_message(event):
                turns.append((event.source.chat_id, event.text))

            adapter.handle_message = handle_message

            # Dispatch both groups' first messages concurrently through the real per-group queue.
            adapter._inbound_queue.enqueue(
                group_a, lambda: adapter._dispatch_inbound_message(make_event(group_a, "01" * 32, "hi from A"))
            )
            adapter._inbound_queue.enqueue(
                group_b, lambda: adapter._dispatch_inbound_message(make_event(group_b, "02" * 32, "hi from B"))
            )

            # Let both dispatch tasks reach the prompt-claim/send seam, then release the slow send.
            for _ in range(200):
                if fake_client._prompt_started.is_set():
                    break
                await asyncio.sleep(0.005)
            fake_client._release.set()
            await adapter._inbound_queue.join()

        # Exactly one prompt was sent (the claim winner); the loser did NOT also prompt.
        self.assertEqual(
            len(fake_client.final_sends), 1, f"expected exactly one prompt, got {fake_client.final_sends}"
        )
        # Exactly one original message was consumed as a prompt trigger; the other fell through
        # to a normal agent turn instead of being swallowed.
        self.assertEqual(len(turns), 1, f"expected exactly one normal turn, got {turns}")
        # The group that was prompted is NOT the group that ran a normal turn.
        prompted_group = fake_client.final_sends[0][1]
        turn_group = turns[0][0]
        self.assertNotEqual(prompted_group, turn_group)
        self.assertEqual({prompted_group, turn_group}, {group_a, group_b})

    async def test_profile_prompt_send_failure_releases_claim_for_retry(self):
        # If the claim winner cannot deliver the prompt, it must release the slot (clear) so a
        # later inbound message retries — otherwise the account is stuck "prompted" with no
        # prompt ever delivered and every message is silently swallowed.
        account = "11" * 32
        group = "22" * 32

        class FakeClient:
            def __init__(self):
                self.calls = 0
                self.final_sends = []

            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                if False:  # pragma: no cover - generator shape only
                    yield {}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.calls += 1
                if self.calls == 1:
                    # First prompt send fails: _send_final_direct maps a raised exception to
                    # SendResult(success=False), which must trigger the claim release.
                    raise RuntimeError("transient send failure")
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["55" * 32]}

        with tempfile.TemporaryDirectory() as tempdir:
            state_path = Path(tempdir) / "profile-state.json"
            fake_client = FakeClient()
            adapter = self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(
                    extra={
                        "account_id_hex": account,
                        "profile_name_onboarding": True,
                        "profile_onboarding_state_path": str(state_path),
                    }
                ),
                client=fake_client,
            )
            store = adapter.profile_name_onboarding

            event = {
                "type": "inbound_message",
                "account_id_hex": account,
                "group_id_hex": group,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "hi",
            }

            # First attempt: claim succeeds, send fails, slot must be released (not "prompted").
            consumed_first = await adapter._maybe_handle_profile_name_onboarding(event)
            self.assertFalse(consumed_first, "failed prompt must not consume the message")
            self.assertEqual(await store.get(account), {}, "claim must be released after send failure")

            # Second attempt: a later message retries and now succeeds.
            consumed_second = await adapter._maybe_handle_profile_name_onboarding(event)
            self.assertTrue(consumed_second, "retry should prompt and consume the message")
            self.assertEqual(len(fake_client.final_sends), 1)
            self.assertEqual((await store.get(account)).get("status"), "prompted")

    async def test_progressive_edit_stream_finalizes_then_sends_durable_message(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.stream_begin_args = (account_id_hex, group_id_hex, tuple(quic_candidates))
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, final_text, transcript_hash_hex, chunk_count):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {
                    "type": "final_sent",
                    "message_ids_hex": ["88" * 32],
                }

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        first = await adapter.send("22" * 32, "hel\u2589")
        self.assertTrue(first.success)
        self.assertEqual(first.message_id, "marmot-stream:" + "55" * 32)

        edited = await adapter.edit_message("22" * 32, first.message_id, "hello\u2589")
        self.assertTrue(edited.success)

        final = await adapter.edit_message("22" * 32, first.message_id, "hello", finalize=True)

        self.assertTrue(final.success)
        self.assertEqual(final.message_id, "77" * 32)
        self.assertEqual(
            fake_client.stream_appends,
            [("55" * 32, "hel"), ("55" * 32, "lo")],
        )
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(fake_client.stream_finalizes[0][1], "hello")
        self.assertEqual(fake_client.stream_finalizes[0][3], 2)
        self.assertEqual(fake_client.final_sends, [])

    async def test_draft_stream_skips_empty_visible_frames(self):
        class FakeClient:
            def __init__(self):
                self.stream_begins = []
                self.stream_appends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.stream_begins.append((account_id_hex, group_id_hex, tuple(quic_candidates)))
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        result = await adapter.send_draft("22" * 32, 1, "\u2589")

        self.assertTrue(result.success)
        self.assertEqual(fake_client.stream_begins, [])
        self.assertEqual(fake_client.stream_appends, [])

    async def test_draft_stream_clear_cancels_existing_preview(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_cancels = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        first = await adapter.send_draft("22" * 32, 1, "Let me search")
        cleared = await adapter.send_draft("22" * 32, 1, "\u2589")

        self.assertTrue(first.success)
        self.assertTrue(cleared.success)
        self.assertEqual(fake_client.stream_appends, [("55" * 32, "Let me search")])
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "draft cleared")])
        self.assertEqual(adapter._draft_streams, {})

    async def test_draft_stream_rotation_cancels_previous_preview(self):
        class FakeClient:
            def __init__(self):
                self.next_stream = 0
                self.stream_appends = []
                self.stream_cancels = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.next_stream += 1
                stream_byte = f"{0x54 + self.next_stream:02x}"
                start_byte = f"{0x64 + self.next_stream:02x}"
                return {
                    "type": "stream_begun",
                    "stream_id_hex": stream_byte * 32,
                    "start_message_id_hex": start_byte * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        first = await adapter.send_draft("22" * 32, 1, "Let me search")
        second = await adapter.send_draft("22" * 32, 2, "Based on")

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertEqual(
            fake_client.stream_appends,
            [("55" * 32, "Let me search"), ("56" * 32, "Based on")],
        )
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "superseded by newer draft")])

    async def test_new_preview_cancels_previous_chat_stream(self):
        class FakeClient:
            def __init__(self):
                self.next_stream = 0
                self.stream_cancels = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.next_stream += 1
                stream_byte = f"{0x54 + self.next_stream:02x}"
                start_byte = f"{0x64 + self.next_stream:02x}"
                return {
                    "type": "stream_begun",
                    "stream_id_hex": stream_byte * 32,
                    "start_message_id_hex": start_byte * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                return {"type": "ack"}

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        first = await adapter.send("22" * 32, "hel\u2589")
        second = await adapter.send("22" * 32, "hello\u2589")

        self.assertTrue(first.success)
        self.assertTrue(second.success)
        self.assertEqual(
            fake_client.stream_cancels,
            [("55" * 32, "superseded by newer preview")],
        )
        self.assertEqual(second.message_id, "marmot-stream:" + "56" * 32)

    async def test_send_final_extension_finalizes_stream(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, final_text, transcript_hash_hex, chunk_count):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        preview = await adapter.send("22" * 32, "Based on my research\u2589")
        final = await adapter.send("22" * 32, "Based on my research, here's the answer")

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(final.message_id, "77" * 32)
        self.assertEqual(fake_client.final_sends, [])
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(
            fake_client.stream_finalizes[0][1],
            "Based on my research, here's the answer",
        )

    async def test_whitespace_mismatched_final_replaces_preview_without_duplication(self):
        class FakeClient:
            def __init__(self):
                self.stream_finalizes = []
                self.stream_cancels = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, final_text, transcript_hash_hex, chunk_count):
                self.stream_finalizes.append((stream_id_hex, final_text))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {"type": "final_sent", "message_ids_hex": ["88" * 32]}

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        # The preview snapshot keeps a trailing space before the cursor; the
        # final send is the rstripped text. The mismatch must not duplicate or
        # concatenate text in the durable final.
        segment = "\n\nLet me use the web search tool to find current titanium prices:"
        preview = await adapter.send("22" * 32, segment + " \u2589")
        final = await adapter.send("22" * 32, segment)

        self.assertTrue(preview.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(
            fake_client.stream_cancels,
            [("55" * 32, "final text was not append-only")],
        )
        self.assertEqual(len(fake_client.final_sends), 1)
        self.assertEqual(fake_client.final_sends[0][2], segment)

    async def test_final_send_cancels_non_append_only_draft_preview(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.stream_cancels = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, final_text, transcript_hash_hex, chunk_count):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {"type": "stream_finalized", "stream_id_hex": stream_id_hex}

            async def stream_cancel(self, stream_id_hex, reason=None):
                self.stream_cancels.append((stream_id_hex, reason))
                return {"type": "ack"}

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {
                    "type": "final_sent",
                    "message_ids_hex": ["88" * 32],
                }

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        draft = await adapter.send_draft("22" * 32, 1, "Let me search")
        final = await adapter.send("22" * 32, "Based on my search")

        self.assertTrue(draft.success)
        self.assertTrue(final.success)
        self.assertEqual(fake_client.stream_appends, [("55" * 32, "Let me search")])
        self.assertEqual(fake_client.stream_finalizes, [])
        self.assertEqual(fake_client.stream_cancels, [("55" * 32, "final text was not append-only")])
        self.assertEqual(
            fake_client.final_sends,
            [("11" * 32, "22" * 32, "Based on my search", None)],
        )


if __name__ == "__main__":
    unittest.main()
