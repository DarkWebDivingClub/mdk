import { createServer, type Server, type Socket } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AgentControlError,
  MarmotAgentControlClient,
  normalizeHex,
} from "../src/client.js";

const PROTOCOL = "marmot.agent-control.v1";
const HEX32 = (b: string) => b.repeat(32);

function send(socket: Socket, id: unknown, payload: Record<string, unknown>): void {
  socket.write(`${JSON.stringify({ marmot_agent_control: PROTOCOL, id, ...payload })}\n`);
}

/** Minimal in-memory dm-agent control socket for exercising the client. */
function handleRequest(socket: Socket, req: Record<string, unknown>): void {
  const id = req.id;
  switch (req.type) {
    case "account_list":
      send(socket, id, {
        type: "account_list",
        accounts: [{ account_id_hex: HEX32("aa"), label: "agent", local_signing: true }],
      });
      break;
    case "send_final":
      send(socket, id, { type: "final_sent", message_ids_hex: [HEX32("ab")] });
      break;
    case "explode":
      send(socket, id, { type: "error", code: "bad_request", message: "nope" });
      break;
    case "wrong_id":
      send(socket, "some-other-id", { type: "ack" });
      break;
    case "wrong_proto":
      socket.write(`${JSON.stringify({ marmot_agent_control: "nope", id, type: "ack" })}\n`);
      break;
    case "subscribe_inbound":
      send(socket, id, { type: "ack" });
      send(socket, id, {
        type: "inbound_message",
        account_id_hex: req.account_id_hex ?? HEX32("aa"),
        group_id_hex: HEX32("cc"),
        message_id_hex: HEX32("dd"),
        sender_account_id_hex: HEX32("bb"),
        text: "hello agent",
      });
      send(socket, id, {
        type: "resync_required",
        account_id_hex: null,
        group_id_hex: null,
        dropped_events: 3,
      });
      socket.end();
      break;
    default:
      send(socket, id, { type: "error", code: "unknown", message: "unknown type" });
  }
}

function startServer(socketPath: string): Promise<Server> {
  const server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      let index = buffer.indexOf(0x0a);
      while (index !== -1) {
        const line = buffer.subarray(0, index);
        buffer = buffer.subarray(index + 1);
        if (line.length > 0) {
          handleRequest(socket, JSON.parse(line.toString("utf8")));
        }
        index = buffer.indexOf(0x0a);
      }
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve(server));
  });
}

describe("MarmotAgentControlClient", () => {
  let dir: string;
  let socketPath: string;
  let server: Server;
  let client: MarmotAgentControlClient;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "oc-marmot-"));
    socketPath = join(dir, "a.sock");
    server = await startServer(socketPath);
    client = new MarmotAgentControlClient({ socketPath, requestTimeoutMs: 2000 });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  });

  it("round-trips a typed request", async () => {
    const res = await client.accountList();
    expect(res.accounts).toHaveLength(1);
    expect(res.accounts[0]?.label).toBe("agent");
  });

  it("returns durable message ids from send_final", async () => {
    const res = await client.sendFinal(HEX32("aa"), HEX32("cc"), "done");
    expect(res.message_ids_hex).toEqual([HEX32("ab")]);
  });

  it("maps an error response to a typed AgentControlError", async () => {
    await expect(client.request({ type: "explode" })).rejects.toMatchObject({
      name: "AgentControlError",
      code: "bad_request",
    });
  });

  it("rejects a mismatched response id", async () => {
    await expect(client.request({ type: "wrong_id" })).rejects.toMatchObject({
      code: "id_mismatch",
    });
  });

  it("rejects a wrong protocol tag", async () => {
    await expect(client.request({ type: "wrong_proto" })).rejects.toMatchObject({
      code: "wrong_protocol",
    });
  });

  it("streams inbound events after the ack until EOF", async () => {
    const events = [];
    for await (const event of client.subscribeInbound({ accountIdHex: HEX32("aa") })) {
      events.push(event);
    }
    expect(events.map((e) => e.type)).toEqual(["inbound_message", "resync_required"]);
    expect(events[0]).toMatchObject({ text: "hello agent", group_id_hex: HEX32("cc") });
  });

  it("surfaces a connection failure as a retryable error", async () => {
    const broken = new MarmotAgentControlClient({
      socketPath: join(dir, "does-not-exist.sock"),
      requestTimeoutMs: 1000,
    });
    await expect(broken.accountList()).rejects.toMatchObject({ retryable: true });
  });
});

describe("normalizeHex", () => {
  it("lowercases and strips a 0x prefix", () => {
    expect(normalizeHex("0xABCD")).toBe("abcd");
  });

  it("rejects empty and non-hex input", () => {
    expect(() => normalizeHex("")).toThrow(AgentControlError);
    expect(() => normalizeHex("zz")).toThrow(AgentControlError);
    expect(() => normalizeHex("abc")).toThrow(AgentControlError);
  });
});
