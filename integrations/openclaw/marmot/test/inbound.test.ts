import { describe, expect, it } from "vitest";

import type { AgentControlEvent } from "../src/client.js";
import { MarmotInboundBridge, type InboundSubscribeClient } from "../src/inbound.js";

const HEX32 = (b: string) => b.repeat(32);

function inboundMessage(messageId: string): AgentControlEvent {
  return {
    type: "inbound_message",
    account_id_hex: HEX32("aa"),
    group_id_hex: HEX32("cc"),
    message_id_hex: messageId,
    sender_account_id_hex: HEX32("bb"),
    text: "hello agent",
  };
}

/** Client whose first subscription yields `firstBatch`, later ones yield nothing. */
function makeClient(firstBatch: AgentControlEvent[]): {
  client: InboundSubscribeClient;
  subscribeCalls: () => number;
} {
  let calls = 0;
  const client = {
    async *subscribeInbound(): AsyncGenerator<AgentControlEvent> {
      calls += 1;
      if (calls === 1) {
        for (const event of firstBatch) {
          yield event;
        }
      }
    },
  } as unknown as InboundSubscribeClient;
  return { client, subscribeCalls: () => calls };
}

describe("MarmotInboundBridge", () => {
  it("delivers inbound messages, dedupes by id, and surfaces resync", async () => {
    const resync: AgentControlEvent = {
      type: "resync_required",
      account_id_hex: null,
      group_id_hex: null,
      dropped_events: 3,
    };
    const { client } = makeClient([
      inboundMessage(HEX32("d1")),
      inboundMessage(HEX32("d1")), // duplicate id
      inboundMessage(HEX32("d2")),
      resync,
    ]);

    const delivered: string[] = [];
    let droppedEvents = -1;
    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 1,
      onMessage: (message) => {
        delivered.push(message.messageIdHex);
      },
      onResync: ({ droppedEvents: dropped }) => {
        droppedEvents = dropped;
        controller.abort();
      },
    });

    await bridge.run(controller.signal);

    expect(delivered).toEqual([HEX32("d1"), HEX32("d2")]);
    expect(droppedEvents).toBe(3);
  });

  it("stops cleanly when the signal aborts", async () => {
    const { client, subscribeCalls } = makeClient([]);
    const controller = new AbortController();
    const bridge = new MarmotInboundBridge(client, {
      reconnectDelayMs: 5,
      onMessage: () => {},
    });

    const run = bridge.run(controller.signal);
    controller.abort();
    await run;

    expect(subscribeCalls()).toBeGreaterThanOrEqual(1);
  });
});
