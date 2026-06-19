import { describe, expect, it } from "vitest";
import type { ChannelMessageSendTextContext } from "openclaw/plugin-sdk/channel-outbound";

import type { MarmotAgentControlClient } from "../src/client.js";
import { createMarmotMessageAdapter, receiptFromMessageIds } from "../src/outbound.js";

const HEX32 = (b: string) => b.repeat(32);

interface SendFinalCall {
  accountIdHex: string;
  groupIdHex: string;
  text: string;
  replyToMessageIdHex?: string | null;
}

/** Minimal stub of the control client capturing send_final calls. */
function stubClient(calls: SendFinalCall[]): MarmotAgentControlClient {
  return {
    async sendFinal(
      accountIdHex: string,
      groupIdHex: string,
      text: string,
      replyToMessageIdHex?: string | null,
    ) {
      calls.push({ accountIdHex, groupIdHex, text, replyToMessageIdHex });
      return { type: "final_sent", message_ids_hex: [HEX32("ab")] };
    },
  } as unknown as MarmotAgentControlClient;
}

describe("createMarmotMessageAdapter", () => {
  it("routes a durable text send to send_final and returns a receipt", async () => {
    const calls: SendFinalCall[] = [];
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({
        client: stubClient(calls),
        marmotAccountIdHex: HEX32("aa"),
      }),
      nowMs: () => 1234,
    });

    const ctx = {
      cfg: {},
      to: HEX32("cc"),
      text: "done",
      replyToId: HEX32("dd"),
    } as unknown as ChannelMessageSendTextContext;

    const result = await adapter.send!.text!(ctx);

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      accountIdHex: HEX32("aa"),
      groupIdHex: HEX32("cc"),
      text: "done",
      replyToMessageIdHex: HEX32("dd"),
    });
    expect(result.receipt.primaryPlatformMessageId).toBe(HEX32("ab"));
    expect(result.receipt.platformMessageIds).toEqual([HEX32("ab")]);
    expect(result.receipt.parts[0]).toMatchObject({ kind: "text", index: 0 });
    expect(result.receipt.sentAt).toBe(1234);
  });

  it("declares only durable text + replyTo capabilities (no unproven live caps)", () => {
    const adapter = createMarmotMessageAdapter({
      resolveTarget: () => ({ client: stubClient([]), marmotAccountIdHex: HEX32("aa") }),
    });
    expect(adapter.durableFinal?.capabilities).toEqual({ text: true, replyTo: true });
    expect(Object.prototype.hasOwnProperty.call(adapter, "live")).toBe(false);
  });
});

describe("receiptFromMessageIds", () => {
  it("throws when dm-agent returns no message ids", () => {
    expect(() => receiptFromMessageIds([], 0)).toThrow();
  });

  it("builds parts for each durable message id", () => {
    const receipt = receiptFromMessageIds([HEX32("ab"), HEX32("ac")], 7);
    expect(receipt.platformMessageIds).toEqual([HEX32("ab"), HEX32("ac")]);
    expect(receipt.parts.map((p) => p.index)).toEqual([0, 1]);
    expect(receipt.sentAt).toBe(7);
  });
});
