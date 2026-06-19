// Outbound message adapter (durable kind-9 sends) for the OpenClaw channel.
//
// Built with the current `openclaw/plugin-sdk/channel-outbound` message
// lifecycle: `send.text` is the durable final path and maps onto dm-agent's
// `send_final`. Live QUIC previews are layered on separately via the
// finalizable-live-preview adapter (see src/live.ts) and are only declared as
// capabilities once backed by contract tests.

import {
  defineChannelMessageAdapter,
  type ChannelMessageSendTextContext,
  type MessageReceipt,
  type MessageReceiptPart,
} from "openclaw/plugin-sdk/channel-outbound";

import type { MarmotAgentControlClient } from "./client.js";

/** Marmot send target resolved from OpenClaw config + the inbound chat id. */
export interface ResolvedMarmotTarget {
  client: MarmotAgentControlClient;
  marmotAccountIdHex: string;
}

export interface MarmotMessageAdapterDeps {
  /**
   * Resolve the dm-agent client and the Marmot agent account for an outbound
   * send. `accountId` is OpenClaw's per-account id; `cfg` is the gateway config.
   */
  resolveTarget: (
    cfg: unknown,
    accountId?: string | null,
  ) => ResolvedMarmotTarget | Promise<ResolvedMarmotTarget>;
  nowMs?: () => number;
}

/** Build an OpenClaw `MessageReceipt` from dm-agent's durable message ids. */
export function receiptFromMessageIds(
  messageIdsHex: string[],
  nowMs: number,
): MessageReceipt {
  if (messageIdsHex.length === 0) {
    throw new Error("dm-agent send_final returned no durable message ids");
  }
  const parts: MessageReceiptPart[] = messageIdsHex.map((id, index) => ({
    platformMessageId: id,
    kind: "text",
    index,
  }));
  return {
    primaryPlatformMessageId: messageIdsHex[0],
    platformMessageIds: messageIdsHex,
    parts,
    sentAt: nowMs,
  };
}

/**
 * Define the Marmot channel message adapter. The durable text send routes to
 * dm-agent `send_final`; the chat id (`ctx.to`) is the Marmot group id hex and
 * `ctx.replyToId` is a durable message id hex.
 */
export function createMarmotMessageAdapter(deps: MarmotMessageAdapterDeps) {
  const now = deps.nowMs ?? (() => Date.now());
  return defineChannelMessageAdapter({
    id: "marmot",
    durableFinal: {
      // Marmot durable sends are plain encrypted kind-9 text with optional reply.
      capabilities: { text: true, replyTo: true },
    },
    send: {
      text: async (ctx: ChannelMessageSendTextContext) => {
        const { client, marmotAccountIdHex } = await deps.resolveTarget(
          ctx.cfg,
          ctx.accountId,
        );
        const response = await client.sendFinal(
          marmotAccountIdHex,
          ctx.to,
          ctx.text,
          ctx.replyToId ?? null,
        );
        return { receipt: receiptFromMessageIds(response.message_ids_hex, now()) };
      },
    },
    receive: {
      defaultAckPolicy: "after_agent_dispatch",
      supportedAckPolicies: ["after_agent_dispatch", "manual"],
    },
  });
}
