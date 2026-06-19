// The Marmot OpenClaw channel plugin definition.
//
// Composed with `createChatChannelPlugin`: meta + capabilities + a config
// adapter that resolves a Marmot account from the `channels.marmot` config (or
// MARMOT_* env), the durable/live message adapter, DM allowlist security, and
// reply threading. Outbound (durable send + live preview) flows through the
// message adapter; inbound is driven by src/inbound-runtime.ts.

import {
  createChatChannelPlugin,
  type OpenClawConfig,
} from "openclaw/plugin-sdk/channel-core";

import { resolveSingleAccount } from "./account.js";
import {
  clientForAccount,
  marmotChannelConfigSchema,
  resolveMarmotAccount,
  type MarmotChannelAccountConfig,
  type ResolvedMarmotAccount,
} from "./config.js";
import { createMarmotMessageAdapter } from "./outbound.js";

export const MARMOT_CHANNEL_ID = "marmot";

interface MarmotChannelsConfig {
  channels?: {
    marmot?: MarmotChannelAccountConfig & {
      accounts?: Record<string, MarmotChannelAccountConfig>;
    };
  };
}

function marmotSlice(cfg: OpenClawConfig): NonNullable<MarmotChannelsConfig["channels"]>["marmot"] {
  return (cfg as unknown as MarmotChannelsConfig).channels?.marmot ?? {};
}

/** Resolve a Marmot account for a (possibly multi-account) OpenClaw config. */
export function resolveMarmotChannelAccount(
  cfg: OpenClawConfig,
  accountId?: string | null,
): ResolvedMarmotAccount {
  const slice = marmotSlice(cfg);
  // Multi-account mode: every account (including "default") lives under
  // `channels.marmot.accounts.<id>`. Single-account mode: settings live on the
  // `channels.marmot` slice itself.
  if (slice?.accounts) {
    const selectedId = accountId ?? "default";
    const accountConfig = slice.accounts[selectedId];
    if (!accountConfig) {
      throw new Error(`unknown Marmot account id: ${selectedId}`);
    }
    return resolveMarmotAccount(accountConfig, selectedId);
  }
  return resolveMarmotAccount(slice, accountId ?? null);
}

/** Build the Marmot channel plugin for registration with OpenClaw. */
export function createMarmotChannelPlugin() {
  return createChatChannelPlugin<ResolvedMarmotAccount>({
    base: {
      id: MARMOT_CHANNEL_ID,
      meta: {
        id: MARMOT_CHANNEL_ID,
        label: "Marmot",
        selectionLabel: "Marmot",
        docsPath: "channels/marmot",
        blurb: "End-to-end encrypted Marmot groups through the local dm-agent connector.",
        markdownCapable: true,
      },
      capabilities: {
        chatTypes: ["direct", "group"],
        reply: true,
        media: false,
        blockStreaming: true,
      },
      configSchema: marmotChannelConfigSchema(),
      config: {
        listAccountIds: (cfg) => {
          const accounts = marmotSlice(cfg)?.accounts;
          return accounts ? Object.keys(accounts) : ["default"];
        },
        resolveAccount: resolveMarmotChannelAccount,
      },
      message: createMarmotMessageAdapter({
        resolveTarget: async (cfg, accountId) => {
          const resolved = resolveMarmotChannelAccount(cfg as OpenClawConfig, accountId);
          const client = clientForAccount(resolved);
          const marmotAccountIdHex =
            resolved.marmotAccountIdHex ?? (await resolveSingleAccount(client));
          return { client, marmotAccountIdHex };
        },
      }),
    },
    security: {
      dm: {
        channelKey: MARMOT_CHANNEL_ID,
        resolvePolicy: (account) => account.dmPolicy ?? null,
        resolveAllowFrom: (account) => account.allowFrom,
        defaultPolicy: "allowlist",
      },
    },
    threading: {
      topLevelReplyToMode: "reply",
    },
  });
}
