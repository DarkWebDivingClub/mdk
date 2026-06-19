import { describe, expect, it } from "vitest";

import { resolveMarmotChannelAccount } from "../src/channel.js";

type Cfg = Parameters<typeof resolveMarmotChannelAccount>[0];

describe("resolveMarmotChannelAccount", () => {
  it("uses the root slice in single-account mode", () => {
    const cfg = { channels: { marmot: { socketPath: "/root.sock" } } } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").socketPath).toBe("/root.sock");
    expect(resolveMarmotChannelAccount(cfg, null).socketPath).toBe("/root.sock");
  });

  it("resolves accounts.default (and named accounts) in multi-account mode", () => {
    const cfg = {
      channels: {
        marmot: {
          accounts: {
            default: { socketPath: "/d.sock" },
            alice: { socketPath: "/a.sock" },
          },
        },
      },
    } as unknown as Cfg;
    expect(resolveMarmotChannelAccount(cfg, "default").socketPath).toBe("/d.sock");
    expect(resolveMarmotChannelAccount(cfg, "alice").socketPath).toBe("/a.sock");
    expect(resolveMarmotChannelAccount(cfg, null).socketPath).toBe("/d.sock");
  });

  it("throws for an unknown account id in multi-account mode", () => {
    const cfg = {
      channels: { marmot: { accounts: { default: { socketPath: "/d.sock" } } } },
    } as unknown as Cfg;
    expect(() => resolveMarmotChannelAccount(cfg, "bob")).toThrow(/unknown Marmot account/);
  });
});
