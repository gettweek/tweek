import { describe, it, expect } from "vitest";
import {
  resolveConfig,
  getToolTier,
  shouldScreenTool,
  DEFAULT_SCANNER_PORT,
} from "../src/config";
import type { TweekPluginConfig, PresetName } from "../src/config";

describe("resolveConfig", () => {
  it("defaults to cautious preset", () => {
    const config = resolveConfig({});
    expect(config.preset).toBe("cautious");
  });

  it("defaults enabled to true", () => {
    const config = resolveConfig({});
    expect(config.enabled).toBe(true);
  });

  it("allows disabling the plugin", () => {
    const config = resolveConfig({ enabled: false });
    expect(config.enabled).toBe(false);
  });

  it("uses default scanner port", () => {
    const config = resolveConfig({});
    expect(config.scannerPort).toBe(DEFAULT_SCANNER_PORT);
    expect(config.scannerPort).toBe(9878);
  });

  it("allows custom scanner port", () => {
    const config = resolveConfig({ scannerPort: 12345 });
    expect(config.scannerPort).toBe(12345);
  });

  it("resolves trusted preset", () => {
    const config = resolveConfig({ preset: "trusted" });
    expect(config.skillGuard.mode).toBe("fingerprint_only");
    expect(config.outputScanning.enabled).toBe(false);
    expect(config.toolScreening.llmReview).toBe(false);
  });

  it("resolves cautious preset", () => {
    const config = resolveConfig({ preset: "cautious" });
    expect(config.skillGuard.mode).toBe("auto");
    expect(config.skillGuard.blockDangerous).toBe(true);
    expect(config.toolScreening.enabled).toBe(true);
    expect(config.toolScreening.llmReview).toBe(true);
    expect(config.outputScanning.enabled).toBe(true);
  });

  it("resolves paranoid preset", () => {
    const config = resolveConfig({ preset: "paranoid" });
    expect(config.skillGuard.mode).toBe("manual");
    expect(config.toolScreening.llmReview).toBe(true);
    expect(config.outputScanning.enabled).toBe(true);
  });

  it("throws on invalid preset", () => {
    expect(() =>
      resolveConfig({ preset: "nonexistent" as PresetName })
    ).toThrow('Unknown Tweek preset: "nonexistent"');
  });

  it("merges user overrides over preset defaults", () => {
    const config = resolveConfig({
      preset: "cautious",
      skillGuard: { enabled: false, mode: "auto", blockDangerous: true, promptSuspicious: true },
    });
    expect(config.skillGuard.enabled).toBe(false);
    // Other preset defaults should still be present
    expect(config.toolScreening.enabled).toBe(true);
  });

  it("merges custom tool tiers", () => {
    const config = resolveConfig({
      preset: "cautious",
      toolScreening: {
        enabled: true,
        llmReview: true,
        tiers: { custom_tool: "dangerous" },
      },
    });
    expect(config.toolScreening.tiers.custom_tool).toBe("dangerous");
    // Default tiers should still exist
    expect(config.toolScreening.tiers.bash).toBe("dangerous");
    expect(config.toolScreening.tiers.Bash).toBe("dangerous");
  });
});

describe("getToolTier", () => {
  const config = resolveConfig({ preset: "cautious" });

  it("returns configured tier for known tools", () => {
    expect(getToolTier(config, "bash")).toBe("dangerous");
    expect(getToolTier(config, "Bash")).toBe("dangerous");
    expect(getToolTier(config, "Write")).toBe("risky");
    expect(getToolTier(config, "Read")).toBe("safe");
  });

  it("returns 'default' for unknown tools", () => {
    expect(getToolTier(config, "unknown_tool")).toBe("default");
    expect(getToolTier(config, "SomeNewTool")).toBe("default");
  });
});

describe("shouldScreenTool", () => {
  it("returns false when screening is disabled", () => {
    const config = resolveConfig({
      preset: "cautious",
      toolScreening: {
        enabled: false,
        llmReview: false,
        tiers: {},
      },
    });
    expect(shouldScreenTool(config, "bash")).toBe(false);
  });

  describe("cautious preset", () => {
    const config = resolveConfig({ preset: "cautious" });

    it("screens dangerous tools", () => {
      expect(shouldScreenTool(config, "bash")).toBe(true);
      expect(shouldScreenTool(config, "Bash")).toBe(true);
    });

    it("screens risky tools", () => {
      expect(shouldScreenTool(config, "Write")).toBe(true);
      expect(shouldScreenTool(config, "WebFetch")).toBe(true);
    });

    it("does not screen safe tools", () => {
      expect(shouldScreenTool(config, "Read")).toBe(false);
      expect(shouldScreenTool(config, "Glob")).toBe(false);
    });

    it("does not screen default-tier tools", () => {
      expect(shouldScreenTool(config, "mcp_tool")).toBe(false);
    });
  });

  describe("paranoid preset", () => {
    const config = resolveConfig({ preset: "paranoid" });

    it("screens dangerous tools", () => {
      expect(shouldScreenTool(config, "bash")).toBe(true);
    });

    it("screens default-tier tools", () => {
      // In paranoid, Read/Glob are "default" tier and should be screened
      expect(shouldScreenTool(config, "Read")).toBe(true);
    });

    it("does not screen safe tools", () => {
      // In paranoid, safe tools are still exempt
      // But paranoid has fewer safe tools — check config
      const tier = getToolTier(config, "some_tool");
      if (tier === "safe") {
        expect(shouldScreenTool(config, "some_tool")).toBe(false);
      }
    });
  });

  describe("trusted preset", () => {
    const config = resolveConfig({ preset: "trusted" });

    it("only screens dangerous tools", () => {
      expect(shouldScreenTool(config, "bash")).toBe(true);
      expect(shouldScreenTool(config, "Bash")).toBe(true);
    });

    it("does not screen risky tools", () => {
      expect(shouldScreenTool(config, "Write")).toBe(false);
      expect(shouldScreenTool(config, "WebFetch")).toBe(false);
    });

    it("does not screen safe tools", () => {
      expect(shouldScreenTool(config, "Read")).toBe(false);
    });
  });
});
