/**
 * Tweek OpenClaw Plugin — Config Guard
 *
 * Protects Tweek's own security configuration from being weakened
 * by the AI agent. Detects security downgrades, feature disables,
 * and tier reductions — pure TypeScript, no server call needed.
 */

import type { TweekPluginConfig } from "./config";

/** Result of a config change check */
export interface ConfigChangeResult {
  allow: boolean;
  blockReason?: string;
  warnings: string[];
}

/** Severity of a detected config change */
type ChangeSeverity = "critical" | "high" | "medium";

/** A single detected security-relevant config change */
interface DetectedChange {
  description: string;
  severity: ChangeSeverity;
  isDowngrade: boolean;
  isDisable: boolean;
}

type LogFn = (msg: string) => void;

/** Preset security ranking: higher = more secure */
const PRESET_RANK: Record<string, number> = {
  paranoid: 3,
  cautious: 2,
  trusted: 1,
};

/** Tier security ranking: higher = more restrictive */
const TIER_RANK: Record<string, number> = {
  dangerous: 4,
  risky: 3,
  default: 2,
  safe: 1,
};

/**
 * Config tamper protection guard.
 *
 * Analyzes old vs new configuration to detect security downgrades,
 * feature disables, and tier reductions. Operates entirely in
 * TypeScript — no server call needed for config diffing.
 */
export class ConfigGuard {
  private config: TweekPluginConfig;
  private log: LogFn;

  constructor(config: TweekPluginConfig, log: LogFn = console.error) {
    this.config = config;
    this.log = log;
  }

  /**
   * Check a config change for security downgrades.
   *
   * @param oldConfig - The previous configuration object
   * @param newConfig - The proposed new configuration object
   * @returns Check result with allow/block decision and warnings
   */
  check(
    oldConfig: Record<string, unknown>,
    newConfig: Record<string, unknown>
  ): ConfigChangeResult {
    if (!this.config.configProtection.enabled) {
      return { allow: true, warnings: [] };
    }

    const oldTweek = extractTweekSection(oldConfig);
    const newTweek = extractTweekSection(newConfig);

    if (!oldTweek || !newTweek) {
      return { allow: true, warnings: [] };
    }

    const changes = detectChanges(oldTweek, newTweek);

    if (changes.length === 0) {
      return { allow: true, warnings: [] };
    }

    const warnings = changes.map((c) => `[${c.severity}] ${c.description}`);

    // Check if any change should trigger a block
    const hasDowngrade = changes.some((c) => c.isDowngrade);
    const hasDisable = changes.some((c) => c.isDisable);

    if (this.config.configProtection.blockDowngrades && hasDowngrade) {
      return {
        allow: false,
        blockReason: `Tweek Security: config downgrade blocked — ${changes.filter((c) => c.isDowngrade).map((c) => c.description).join("; ")}`,
        warnings,
      };
    }

    if (this.config.configProtection.blockDisable && hasDisable) {
      return {
        allow: false,
        blockReason: `Tweek Security: disabling security features blocked — ${changes.filter((c) => c.isDisable).map((c) => c.description).join("; ")}`,
        warnings,
      };
    }

    return { allow: true, warnings };
  }
}

/**
 * Extract the tweek plugin config section from a full config object.
 */
function extractTweekSection(
  config: Record<string, unknown>
): Record<string, unknown> | null {
  // Try common nesting patterns
  if (config.tweek && typeof config.tweek === "object") {
    return config.tweek as Record<string, unknown>;
  }

  // Check plugins.entries.tweek.config
  const plugins = config.plugins as Record<string, unknown> | undefined;
  if (plugins) {
    const entries = plugins.entries as Record<string, unknown> | undefined;
    if (entries) {
      const tweekEntry = entries.tweek as Record<string, unknown> | undefined;
      if (tweekEntry?.config && typeof tweekEntry.config === "object") {
        return tweekEntry.config as Record<string, unknown>;
      }
    }
  }

  // If the config itself looks like a tweek config (has preset or enabled)
  if ("preset" in config || "skillGuard" in config) {
    return config;
  }

  return null;
}

/**
 * Detect security-relevant changes between old and new tweek configs.
 */
function detectChanges(
  oldCfg: Record<string, unknown>,
  newCfg: Record<string, unknown>
): DetectedChange[] {
  const changes: DetectedChange[] = [];

  // 1. Master switch disabled (critical)
  if (getBool(oldCfg, "enabled") === true && getBool(newCfg, "enabled") === false) {
    changes.push({
      description: "Master switch disabled (enabled: true -> false)",
      severity: "critical",
      isDowngrade: true,
      isDisable: true,
    });
  }

  // 2. Preset downgrade (high)
  const oldPreset = getString(oldCfg, "preset");
  const newPreset = getString(newCfg, "preset");
  if (oldPreset && newPreset) {
    const oldRank = PRESET_RANK[oldPreset] ?? 0;
    const newRank = PRESET_RANK[newPreset] ?? 0;
    if (newRank < oldRank) {
      changes.push({
        description: `Preset downgraded: ${oldPreset} -> ${newPreset}`,
        severity: "high",
        isDowngrade: true,
        isDisable: false,
      });
    }
  }

  // 3. Feature section disables (medium)
  const featureSections = [
    "skillGuard",
    "toolScreening",
    "outputScanning",
    "messageScanning",
    "sessionAnalysis",
    "agentContext",
    "mcpScreening",
    "configProtection",
  ];

  for (const section of featureSections) {
    const oldSection = oldCfg[section] as Record<string, unknown> | undefined;
    const newSection = newCfg[section] as Record<string, unknown> | undefined;

    if (oldSection && newSection) {
      if (getBool(oldSection, "enabled") === true && getBool(newSection, "enabled") === false) {
        changes.push({
          description: `${section} disabled (enabled: true -> false)`,
          severity: "medium",
          isDowngrade: true,
          isDisable: true,
        });
      }
    }
  }

  // 4. Block-on-high-risk disabled (high)
  const oldSession = oldCfg.sessionAnalysis as Record<string, unknown> | undefined;
  const newSession = newCfg.sessionAnalysis as Record<string, unknown> | undefined;
  if (oldSession && newSession) {
    if (
      getBool(oldSession, "blockOnHighRisk") === true &&
      getBool(newSession, "blockOnHighRisk") === false
    ) {
      changes.push({
        description: "Session analysis blockOnHighRisk disabled",
        severity: "high",
        isDowngrade: true,
        isDisable: false,
      });
    }
  }

  // 5. Tool tier downgrades (medium)
  const oldTiers = getRecord(
    oldCfg.toolScreening as Record<string, unknown> | undefined,
    "tiers"
  );
  const newTiers = getRecord(
    newCfg.toolScreening as Record<string, unknown> | undefined,
    "tiers"
  );
  if (oldTiers && newTiers) {
    for (const tool of Object.keys(oldTiers)) {
      const oldTier = oldTiers[tool] as string;
      const newTier = newTiers[tool] as string | undefined;
      if (newTier) {
        const oldRank = TIER_RANK[oldTier] ?? 0;
        const newRank = TIER_RANK[newTier] ?? 0;
        if (newRank < oldRank) {
          changes.push({
            description: `Tool tier downgraded: ${tool} (${oldTier} -> ${newTier})`,
            severity: "medium",
            isDowngrade: true,
            isDisable: false,
          });
        }
      }
    }
  }

  // 6. Config protection weakened (high)
  const oldProtection = oldCfg.configProtection as Record<string, unknown> | undefined;
  const newProtection = newCfg.configProtection as Record<string, unknown> | undefined;
  if (oldProtection && newProtection) {
    if (
      getBool(oldProtection, "blockDowngrades") === true &&
      getBool(newProtection, "blockDowngrades") === false
    ) {
      changes.push({
        description: "Config protection blockDowngrades disabled",
        severity: "high",
        isDowngrade: true,
        isDisable: false,
      });
    }
    if (
      getBool(oldProtection, "blockDisable") === true &&
      getBool(newProtection, "blockDisable") === false
    ) {
      changes.push({
        description: "Config protection blockDisable disabled",
        severity: "high",
        isDowngrade: true,
        isDisable: false,
      });
    }
  }

  return changes;
}

function getBool(obj: Record<string, unknown>, key: string): boolean | undefined {
  const val = obj[key];
  return typeof val === "boolean" ? val : undefined;
}

function getString(obj: Record<string, unknown>, key: string): string | undefined {
  const val = obj[key];
  return typeof val === "string" ? val : undefined;
}

function getRecord(
  obj: Record<string, unknown> | undefined,
  key: string
): Record<string, unknown> | undefined {
  if (!obj) return undefined;
  const val = obj[key];
  return val && typeof val === "object" && !Array.isArray(val)
    ? (val as Record<string, unknown>)
    : undefined;
}
