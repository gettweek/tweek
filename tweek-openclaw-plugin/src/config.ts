/**
 * Tweek OpenClaw Plugin — Configuration
 *
 * Defines the configuration schema, security presets, and validation
 * for the Tweek security plugin in openclaw.json.
 */

/** Security tier for tool screening */
export type SecurityTier = "safe" | "default" | "risky" | "dangerous";

/** Skill guard mode */
export type SkillGuardMode = "auto" | "manual" | "fingerprint_only";

/** Security preset name */
export type PresetName = "trusted" | "cautious" | "paranoid";

/** Skill guard configuration */
export interface SkillGuardConfig {
  enabled: boolean;
  mode: SkillGuardMode;
  blockDangerous: boolean;
  promptSuspicious: boolean;
}

/** Tool screening configuration */
export interface ToolScreeningConfig {
  enabled: boolean;
  llmReview: boolean;
  tiers: Record<string, SecurityTier>;
}

/** Output scanning configuration */
export interface OutputScanningConfig {
  enabled: boolean;
  secretDetection: boolean;
  exfiltrationDetection: boolean;
}

/** Message scanning configuration */
export interface MessageScanningConfig {
  enabled: boolean;
  /** Scan inbound user/agent messages for prompt injection */
  scanInbound: boolean;
  /** Scan outbound responses for PII and credential leakage */
  scanOutbound: boolean;
  /** Auto-redact PII in outbound messages (vs just warn) */
  redactPii: boolean;
}

/** Session analysis configuration */
export interface SessionAnalysisConfig {
  enabled: boolean;
  /** Run full session analysis every N tool calls (0 = disabled) */
  analyzeInterval: number;
  /** Hard-block when session is high risk + graduated escalation */
  blockOnHighRisk: boolean;
}

/** Agent context injection configuration */
export interface AgentContextConfig {
  enabled: boolean;
  /** Include soul.md security policy in agent system prompts */
  injectSoulPolicy: boolean;
}

/** Full Tweek plugin configuration */
export interface TweekPluginConfig {
  /** Master switch — when false, plugin registers but does not activate hooks */
  enabled: boolean;
  preset: PresetName;
  scannerPort: number;
  skillGuard: SkillGuardConfig;
  toolScreening: ToolScreeningConfig;
  outputScanning: OutputScanningConfig;
  messageScanning: MessageScanningConfig;
  sessionAnalysis: SessionAnalysisConfig;
  agentContext: AgentContextConfig;
}

/** Default tool security tiers */
const DEFAULT_TIERS: Record<string, SecurityTier> = {
  bash: "dangerous",
  Bash: "dangerous",
  file_write: "risky",
  Write: "risky",
  Edit: "risky",
  web_fetch: "risky",
  WebFetch: "risky",
  mcp_tool: "default",
  Read: "safe",
  Glob: "safe",
  Grep: "safe",
};

/** Security presets */
const PRESETS: Record<PresetName, Omit<TweekPluginConfig, "scannerPort" | "enabled">> = {
  trusted: {
    preset: "trusted",
    skillGuard: {
      enabled: true,
      mode: "fingerprint_only",
      blockDangerous: true,
      promptSuspicious: false,
    },
    toolScreening: {
      enabled: true,
      llmReview: false,
      tiers: DEFAULT_TIERS,
    },
    outputScanning: {
      enabled: false,
      secretDetection: false,
      exfiltrationDetection: false,
    },
    messageScanning: {
      enabled: false,
      scanInbound: false,
      scanOutbound: false,
      redactPii: false,
    },
    sessionAnalysis: {
      enabled: false,
      analyzeInterval: 0,
      blockOnHighRisk: false,
    },
    agentContext: {
      enabled: false,
      injectSoulPolicy: false,
    },
  },
  cautious: {
    preset: "cautious",
    skillGuard: {
      enabled: true,
      mode: "auto",
      blockDangerous: true,
      promptSuspicious: true,
    },
    toolScreening: {
      enabled: true,
      llmReview: true,
      tiers: DEFAULT_TIERS,
    },
    outputScanning: {
      enabled: true,
      secretDetection: true,
      exfiltrationDetection: true,
    },
    messageScanning: {
      enabled: true,
      scanInbound: true,
      scanOutbound: true,
      redactPii: false,
    },
    sessionAnalysis: {
      enabled: true,
      analyzeInterval: 15,
      blockOnHighRisk: false,
    },
    agentContext: {
      enabled: true,
      injectSoulPolicy: true,
    },
  },
  paranoid: {
    preset: "paranoid",
    skillGuard: {
      enabled: true,
      mode: "manual",
      blockDangerous: true,
      promptSuspicious: true,
    },
    toolScreening: {
      enabled: true,
      llmReview: true,
      tiers: {
        ...DEFAULT_TIERS,
        Read: "default",
        Glob: "default",
        Grep: "default",
        mcp_tool: "risky",
      },
    },
    outputScanning: {
      enabled: true,
      secretDetection: true,
      exfiltrationDetection: true,
    },
    messageScanning: {
      enabled: true,
      scanInbound: true,
      scanOutbound: true,
      redactPii: true,
    },
    sessionAnalysis: {
      enabled: true,
      analyzeInterval: 5,
      blockOnHighRisk: true,
    },
    agentContext: {
      enabled: true,
      injectSoulPolicy: true,
    },
  },
};

/** Default scanner server port */
export const DEFAULT_SCANNER_PORT = 9878;

/**
 * Resolve a full configuration from partial user config + preset.
 *
 * Priority: explicit config > preset defaults
 */
export function resolveConfig(
  userConfig: Partial<TweekPluginConfig> & { preset?: PresetName }
): TweekPluginConfig {
  const presetName = userConfig.preset ?? "cautious";
  const preset = PRESETS[presetName];

  if (!preset) {
    throw new Error(
      `Unknown Tweek preset: "${presetName}". Valid presets: ${Object.keys(PRESETS).join(", ")}`
    );
  }

  return {
    enabled: userConfig.enabled ?? true,
    preset: presetName,
    scannerPort: userConfig.scannerPort ?? DEFAULT_SCANNER_PORT,
    skillGuard: {
      ...preset.skillGuard,
      ...(userConfig.skillGuard ?? {}),
    },
    toolScreening: {
      ...preset.toolScreening,
      ...(userConfig.toolScreening ?? {}),
      tiers: {
        ...preset.toolScreening.tiers,
        ...(userConfig.toolScreening?.tiers ?? {}),
      },
    },
    outputScanning: {
      ...preset.outputScanning,
      ...(userConfig.outputScanning ?? {}),
    },
    messageScanning: {
      ...preset.messageScanning,
      ...(userConfig.messageScanning ?? {}),
    },
    sessionAnalysis: {
      ...preset.sessionAnalysis,
      ...(userConfig.sessionAnalysis ?? {}),
    },
    agentContext: {
      ...preset.agentContext,
      ...(userConfig.agentContext ?? {}),
    },
  };
}

/**
 * Get the security tier for a tool.
 */
export function getToolTier(
  config: TweekPluginConfig,
  toolName: string
): SecurityTier {
  return config.toolScreening.tiers[toolName] ?? "default";
}

/**
 * Check if a tool should be screened based on its tier and config.
 */
export function shouldScreenTool(
  config: TweekPluginConfig,
  toolName: string
): boolean {
  if (!config.toolScreening.enabled) return false;

  const tier = getToolTier(config, toolName);

  // In cautious mode, only screen risky and dangerous
  if (config.preset === "cautious") {
    return tier === "risky" || tier === "dangerous";
  }

  // In paranoid mode, screen everything except safe
  if (config.preset === "paranoid") {
    return tier !== "safe";
  }

  // In trusted mode, only screen dangerous
  if (config.preset === "trusted") {
    return tier === "dangerous";
  }

  return tier === "risky" || tier === "dangerous";
}
