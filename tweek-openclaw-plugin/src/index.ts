/**
 * Tweek OpenClaw Plugin — Main Entry Point
 *
 * Registers the Tweek security plugin with the OpenClaw Gateway.
 * Provides skill install scanning, runtime tool screening, and
 * output scanning through hooks into the Gateway lifecycle.
 *
 * Architecture:
 *   OpenClaw Gateway → Tweek Plugin (hooks) → Scanner Bridge (HTTP)
 *   → Tweek Python Scanning Server (localhost:9878)
 */

import { spawn, type ChildProcess } from "child_process";
import { ScannerBridge } from "./scanner-bridge";
import { SkillGuard } from "./skill-guard";
import { ToolScreener } from "./tool-screener";
import { OutputScanner } from "./output-scanner";
import { MessageScanner } from "./message-scanner";
import { SessionTracker } from "./session-tracker";
import { AgentContextBuilder } from "./agent-context";
import { McpScreener } from "./mcp-screener";
import { ConfigGuard } from "./config-guard";
import { resolveConfig, type TweekPluginConfig } from "./config";
import {
  formatStartupBanner,
  formatSessionAnalysis,
  formatMcpBlock,
  formatSkillLifecycle,
  formatConfigGuard,
} from "./notifications";

const PLUGIN_VERSION = "1.0.0";

/**
 * OpenClaw Plugin API interface.
 *
 * Matches the types from openclaw/src/plugins/types.ts.
 * We declare it here to avoid a hard dependency on openclaw's types package.
 */
interface OpenClawPluginApi {
  registerHook(hookName: string, handler: (...args: unknown[]) => unknown): void;
  registerService(name: string, service: unknown): void;
  registerCommand(name: string, handler: (...args: unknown[]) => unknown): void;
  on(event: string, handler: (...args: unknown[]) => unknown): void;
  log(message: string): void;
}

interface OpenClawPluginDefinition {
  id: string;
  name: string;
  version: string;
  register(api: OpenClawPluginApi): void | Promise<void>;
  activate(api: OpenClawPluginApi): void | Promise<void>;
}

/** Tool call hook parameters from OpenClaw */
interface BeforeToolCallParams {
  tool_name: string;
  tool_input: Record<string, unknown>;
}

/** Tool call hook result */
interface BeforeToolCallResult {
  params?: BeforeToolCallParams;
  block?: boolean;
  blockReason?: string;
}

/** After tool call hook parameters */
interface AfterToolCallParams {
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response: string;
}

/** Message received hook parameters */
interface MessageReceivedParams {
  content: string;
  role: string;
}

/** Message received hook result */
interface MessageReceivedResult {
  block?: boolean;
  blockReason?: string;
}

/** Message sending hook parameters */
interface MessageSendingParams {
  content: string;
}

/** Message sending hook result */
interface MessageSendingResult {
  block?: boolean;
  blockReason?: string;
  content?: string;
}

/** Session start/end hook parameters */
interface SessionParams {
  session_id: string;
}

/** Agent start hook result */
interface AgentStartResult {
  systemPromptAddition?: string;
}

/** Before MCP call hook parameters */
interface BeforeMcpCallParams {
  upstream_name: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
}

/** Before MCP call hook result */
interface BeforeMcpCallResult {
  block?: boolean;
  blockReason?: string;
}

/** After MCP call hook parameters */
interface AfterMcpCallParams {
  upstream_name: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response: string;
}

/** Skill install hook parameters */
interface SkillInstallParams {
  skill_name: string;
  skill_dir: string;
}

/** Skill install hook result */
interface SkillInstallResult {
  allow?: boolean;
  blockReason?: string;
}

/** Skill uninstall hook parameters */
interface SkillUninstallParams {
  skill_name: string;
  skill_dir: string;
}

/** Config change hook parameters */
interface ConfigChangeParams {
  old_config: Record<string, unknown>;
  new_config: Record<string, unknown>;
}

/** Config change hook result */
interface ConfigChangeHookResult {
  block?: boolean;
  blockReason?: string;
}

/**
 * The Tweek Security plugin for OpenClaw.
 */
const tweekPlugin: OpenClawPluginDefinition = {
  id: "tweek-security",
  name: "Tweek Security",
  version: PLUGIN_VERSION,

  /**
   * Register phase — set up hooks before Gateway starts processing.
   */
  register(api: OpenClawPluginApi) {
    let config: TweekPluginConfig;
    let scanner: ScannerBridge;
    let skillGuard: SkillGuard;
    let toolScreener: ToolScreener;
    let outputScanner: OutputScanner;
    let scannerProcess: ChildProcess | null = null;

    const log = (msg: string) => {
      try {
        api.log(msg);
      } catch {
        console.error(msg);
      }
    };

    // Initialize config from the plugin config in openclaw.json
    // OpenClaw passes the config from plugins.entries.tweek.config
    try {
      // Config is injected by OpenClaw from openclaw.json at registration time
      // We access it through a convention: the api object may carry config
      // For now, resolve with defaults — activate() will get the real config
      config = resolveConfig({});
    } catch (err) {
      log(`[Tweek] Config error: ${err}`);
      config = resolveConfig({ preset: "cautious" });
    }

    // Master switch — if disabled, register but don't activate hooks
    if (!config.enabled) {
      log(`[Tweek] Plugin disabled via configuration. Skipping hook registration.`);
      return;
    }

    scanner = new ScannerBridge(config.scannerPort);
    skillGuard = new SkillGuard(scanner, config, log);
    toolScreener = new ToolScreener(scanner, config, log);
    outputScanner = new OutputScanner(scanner, config, log);
    const messageScanner = new MessageScanner(scanner, config, log);
    const sessionTracker = new SessionTracker(scanner, config, log);
    const agentContext = new AgentContextBuilder(scanner, config, log);
    const mcpScreener = new McpScreener(scanner, config, log);
    const configGuard = new ConfigGuard(config, log);

    // Register the scanning server as a managed service
    api.registerService("tweek-scanner", {
      start: () => startScannerServer(config.scannerPort, log),
      stop: () => {
        if (scannerProcess) {
          scannerProcess.kill();
          scannerProcess = null;
        }
      },
      isHealthy: () => scanner.isHealthy(),
    });

    // Hook: before_tool_call — screen tool calls
    api.on("before_tool_call", async (params: unknown): Promise<BeforeToolCallResult> => {
      const toolParams = params as BeforeToolCallParams;

      // Standard tool screening (skill install detection moved to skill_install hook)
      const result = await toolScreener.screen(
        toolParams.tool_name,
        toolParams.tool_input
      );

      if (result.block) {
        return {
          block: true,
          blockReason: result.blockReason,
        };
      }

      return {};
    });

    // Hook: after_tool_call — scan tool output + feed session tracker
    api.on("after_tool_call", async (params: unknown): Promise<void> => {
      const toolParams = params as AfterToolCallParams;

      if (!toolParams.tool_response) return;

      const result = await outputScanner.scan(
        toolParams.tool_name,
        toolParams.tool_response
      );

      if (result.blocked) {
        log(
          `[Tweek] Output from '${toolParams.tool_name}' contained security risk: ${result.reason}`
        );
      }

      // Feed the session tracker for cross-turn analysis
      await sessionTracker.recordToolCall(
        toolParams.tool_name,
        result.blocked ? "block" : "allow",
        "default"
      );
      const analysis = await sessionTracker.checkAnalysis();
      if (analysis?.should_hard_block) {
        log(formatSessionAnalysis(analysis));
      }
    });

    // Hook: gateway_start — start the scanning server
    api.on("gateway_start", async () => {
      log(`[Tweek] Gateway starting, launching scanning server...`);

      try {
        scannerProcess = await startScannerServer(config.scannerPort, log);

        // Wait for server to become healthy
        const healthy = await waitForHealthy(scanner, 10000);

        log(
          formatStartupBanner(
            PLUGIN_VERSION,
            config.scannerPort,
            healthy,
            config.preset
          )
        );

        if (!healthy) {
          log(
            `[Tweek] WARNING: Scanning server did not become healthy. ` +
            `Tool screening will fail open (except in paranoid mode).`
          );
        }
      } catch (err) {
        log(`[Tweek] Failed to start scanning server: ${err}`);
      }
    });

    // Hook: gateway_stop — stop the scanning server
    api.on("gateway_stop", () => {
      if (scannerProcess) {
        log(`[Tweek] Stopping scanning server...`);
        scannerProcess.kill("SIGTERM");
        scannerProcess = null;
      }
    });

    // Hook: message_received — scan inbound messages for injection
    api.on("message_received", async (params: unknown): Promise<MessageReceivedResult> => {
      const msgParams = params as MessageReceivedParams;
      const result = await messageScanner.scanInbound(msgParams.content, msgParams.role);
      if (result.blocked) {
        return { block: true, blockReason: result.reason };
      }
      return {};
    });

    // Hook: message_sending — scan outbound messages for PII/leakage
    api.on("message_sending", async (params: unknown): Promise<MessageSendingResult> => {
      const msgParams = params as MessageSendingParams;
      const result = await messageScanner.scanOutbound(msgParams.content);
      if (result.blocked) {
        return { block: true, blockReason: result.reason };
      }
      if (result.redacted) {
        return { content: result.redacted };
      }
      return {};
    });

    // Hook: session_start — initialize session tracking
    api.on("session_start", async (params: unknown): Promise<void> => {
      const sessionParams = params as SessionParams;
      sessionTracker.setSessionId(sessionParams.session_id);
      log(`[Tweek] Session tracking started: ${sessionParams.session_id}`);
    });

    // Hook: session_end — run final session analysis
    api.on("session_end", async (): Promise<void> => {
      const analysis = await sessionTracker.checkAnalysis();
      if (analysis?.is_suspicious) {
        log(formatSessionAnalysis(analysis));
      }
    });

    // Hook: before_agent_start — inject security context (soul.md)
    api.on("before_agent_start", async (): Promise<AgentStartResult> => {
      const context = await agentContext.buildContext();
      if (context) {
        return { systemPromptAddition: context };
      }
      return {};
    });

    // Hook: before_mcp_call — screen MCP tool calls before forwarding
    api.on("before_mcp_call", async (params: unknown): Promise<BeforeMcpCallResult> => {
      const p = params as BeforeMcpCallParams;
      const result = await mcpScreener.screen(p.upstream_name, p.tool_name, p.tool_input);
      if (result.block) {
        log(formatMcpBlock(p.upstream_name, p.tool_name, result.blockReason ?? "blocked"));
        return { block: true, blockReason: result.blockReason };
      }
      return {};
    });

    // Hook: after_mcp_call — scan MCP responses + feed session tracker
    api.on("after_mcp_call", async (params: unknown): Promise<void> => {
      const p = params as AfterMcpCallParams;
      if (!p.tool_response) return;

      const namespacedName = `mcp__${p.upstream_name}__${p.tool_name}`;
      const result = await outputScanner.scan(namespacedName, p.tool_response);
      if (result.blocked) {
        log(`[Tweek] MCP output from '${namespacedName}' blocked: ${result.reason}`);
      }

      await sessionTracker.recordToolCall(namespacedName, result.blocked ? "block" : "allow", "mcp");
      const analysis = await sessionTracker.checkAnalysis();
      if (analysis?.should_hard_block) {
        log(formatSessionAnalysis(analysis));
      }
    });

    // Hook: skill_install — proper lifecycle hook for skill installation scanning
    api.on("skill_install", async (params: unknown): Promise<SkillInstallResult> => {
      const p = params as SkillInstallParams;
      const result = await skillGuard.checkInstall(p.skill_dir, p.skill_name);
      if (!result.allowed) {
        log(formatSkillLifecycle(p.skill_name, "blocked"));
        return { allow: false, blockReason: result.message };
      }
      log(formatSkillLifecycle(p.skill_name, "installed"));
      await sessionTracker.recordToolCall(`skill_install:${p.skill_name}`, "allow", "lifecycle");
      return { allow: true };
    });

    // Hook: skill_uninstall — audit trail + session tracking
    api.on("skill_uninstall", async (params: unknown): Promise<Record<string, never>> => {
      const p = params as SkillUninstallParams;
      log(formatSkillLifecycle(p.skill_name, "uninstalled"));
      await sessionTracker.recordToolCall(`skill_uninstall:${p.skill_name}`, "allow", "lifecycle");
      return {};
    });

    // Hook: config_change — tamper protection for Tweek's own config
    api.on("config_change", async (params: unknown): Promise<ConfigChangeHookResult> => {
      const p = params as ConfigChangeParams;
      const result = configGuard.check(p.old_config, p.new_config);
      if (result.warnings.length > 0) {
        log(formatConfigGuard(result.warnings, !result.allow));
      }
      if (!result.allow) {
        return { block: true, blockReason: result.blockReason };
      }
      return {};
    });

    // Register skill scan command
    api.registerCommand("tweek-scan", async (...args: unknown[]) => {
      const skillDir = args[0] as string;
      if (!skillDir) {
        log("[Tweek] Usage: tweek-scan <skill-directory>");
        return;
      }

      try {
        const report = await scanner.scanSkill(skillDir);
        log(JSON.stringify(report, null, 2));
      } catch (err) {
        log(`[Tweek] Scan failed: ${err}`);
      }
    });

    // Register health check command
    api.registerCommand("tweek-status", async () => {
      const healthy = await scanner.isHealthy();
      log(
        formatStartupBanner(
          PLUGIN_VERSION,
          config.scannerPort,
          healthy,
          config.preset
        )
      );
    });
  },

  /**
   * Activate phase — called after all plugins are registered.
   */
  activate(api: OpenClawPluginApi) {
    api.log(`[Tweek] Security plugin activated (v${PLUGIN_VERSION})`);
  },
};

/**
 * Start the Tweek Python scanning server as a child process.
 */
function startScannerServer(
  port: number,
  log: (msg: string) => void
): ChildProcess {
  const proc = spawn(
    "python3",
    ["-m", "tweek.integrations.openclaw_server", "--port", String(port)],
    {
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
    }
  );

  proc.stdout?.on("data", (data: Buffer) => {
    const msg = data.toString().trim();
    if (msg) log(msg);
  });

  proc.stderr?.on("data", (data: Buffer) => {
    const msg = data.toString().trim();
    if (msg) log(msg);
  });

  proc.on("error", (err) => {
    log(`[Tweek] Scanning server process error: ${err.message}`);
  });

  proc.on("exit", (code) => {
    if (code !== null && code !== 0) {
      log(`[Tweek] Scanning server exited with code ${code}`);
    }
  });

  return proc;
}

/**
 * Wait for the scanning server to become healthy.
 */
async function waitForHealthy(
  scanner: ScannerBridge,
  timeoutMs: number
): Promise<boolean> {
  const start = Date.now();
  const interval = 500;

  while (Date.now() - start < timeoutMs) {
    if (await scanner.isHealthy()) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }

  return false;
}

// Export for OpenClaw plugin loader
export default tweekPlugin;

// Named exports for testing and advanced usage
export { ScannerBridge } from "./scanner-bridge";
export { SkillGuard } from "./skill-guard";
export { ToolScreener } from "./tool-screener";
export { OutputScanner } from "./output-scanner";
export { MessageScanner } from "./message-scanner";
export { SessionTracker } from "./session-tracker";
export { AgentContextBuilder } from "./agent-context";
export { McpScreener } from "./mcp-screener";
export { ConfigGuard } from "./config-guard";
export { resolveConfig, type TweekPluginConfig } from "./config";
export type {
  ScanReport,
  ScreeningDecision,
  OutputScanResult,
  MessageScanResult,
  OutboundScanResult,
  SessionAnalysisResult,
  SoulPolicyResult,
} from "./scanner-bridge";
export type { SkillGuardResult } from "./skill-guard";
export type { ToolScreenResult } from "./tool-screener";
export type { McpScreenResult } from "./mcp-screener";
export type { ConfigChangeResult as ConfigGuardResult } from "./config-guard";
export type { OutputScreenResult } from "./output-scanner";
export type { MessageScreenResult, OutboundScreenResult } from "./message-scanner";
