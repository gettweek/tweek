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
import { resolveConfig, type TweekPluginConfig } from "./config";
import { formatStartupBanner } from "./notifications";

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

      // Check for skill installation commands
      if (
        toolParams.tool_name === "bash" ||
        toolParams.tool_name === "Bash"
      ) {
        const command = (toolParams.tool_input.command as string) ?? "";

        if (SkillGuard.isInstallCommand(command)) {
          const skillName = SkillGuard.extractSkillName(command);
          if (skillName) {
            // For install commands, we need the skill content first
            // The actual scanning happens after download but before activation
            // Log the interception for now
            log(`[Tweek] Detected skill install: ${skillName}`);
          }
        }
      }

      // Standard tool screening
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

    // Hook: after_tool_call — scan tool output
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
export { resolveConfig, type TweekPluginConfig } from "./config";
export type { ScanReport, ScreeningDecision, OutputScanResult } from "./scanner-bridge";
export type { SkillGuardResult } from "./skill-guard";
export type { ToolScreenResult } from "./tool-screener";
export type { OutputScreenResult } from "./output-scanner";
