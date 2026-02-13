/**
 * Tweek OpenClaw Plugin — MCP Screener
 *
 * Pre-execution screening for MCP tool calls from external servers.
 * MCP tools default to a higher security tier since they originate
 * from untrusted external upstream servers.
 */

import type { ScannerBridge, ScreeningDecision } from "./scanner-bridge";
import type { TweekPluginConfig } from "./config";
import { formatScreeningDecision } from "./notifications";

/** Result of MCP tool screening */
export interface McpScreenResult {
  block: boolean;
  blockReason?: string;
  decision: ScreeningDecision | null;
}

type LogFn = (msg: string) => void;

/**
 * MCP tool call screener.
 *
 * Screens MCP tool calls through Tweek's security pipeline before
 * forwarding to the upstream server. Follows the ToolScreener pattern
 * but defaults to a higher security tier for external MCP tools.
 */
export class McpScreener {
  private scanner: ScannerBridge;
  private config: TweekPluginConfig;
  private log: LogFn;

  constructor(scanner: ScannerBridge, config: TweekPluginConfig, log: LogFn = console.error) {
    this.scanner = scanner;
    this.config = config;
    this.log = log;
  }

  /**
   * Screen an MCP tool call before forwarding to the upstream server.
   *
   * @param upstreamName - Name of the MCP upstream server
   * @param toolName - Name of the tool being invoked
   * @param toolInput - Tool input parameters
   * @returns Screening result with block decision
   */
  async screen(
    upstreamName: string,
    toolName: string,
    toolInput: Record<string, unknown>
  ): Promise<McpScreenResult> {
    if (!this.config.mcpScreening.enabled) {
      return { block: false, decision: null };
    }

    // Determine tier: trusted upstreams get lower tier, others get the configured default
    const isTrusted = this.config.mcpScreening.trustedUpstreams.includes(upstreamName);
    const tier = isTrusted ? "default" : this.config.mcpScreening.defaultTier;

    const namespacedName = `mcp__${upstreamName}__${toolName}`;

    try {
      const decision = await this.scanner.screenTool(namespacedName, toolInput, tier);
      const message = formatScreeningDecision(decision);

      if (message) {
        this.log(message);
      }

      // deny and ask both map to block — OpenClaw hooks don't have a native "ask"
      if (decision.decision === "deny") {
        return {
          block: true,
          blockReason: `Tweek Security: MCP tool '${namespacedName}' blocked: ${decision.reason}`,
          decision,
        };
      }

      if (decision.decision === "ask") {
        return {
          block: true,
          blockReason: `Tweek Security (requires approval): MCP tool '${namespacedName}': ${decision.reason}`,
          decision,
        };
      }

      return { block: false, decision };
    } catch (err) {
      this.log(`[Tweek] MCP screening error for '${namespacedName}': ${err}`);

      // Paranoid: fail closed
      if (this.config.preset === "paranoid") {
        return {
          block: true,
          blockReason: `Tweek Security: MCP screening failed (fail-closed): ${err}`,
          decision: null,
        };
      }

      // Other presets: fail open
      return { block: false, decision: null };
    }
  }
}
