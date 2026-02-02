/**
 * Tweek OpenClaw Plugin — Tool Screener
 *
 * Pre-execution screening for tool calls. Hooks into OpenClaw's
 * before_tool_call event to screen commands through Tweek's
 * pattern matcher and LLM reviewer.
 */

import type { ScannerBridge, ScreeningDecision } from "./scanner-bridge";
import type { TweekPluginConfig } from "./config";
import { shouldScreenTool, getToolTier } from "./config";
import { formatScreeningDecision } from "./notifications";

/** Result of tool screening with block decision */
export interface ToolScreenResult {
  block: boolean;
  blockReason?: string;
  decision: ScreeningDecision | null;
}

/**
 * Tool call screener.
 *
 * Screens agent tool calls through Tweek's security pipeline before execution.
 */
export class ToolScreener {
  private scanner: ScannerBridge;
  private config: TweekPluginConfig;
  private log: (msg: string) => void;

  constructor(
    scanner: ScannerBridge,
    config: TweekPluginConfig,
    log: (msg: string) => void = console.error
  ) {
    this.scanner = scanner;
    this.config = config;
    this.log = log;
  }

  /**
   * Screen a tool call before execution.
   *
   * @param toolName - Name of the tool being invoked
   * @param toolInput - Tool input parameters
   * @returns Screening result with block decision
   */
  async screen(
    toolName: string,
    toolInput: Record<string, unknown>
  ): Promise<ToolScreenResult> {
    // Check if this tool should be screened
    if (!shouldScreenTool(this.config, toolName)) {
      return { block: false, decision: null };
    }

    const tier = getToolTier(this.config, toolName);

    try {
      const decision = await this.scanner.screenTool(toolName, toolInput, tier);
      const message = formatScreeningDecision(decision);

      if (message) {
        this.log(message);
      }

      if (decision.decision === "deny") {
        return {
          block: true,
          blockReason: `Tweek Security: ${decision.reason}`,
          decision,
        };
      }

      // "ask" decisions are treated as blocks in the plugin context —
      // OpenClaw's hook system doesn't have a native "ask" mechanism,
      // so we block and include the reason for the user to see
      if (decision.decision === "ask") {
        return {
          block: true,
          blockReason: `Tweek Security (requires approval): ${decision.reason}`,
          decision,
        };
      }

      return { block: false, decision };
    } catch (err) {
      this.log(`[Tweek] Tool screening error: ${err}`);

      // Fail behavior depends on preset
      if (this.config.preset === "paranoid") {
        // Paranoid: fail closed
        return {
          block: true,
          blockReason: `Tweek Security: screening failed (fail-closed): ${err}`,
          decision: null,
        };
      }

      // Other presets: fail open
      return { block: false, decision: null };
    }
  }
}
