/**
 * Tweek OpenClaw Plugin — Output Scanner
 *
 * Post-execution scanning for tool outputs. Hooks into OpenClaw's
 * after_tool_call event to detect credential leakage and
 * exfiltration attempts in tool responses.
 */

import type { ScannerBridge, OutputScanResult } from "./scanner-bridge";
import type { TweekPluginConfig } from "./config";
import { formatOutputBlock } from "./notifications";

/** Result of output scanning */
export interface OutputScreenResult {
  blocked: boolean;
  reason?: string;
}

/**
 * Tool output scanner.
 *
 * Scans agent tool outputs for security risks after execution.
 */
export class OutputScanner {
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
   * Scan tool output for security risks.
   *
   * @param toolName - Name of the tool that produced the output
   * @param output - The tool's output content
   * @returns Scan result indicating whether content should be blocked
   */
  async scan(toolName: string, output: string): Promise<OutputScreenResult> {
    if (!this.config.outputScanning.enabled) {
      return { blocked: false };
    }

    // Skip scanning for safe tools with small outputs
    if (output.length < 10) {
      return { blocked: false };
    }

    try {
      const result = await this.scanner.scanOutput(output);

      if (result.blocked) {
        const reason = result.reason ?? "Security risk detected in output";
        this.log(formatOutputBlock(reason));
        return { blocked: true, reason };
      }

      return { blocked: false };
    } catch (err) {
      this.log(`[Tweek] Output scanning error: ${err}`);

      // Fail behavior depends on preset
      if (this.config.preset === "paranoid") {
        return {
          blocked: true,
          reason: `Output scanning failed (fail-closed): ${err}`,
        };
      }

      // Other presets: fail open
      return { blocked: false };
    }
  }
}
