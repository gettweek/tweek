/**
 * Tweek OpenClaw Plugin — Message Scanner
 *
 * Scans inbound messages for prompt injection and outbound messages
 * for PII and credential leakage. Hooks into OpenClaw's message
 * lifecycle events.
 */

import type { ScannerBridge, MessageScanResult, OutboundScanResult } from "./scanner-bridge";
import type { TweekPluginConfig } from "./config";
import { formatMessageBlock, formatPiiWarning } from "./notifications";

/** Result of inbound message screening */
export interface MessageScreenResult {
  blocked: boolean;
  reason?: string;
}

/** Result of outbound message screening */
export interface OutboundScreenResult {
  blocked: boolean;
  reason?: string;
  redacted?: string;
}

/**
 * Message scanner for inbound/outbound content.
 *
 * Follows the same pattern as OutputScanner:
 * - Fail-open in trusted/cautious mode
 * - Fail-closed in paranoid mode
 */
export class MessageScanner {
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
   * Scan an inbound message for prompt injection patterns.
   *
   * @param content - Message text to scan
   * @param role - Message role ("user", "assistant", "system", "tool")
   * @returns Screening result indicating whether message should be blocked
   */
  async scanInbound(
    content: string,
    role: string = "user"
  ): Promise<MessageScreenResult> {
    if (!this.config.messageScanning.enabled || !this.config.messageScanning.scanInbound) {
      return { blocked: false };
    }

    // Skip very short messages
    if (content.length < 10) {
      return { blocked: false };
    }

    try {
      const result = await this.scanner.scanMessage(content, role);

      if (result.flagged) {
        const reason =
          result.findings.length > 0
            ? result.findings[0].description
            : "Prompt injection pattern detected";

        this.log(formatMessageBlock("inbound", reason));

        // Block critical/high in cautious+, block medium+ in paranoid
        const shouldBlock =
          result.risk_level === "critical" ||
          result.risk_level === "high" ||
          (this.config.preset === "paranoid" && result.risk_level === "medium");

        if (shouldBlock) {
          return { blocked: true, reason };
        }

        // Log but don't block for lower severity
        return { blocked: false };
      }

      return { blocked: false };
    } catch (err) {
      this.log(`[Tweek] Inbound message scanning error: ${err}`);

      if (this.config.preset === "paranoid") {
        return {
          blocked: true,
          reason: `Message scanning failed (fail-closed): ${err}`,
        };
      }

      return { blocked: false };
    }
  }

  /**
   * Scan an outbound message for PII and credential leakage.
   *
   * @param content - Outbound message text to scan
   * @returns Screening result with optional redacted content
   */
  async scanOutbound(content: string): Promise<OutboundScreenResult> {
    if (!this.config.messageScanning.enabled || !this.config.messageScanning.scanOutbound) {
      return { blocked: false };
    }

    if (content.length < 10) {
      return { blocked: false };
    }

    try {
      const result = await this.scanner.scanOutbound(content);

      if (result.flagged) {
        // Log PII findings
        if (result.pii_findings.length > 0) {
          this.log(
            formatPiiWarning(
              result.pii_findings.map((f) => ({
                name: f.name,
                count: f.count,
              }))
            )
          );
        }

        // Log secret findings
        if (result.secret_findings.length > 0) {
          this.log(
            formatMessageBlock(
              "outbound",
              `${result.secret_findings.length} credential(s) detected`
            )
          );
        }

        // In paranoid mode with secrets, block outright
        if (
          this.config.preset === "paranoid" &&
          result.secret_findings.length > 0
        ) {
          return {
            blocked: true,
            reason: "Credential leakage detected in outbound message",
          };
        }

        // If redaction is enabled and we have a redacted version, return it
        if (this.config.messageScanning.redactPii && result.redacted) {
          return { blocked: false, redacted: result.redacted };
        }

        return { blocked: false };
      }

      return { blocked: false };
    } catch (err) {
      this.log(`[Tweek] Outbound message scanning error: ${err}`);

      if (this.config.preset === "paranoid") {
        return {
          blocked: true,
          reason: `Outbound scanning failed (fail-closed): ${err}`,
        };
      }

      return { blocked: false };
    }
  }
}
