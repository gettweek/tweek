/**
 * Tweek OpenClaw Plugin — Session Tracker
 *
 * Tracks session events and periodically runs session analysis to
 * detect cross-turn anomalies like privilege escalation, repeated
 * denial attacks, behavior shifts, and ACIP graduated escalation.
 */

import type { ScannerBridge, SessionAnalysisResult } from "./scanner-bridge";
import type { TweekPluginConfig } from "./config";
import { formatSessionAnalysis } from "./notifications";

/**
 * Session event tracker with periodic analysis.
 *
 * Records tool calls via the scanner server and triggers full session
 * analysis at configurable intervals. When analysis detects high-risk
 * patterns, it returns the result for upstream blocking decisions.
 */
export class SessionTracker {
  private scanner: ScannerBridge;
  private config: TweekPluginConfig;
  private log: (msg: string) => void;

  private toolCallCount: number = 0;
  private sessionId: string | null = null;

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
   * Set the current session ID for tracking.
   */
  setSessionId(id: string): void {
    this.sessionId = id;
    this.toolCallCount = 0;
  }

  /**
   * Record a tool call event for session analysis.
   *
   * @param toolName - Name of the tool that was called
   * @param decision - Screening decision ("allow", "deny", "ask")
   * @param tier - Security tier of the tool
   */
  async recordToolCall(
    toolName: string,
    decision: string,
    tier: string
  ): Promise<void> {
    if (!this.config.sessionAnalysis.enabled || !this.sessionId) {
      return;
    }

    this.toolCallCount++;

    try {
      await this.scanner.recordSessionEvent(this.sessionId, {
        tool_name: toolName,
        decision,
        tier,
        tool_call_number: this.toolCallCount,
      });
    } catch (err) {
      // Session event recording is best-effort
      this.log(`[Tweek] Session event recording error: ${err}`);
    }
  }

  /**
   * Check if session analysis should run and return results if triggered.
   *
   * Analysis runs every `analyzeInterval` tool calls. If the session is
   * flagged as high-risk with graduated escalation, and blockOnHighRisk
   * is enabled, the caller should block further operations.
   *
   * @returns Analysis result if triggered, null otherwise
   */
  async checkAnalysis(): Promise<SessionAnalysisResult | null> {
    if (!this.config.sessionAnalysis.enabled || !this.sessionId) {
      return null;
    }

    const interval = this.config.sessionAnalysis.analyzeInterval;
    if (interval <= 0 || this.toolCallCount % interval !== 0) {
      return null;
    }

    try {
      const analysis = await this.scanner.analyzeSession(this.sessionId);

      if (analysis.is_suspicious) {
        this.log(formatSessionAnalysis(analysis));
      }

      if (analysis.should_hard_block && this.config.sessionAnalysis.blockOnHighRisk) {
        this.log(
          `[Tweek] Session ${this.sessionId} flagged for hard block: ` +
          `risk_score=${analysis.risk_score}, anomalies=[${analysis.anomalies.join(", ")}]`
        );
      }

      return analysis;
    } catch (err) {
      this.log(`[Tweek] Session analysis error: ${err}`);
      return null;
    }
  }

  /**
   * Get the current tool call count for this session.
   */
  getToolCallCount(): number {
    return this.toolCallCount;
  }

  /**
   * Get the current session ID.
   */
  getSessionId(): string | null {
    return this.sessionId;
  }
}
