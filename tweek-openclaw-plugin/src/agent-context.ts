/**
 * Tweek OpenClaw Plugin — Agent Context Builder
 *
 * Fetches the operator's soul.md security policy and formats it
 * for injection into agent system prompts. This gives each agent
 * session awareness of the operator's security philosophy.
 */

import type { ScannerBridge } from "./scanner-bridge";
import type { TweekPluginConfig } from "./config";

/**
 * Builds security context for agent system prompts.
 *
 * When enabled, fetches the soul.md policy from the scanner server
 * and returns it as a formatted string suitable for system prompt injection.
 */
export class AgentContextBuilder {
  private scanner: ScannerBridge;
  private config: TweekPluginConfig;
  private log: (msg: string) => void;

  /** Cache the policy for the lifetime of this builder instance */
  private cachedPolicy: string | null | undefined = undefined;

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
   * Build the security context string for agent system prompts.
   *
   * @returns Formatted security policy string, or empty string if
   *          no policy exists or the feature is disabled.
   */
  async buildContext(): Promise<string> {
    if (!this.config.agentContext.enabled || !this.config.agentContext.injectSoulPolicy) {
      return "";
    }

    try {
      // Use cached policy if available
      if (this.cachedPolicy !== undefined) {
        return this.cachedPolicy ? this.formatPolicy(this.cachedPolicy) : "";
      }

      const result = await this.scanner.getSoulPolicy();
      this.cachedPolicy = result.policy;

      if (!result.policy) {
        return "";
      }

      this.log("[Tweek] Soul.md security policy loaded for agent context");
      return this.formatPolicy(result.policy);
    } catch (err) {
      this.log(`[Tweek] Failed to load soul.md policy: ${err}`);
      this.cachedPolicy = null;
      return "";
    }
  }

  /**
   * Format the raw soul.md policy text for system prompt injection.
   */
  private formatPolicy(policy: string): string {
    return (
      "[Tweek Security Policy]\n" +
      "The operator has defined the following security policy.\n" +
      "Factor these rules into your risk assessment and behavior:\n\n" +
      policy.trim() +
      "\n\n[End Tweek Security Policy]"
    );
  }

  /**
   * Clear the cached policy (e.g., on session reset).
   */
  clearCache(): void {
    this.cachedPolicy = undefined;
  }
}
