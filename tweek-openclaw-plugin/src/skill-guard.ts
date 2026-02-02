/**
 * Tweek OpenClaw Plugin — Skill Guard
 *
 * Intercepts skill installations (clawhub install) and routes them
 * through Tweek's 7-layer SkillScanner before allowing activation.
 */

import path from "path";
import fs from "fs";
import os from "os";
import type { ScannerBridge, ScanReport } from "./scanner-bridge";
import type { TweekPluginConfig, SkillGuardMode } from "./config";
import {
  formatScanResult,
  formatSkillGuardIntercept,
} from "./notifications";

/** Result of a skill guard check */
export interface SkillGuardResult {
  allowed: boolean;
  verdict: "pass" | "manual_review" | "fail" | "fingerprint_match" | "error";
  message: string;
  report?: ScanReport;
}

/**
 * Skill installation guard.
 *
 * Intercepts skill installs and scans them through Tweek's scanning pipeline
 * before allowing activation in OpenClaw.
 */
export class SkillGuard {
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
   * Check if a skill should be allowed to install.
   *
   * @param skillDir - Path to the skill directory containing SKILL.md
   * @param skillName - Name of the skill being installed
   * @returns Guard decision with verdict and message
   */
  async checkInstall(
    skillDir: string,
    skillName: string
  ): Promise<SkillGuardResult> {
    if (!this.config.skillGuard.enabled) {
      return {
        allowed: true,
        verdict: "pass",
        message: "Skill guard disabled",
      };
    }

    const mode = this.config.skillGuard.mode;

    // Fingerprint-only mode: check if skill is already known
    if (mode === "fingerprint_only") {
      return this.checkFingerprint(skillDir, skillName);
    }

    // Full scan mode (auto or manual)
    return this.fullScan(skillDir, skillName, mode);
  }

  /**
   * Check fingerprint only — used in "trusted" preset.
   */
  private async checkFingerprint(
    skillDir: string,
    skillName: string
  ): Promise<SkillGuardResult> {
    const skillMd = path.join(skillDir, "SKILL.md");

    try {
      const result = await this.scanner.checkFingerprint(skillMd);

      if (result.known) {
        return {
          allowed: true,
          verdict: "fingerprint_match",
          message: `Skill '${skillName}' recognized by fingerprint`,
        };
      }

      // Unknown skill in fingerprint-only mode — scan it
      return this.fullScan(skillDir, skillName, "auto");
    } catch (err) {
      this.log(`[Tweek] Fingerprint check failed: ${err}`);
      // Fail open for fingerprint-only mode
      return {
        allowed: true,
        verdict: "error",
        message: `Fingerprint check failed, allowing: ${err}`,
      };
    }
  }

  /**
   * Run full 7-layer scan on a skill.
   */
  private async fullScan(
    skillDir: string,
    skillName: string,
    mode: SkillGuardMode
  ): Promise<SkillGuardResult> {
    this.log(formatSkillGuardIntercept(skillName, "scanning"));

    let report: ScanReport;
    try {
      report = await this.scanner.scanSkill(skillDir);
    } catch (err) {
      this.log(`[Tweek] Scan failed: ${err}`);
      // Fail closed — don't install skills we can't scan
      return {
        allowed: false,
        verdict: "error",
        message: `Security scan failed: ${err}`,
      };
    }

    const message = formatScanResult(skillName, report);
    this.log(message);

    switch (report.verdict) {
      case "pass": {
        // Auto-approve passing skills, register fingerprint
        const skillMd = path.join(skillDir, "SKILL.md");
        try {
          await this.scanner.registerFingerprint(
            skillMd,
            "pass",
            report.report_path ?? undefined
          );
        } catch {
          // Non-fatal: fingerprint registration failure shouldn't block install
        }
        this.log(formatSkillGuardIntercept(skillName, "approved"));
        return { allowed: true, verdict: "pass", message, report };
      }

      case "manual_review": {
        if (mode === "manual") {
          // In manual mode, all non-pass results require user approval
          this.log(formatSkillGuardIntercept(skillName, "review"));
          return { allowed: false, verdict: "manual_review", message, report };
        }

        // In auto mode, prompt user for suspicious skills
        if (this.config.skillGuard.promptSuspicious) {
          this.log(formatSkillGuardIntercept(skillName, "review"));
          return { allowed: false, verdict: "manual_review", message, report };
        }

        // If not prompting, allow manual_review skills
        return { allowed: true, verdict: "manual_review", message, report };
      }

      case "fail": {
        if (this.config.skillGuard.blockDangerous) {
          this.log(formatSkillGuardIntercept(skillName, "blocked"));
          return { allowed: false, verdict: "fail", message, report };
        }

        // If not blocking dangerous (unusual config), still warn
        return { allowed: true, verdict: "fail", message, report };
      }

      default:
        return { allowed: false, verdict: "error", message: "Unknown verdict" };
    }
  }

  /**
   * Extract skill name from a clawhub install command.
   */
  static extractSkillName(command: string): string | null {
    // Match: clawhub install <name> [options]
    const match = command.match(
      /clawhub\s+install\s+([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/
    );
    return match ? match[1] : null;
  }

  /**
   * Check if a command is a skill installation command.
   */
  static isInstallCommand(command: string): boolean {
    return /clawhub\s+install\s/.test(command);
  }
}
