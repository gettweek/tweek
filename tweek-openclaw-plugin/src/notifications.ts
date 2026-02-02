/**
 * Tweek OpenClaw Plugin — Notifications
 *
 * Formats user-facing notification messages for scan results,
 * screening decisions, and plugin status updates.
 */

import type { ScanReport, ScreeningDecision, ScanFinding } from "./scanner-bridge";

/**
 * Format a scan report into a user-facing notification string.
 */
export function formatScanResult(
  skillName: string,
  report: ScanReport
): string {
  const lines: string[] = [];

  switch (report.verdict) {
    case "pass":
      lines.push(
        `[Tweek] Scanning '${skillName}'...`,
        `[Tweek] PASSED (${report.layers_passed}/${report.layers_total} layers clean, 0 findings)`
      );
      break;

    case "manual_review":
      lines.push(
        `[Tweek] Scanning '${skillName}'...`,
        `[Tweek] REVIEW REQUIRED — ${report.findings.length} finding(s)`
      );
      for (const finding of report.findings) {
        lines.push(`[Tweek]   ${finding.severity}: ${finding.description}`);
      }
      if (report.report_path) {
        lines.push(`[Tweek]   Report: ${report.report_path}`);
      }
      break;

    case "fail":
      lines.push(
        `[Tweek] Scanning '${skillName}'...`,
        `[Tweek] BLOCKED — ${countCritical(report)} critical finding(s)`
      );
      for (const finding of report.findings) {
        lines.push(
          `[Tweek]   ${finding.severity}: ${finding.description}`
        );
      }
      if (report.report_path) {
        lines.push(`[Tweek]   Report: ${report.report_path}`);
      }
      break;
  }

  return lines.join("\n");
}

/**
 * Format a screening decision into a user-facing notification string.
 */
export function formatScreeningDecision(
  decision: ScreeningDecision
): string {
  if (decision.decision === "allow") {
    return "";
  }

  if (decision.decision === "deny") {
    return (
      `[Tweek] Tool call BLOCKED: ${decision.tool}\n` +
      `[Tweek]   Reason: ${decision.reason}`
    );
  }

  // "ask" — prompt user
  return (
    `[Tweek] Tool call requires approval: ${decision.tool}\n` +
    `[Tweek]   Reason: ${decision.reason}`
  );
}

/**
 * Format an output scan block notification.
 */
export function formatOutputBlock(reason: string): string {
  return (
    `[Tweek] Output BLOCKED — security risk detected\n` +
    `[Tweek]   Reason: ${reason}`
  );
}

/**
 * Format plugin startup banner.
 */
export function formatStartupBanner(
  version: string,
  scannerPort: number,
  scannerHealthy: boolean,
  preset: string
): string {
  const scannerStatus = scannerHealthy ? "ok" : "unreachable";
  return [
    `[Tweek] Security plugin v${version} loaded`,
    `[Tweek]   Scanner server: localhost:${scannerPort} (${scannerStatus})`,
    `[Tweek]   Preset: ${preset}`,
  ].join("\n");
}

/**
 * Format a skill guard install interception message.
 */
export function formatSkillGuardIntercept(
  skillName: string,
  action: "scanning" | "blocked" | "approved" | "review"
): string {
  switch (action) {
    case "scanning":
      return `[Tweek] Scanning '${skillName}' before installation...`;
    case "blocked":
      return `[Tweek] Installation of '${skillName}' BLOCKED by security scan.`;
    case "approved":
      return `[Tweek] '${skillName}' passed security scan. Installation approved.`;
    case "review":
      return `[Tweek] '${skillName}' flagged for manual review. Awaiting approval.`;
  }
}

function countCritical(report: ScanReport): number {
  return report.severity_counts.critical;
}
