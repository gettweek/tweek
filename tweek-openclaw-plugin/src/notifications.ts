/**
 * Tweek OpenClaw Plugin — Notifications
 *
 * Formats user-facing notification messages for scan results,
 * screening decisions, and plugin status updates.
 */

import type {
  ScanReport,
  ScreeningDecision,
  ScanFinding,
  SessionAnalysisResult,
} from "./scanner-bridge";

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

/**
 * Format a message block notification (inbound or outbound).
 */
export function formatMessageBlock(
  direction: "inbound" | "outbound",
  reason: string
): string {
  const label = direction === "inbound" ? "Inbound message" : "Outbound message";
  return (
    `[Tweek] ${label} FLAGGED — security risk detected\n` +
    `[Tweek]   Reason: ${reason}`
  );
}

/**
 * Format a session analysis alert notification.
 */
export function formatSessionAnalysis(
  analysis: SessionAnalysisResult
): string {
  const lines: string[] = [
    `[Tweek] Session Analysis Alert`,
    `[Tweek]   Risk Score: ${(analysis.risk_score * 100).toFixed(0)}%`,
  ];

  if (analysis.anomalies.length > 0) {
    lines.push(
      `[Tweek]   Anomalies: ${analysis.anomalies.join(", ")}`
    );
  }

  if (analysis.should_hard_block) {
    lines.push(`[Tweek]   ACTION: Session flagged for hard block`);
  } else if (analysis.is_high_risk) {
    lines.push(`[Tweek]   WARNING: High-risk session detected`);
  }

  for (const rec of analysis.recommendations.slice(0, 3)) {
    lines.push(`[Tweek]   - ${rec}`);
  }

  return lines.join("\n");
}

/**
 * Format a PII detection warning.
 */
export function formatPiiWarning(
  findings: Array<{ name: string; count: number }>
): string {
  const items = findings
    .map((f) => `${f.name} (${f.count}x)`)
    .join(", ");
  return (
    `[Tweek] PII detected in outbound message\n` +
    `[Tweek]   Found: ${items}`
  );
}

/**
 * Format an MCP tool block notification.
 */
export function formatMcpBlock(
  upstream: string,
  tool: string,
  reason: string
): string {
  return (
    `[Tweek] MCP tool BLOCKED: mcp__${upstream}__${tool}\n` +
    `[Tweek]   Reason: ${reason}`
  );
}

/**
 * Format a skill lifecycle event notification.
 */
export function formatSkillLifecycle(
  skillName: string,
  action: "installed" | "uninstalled" | "blocked"
): string {
  switch (action) {
    case "installed":
      return `[Tweek] Skill '${skillName}' installed (passed security scan)`;
    case "uninstalled":
      return `[Tweek] Skill '${skillName}' uninstalled`;
    case "blocked":
      return `[Tweek] Skill '${skillName}' installation BLOCKED by security scan`;
  }
}

/**
 * Format a config guard notification.
 */
export function formatConfigGuard(
  warnings: string[],
  blocked: boolean
): string {
  const lines: string[] = [];

  if (blocked) {
    lines.push(`[Tweek] Config change BLOCKED — security downgrade detected`);
  } else {
    lines.push(`[Tweek] Config change detected — security warnings`);
  }

  for (const w of warnings) {
    lines.push(`[Tweek]   ${w}`);
  }

  return lines.join("\n");
}

function countCritical(report: ScanReport): number {
  return report.severity_counts.critical;
}
