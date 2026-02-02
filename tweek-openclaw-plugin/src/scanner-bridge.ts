/**
 * Tweek OpenClaw Plugin — Scanner Bridge
 *
 * HTTP client that communicates with the Tweek Python scanning server
 * running on localhost. All scanning operations go through this bridge.
 */

import http from "http";
import { DEFAULT_SCANNER_PORT } from "./config";

/** Scan report from the 7-layer SkillScanner */
export interface ScanReport {
  verdict: "pass" | "manual_review" | "fail";
  risk_level: string;
  skill_name: string;
  layers_passed: number;
  layers_total: number;
  findings: ScanFinding[];
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  report_path: string | null;
}

/** Individual finding from a scan */
export interface ScanFinding {
  layer: string;
  severity: string;
  description: string;
  matched_text: string;
}

/** Tool screening decision */
export interface ScreeningDecision {
  decision: "allow" | "deny" | "ask";
  reason: string;
  tool: string;
  tier: string;
  error?: string;
}

/** Output scanning result */
export interface OutputScanResult {
  blocked: boolean;
  reason?: string;
  error?: string;
}

/** Fingerprint check result */
export interface FingerprintCheckResult {
  known: boolean;
  path: string;
}

/** Fingerprint registration result */
export interface FingerprintRegisterResult {
  registered: boolean;
  path: string;
  verdict: string;
}

/** Health check result */
export interface HealthCheckResult {
  status: string;
  service: string;
  port: number;
}

/**
 * HTTP bridge to the Tweek Python scanning server.
 */
export class ScannerBridge {
  private host: string;
  private port: number;
  private timeoutMs: number;

  constructor(port: number = DEFAULT_SCANNER_PORT, timeoutMs: number = 30000) {
    this.host = "127.0.0.1";
    this.port = port;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Check if the scanning server is reachable.
   */
  async isHealthy(): Promise<boolean> {
    try {
      const result = await this.get<HealthCheckResult>("/health");
      return result.status === "ok";
    } catch {
      return false;
    }
  }

  /**
   * Run the 7-layer SkillScanner on a skill directory.
   */
  async scanSkill(skillDir: string): Promise<ScanReport> {
    return this.post<ScanReport>("/scan", { skill_dir: skillDir });
  }

  /**
   * Screen a tool call through Tweek's pattern matcher and LLM reviewer.
   */
  async screenTool(
    tool: string,
    input: Record<string, unknown>,
    tier: string = "default"
  ): Promise<ScreeningDecision> {
    return this.post<ScreeningDecision>("/screen", { tool, input, tier });
  }

  /**
   * Scan tool output for credential leakage and exfiltration attempts.
   */
  async scanOutput(content: string): Promise<OutputScanResult> {
    return this.post<OutputScanResult>("/output", { content });
  }

  /**
   * Check if a skill is known/approved via fingerprint.
   */
  async checkFingerprint(skillPath: string): Promise<FingerprintCheckResult> {
    return this.post<FingerprintCheckResult>("/fingerprint/check", {
      path: skillPath,
    });
  }

  /**
   * Register a skill's fingerprint after approval.
   */
  async registerFingerprint(
    skillPath: string,
    verdict: string,
    reportPath?: string
  ): Promise<FingerprintRegisterResult> {
    return this.post<FingerprintRegisterResult>("/fingerprint/register", {
      path: skillPath,
      verdict,
      report_path: reportPath,
    });
  }

  /**
   * Retrieve the most recent scan report for a skill.
   */
  async getReport(skillName: string): Promise<ScanReport> {
    return this.get<ScanReport>(`/report/${encodeURIComponent(skillName)}`);
  }

  /**
   * Send a GET request to the scanning server.
   */
  private get<T>(path: string): Promise<T> {
    return new Promise((resolve, reject) => {
      const req = http.get(
        {
          hostname: this.host,
          port: this.port,
          path,
          timeout: this.timeoutMs,
          headers: { Accept: "application/json" },
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            try {
              const parsed = JSON.parse(data);
              if (res.statusCode && res.statusCode >= 400) {
                reject(
                  new ScannerError(
                    parsed.error ?? `HTTP ${res.statusCode}`,
                    res.statusCode
                  )
                );
              } else {
                resolve(parsed as T);
              }
            } catch (e) {
              reject(new ScannerError(`Invalid JSON response: ${data}`, 0));
            }
          });
        }
      );

      req.on("error", (err) => {
        reject(
          new ScannerError(
            `Scanner server unreachable at ${this.host}:${this.port}: ${err.message}`,
            0
          )
        );
      });

      req.on("timeout", () => {
        req.destroy();
        reject(new ScannerError("Scanner server request timed out", 0));
      });
    });
  }

  /**
   * Send a POST request to the scanning server.
   */
  private post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify(body);

      const req = http.request(
        {
          hostname: this.host,
          port: this.port,
          path,
          method: "POST",
          timeout: this.timeoutMs,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
            Accept: "application/json",
          },
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            try {
              const parsed = JSON.parse(data);
              if (res.statusCode && res.statusCode >= 400) {
                reject(
                  new ScannerError(
                    parsed.error ?? `HTTP ${res.statusCode}`,
                    res.statusCode
                  )
                );
              } else {
                resolve(parsed as T);
              }
            } catch (e) {
              reject(new ScannerError(`Invalid JSON response: ${data}`, 0));
            }
          });
        }
      );

      req.on("error", (err) => {
        reject(
          new ScannerError(
            `Scanner server unreachable at ${this.host}:${this.port}: ${err.message}`,
            0
          )
        );
      });

      req.on("timeout", () => {
        req.destroy();
        reject(new ScannerError("Scanner server request timed out", 0));
      });

      req.write(payload);
      req.end();
    });
  }
}

/**
 * Error class for scanner bridge failures.
 */
export class ScannerError extends Error {
  statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "ScannerError";
    this.statusCode = statusCode;
  }
}
