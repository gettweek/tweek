"""
Tweek Cross-Skill Analyzer — Coordinated Attack Detection Across Skills

Detects attacks that are split across multiple installed skills to evade
per-skill analysis. For example:
  - Skill A reads ~/.ssh/id_rsa (looks legitimate for an SSH skill)
  - Skill B sends data to webhook.site (looks legitimate for a notification skill)
  - Together = coordinated credential exfiltration

Architecture inspired by Cisco AI Defense skill-scanner cross-file analysis.
See THIRD-PARTY-NOTICES.md for attribution. Implementation is original code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from tweek.skills.scanner import SUSPICIOUS_HOSTS, SkillScanReport


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class CrossSkillCorrelation:
    """A detected correlation between skills indicating a coordinated attack."""
    threat_type: str        # "credential_relay", "env_harvest_relay", "exfil_chain", "shared_exfil_host"
    severity: str           # "critical", "high"
    skills_involved: List[str]
    evidence: Dict[str, Any]
    description: str


# =============================================================================
# Signal Extraction
# =============================================================================

# Patterns indicating credential/sensitive file access
_CREDENTIAL_ACCESS_PATTERNS = [
    re.compile(r"\.ssh/", re.IGNORECASE),
    re.compile(r"\.aws/credentials", re.IGNORECASE),
    re.compile(r"\.gnupg/", re.IGNORECASE),
    re.compile(r"\.netrc", re.IGNORECASE),
    re.compile(r"credentials\.json", re.IGNORECASE),
    re.compile(r"\.env\b"),
    re.compile(r"id_rsa|id_ed25519|id_ecdsa", re.IGNORECASE),
    re.compile(r"keychain|keystore", re.IGNORECASE),
]

# Patterns indicating environment variable harvesting
_ENV_HARVEST_PATTERNS = [
    re.compile(r"os\.environ\.(get|items|copy|keys|values)"),
    re.compile(r"os\.getenv\s*\("),
    re.compile(r"os\.environ\["),
]

# Patterns indicating network sending capability
_NETWORK_SEND_PATTERNS = [
    re.compile(r"requests\.(post|put|patch|delete)\s*\("),
    re.compile(r"urllib\.request\.urlopen\s*\("),
    re.compile(r"httpx\.(post|put|patch|delete|request)\s*\("),
    re.compile(r"aiohttp\.\w+\.(post|put|patch)\s*\("),
    re.compile(r"socket\.send\s*\("),
    re.compile(r"curl\s+.*-X\s*(POST|PUT)", re.IGNORECASE),
    re.compile(r"curl\s+.*-d\s+", re.IGNORECASE),
]

# Patterns indicating encoding/obfuscation (staging for exfiltration)
_ENCODING_PATTERNS = [
    re.compile(r"base64\.(b64encode|encodebytes|urlsafe_b64encode)"),
    re.compile(r"binascii\.hexlify"),
    re.compile(r"urllib\.parse\.(quote|urlencode)"),
    re.compile(r"zlib\.compress"),
]


@dataclass
class SkillSignals:
    """Extracted behavioral signals from a single skill scan report."""
    skill_name: str
    has_credential_access: bool = False
    has_env_harvest: bool = False
    has_network_send: bool = False
    has_encoding: bool = False
    suspicious_hosts: Set[str] = field(default_factory=set)
    credential_evidence: List[str] = field(default_factory=list)
    network_evidence: List[str] = field(default_factory=list)
    encoding_evidence: List[str] = field(default_factory=list)
    env_evidence: List[str] = field(default_factory=list)


def _extract_signals_from_report(report: SkillScanReport) -> SkillSignals:
    """Extract behavioral signals from a skill scan report."""
    signals = SkillSignals(skill_name=report.skill_name)

    # Collect all content from findings and scan data
    all_text = []

    for layer_data in report.layers.values():
        if not isinstance(layer_data, dict):
            continue
        for finding in layer_data.get("findings", []):
            if isinstance(finding, dict):
                for key in ("matched_text", "description", "source_detail", "sink_detail"):
                    if key in finding:
                        all_text.append(str(finding[key]))
        for issue in layer_data.get("issues", []):
            all_text.append(str(issue))

    combined = "\n".join(all_text)

    # Check for credential access
    for pattern in _CREDENTIAL_ACCESS_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_credential_access = True
            signals.credential_evidence.extend(matches[:3])

    # Check for env variable harvesting
    for pattern in _ENV_HARVEST_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_env_harvest = True
            signals.env_evidence.extend(matches[:3])

    # Check for network sending
    for pattern in _NETWORK_SEND_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_network_send = True
            signals.network_evidence.extend(matches[:3])

    # Check for encoding
    for pattern in _ENCODING_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_encoding = True
            signals.encoding_evidence.extend(matches[:3])

    # Check for suspicious hosts
    for host in SUSPICIOUS_HOSTS:
        if host in combined:
            signals.suspicious_hosts.add(host)

    # Also check taint findings for source/sink data
    taint_layer = report.layers.get("taint", {})
    for finding in taint_layer.get("findings", []):
        if isinstance(finding, dict):
            src_type = finding.get("source_detail", "")
            sink_type = finding.get("sink_detail", "")
            if any(p.search(src_type) for p in _CREDENTIAL_ACCESS_PATTERNS):
                signals.has_credential_access = True
            if any(p.search(src_type) for p in _ENV_HARVEST_PATTERNS):
                signals.has_env_harvest = True
            if any(p.search(sink_type) for p in _NETWORK_SEND_PATTERNS):
                signals.has_network_send = True

    return signals


def _extract_signals_from_content(skill_name: str, files: Dict[str, str]) -> SkillSignals:
    """Extract behavioral signals directly from skill file contents."""
    signals = SkillSignals(skill_name=skill_name)
    combined = "\n".join(files.values())

    for pattern in _CREDENTIAL_ACCESS_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_credential_access = True
            signals.credential_evidence.extend(matches[:3])

    for pattern in _ENV_HARVEST_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_env_harvest = True
            signals.env_evidence.extend(matches[:3])

    for pattern in _NETWORK_SEND_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_network_send = True
            signals.network_evidence.extend(matches[:3])

    for pattern in _ENCODING_PATTERNS:
        matches = pattern.findall(combined)
        if matches:
            signals.has_encoding = True
            signals.encoding_evidence.extend(matches[:3])

    for host in SUSPICIOUS_HOSTS:
        if host in combined:
            signals.suspicious_hosts.add(host)

    return signals


# =============================================================================
# Cross-Skill Analyzer
# =============================================================================

class CrossSkillAnalyzer:
    """Detect coordinated attacks split across multiple installed skills.

    Accepts either pre-computed scan reports or raw file contents per skill.
    Extracts behavioral signals from each skill and correlates them to find
    attack patterns that are invisible when scanning skills independently.
    """

    def analyze_reports(self, reports: List[SkillScanReport]) -> List[CrossSkillCorrelation]:
        """Analyze pre-computed scan reports for cross-skill correlations."""
        signals = [_extract_signals_from_report(r) for r in reports]
        return self._correlate(signals)

    def analyze_contents(self, skills: Dict[str, Dict[str, str]]) -> List[CrossSkillCorrelation]:
        """Analyze raw skill contents for cross-skill correlations.

        Args:
            skills: {skill_name: {relative_path: content}}
        """
        signals = [
            _extract_signals_from_content(name, files)
            for name, files in skills.items()
        ]
        return self._correlate(signals)

    def _correlate(self, all_signals: List[SkillSignals]) -> List[CrossSkillCorrelation]:
        """Run correlation patterns across extracted signals."""
        correlations: List[CrossSkillCorrelation] = []

        if len(all_signals) < 2:
            return correlations

        # Partition skills by capability
        cred_skills = [s for s in all_signals if s.has_credential_access]
        env_skills = [s for s in all_signals if s.has_env_harvest]
        net_skills = [s for s in all_signals if s.has_network_send]
        enc_skills = [s for s in all_signals if s.has_encoding]

        # Pattern 1: Credential Relay
        # One skill reads credentials, another sends data over network
        for cred_s in cred_skills:
            for net_s in net_skills:
                if cred_s.skill_name != net_s.skill_name:
                    correlations.append(CrossSkillCorrelation(
                        threat_type="credential_relay",
                        severity="critical",
                        skills_involved=[cred_s.skill_name, net_s.skill_name],
                        evidence={
                            "credential_skill": cred_s.skill_name,
                            "credential_evidence": cred_s.credential_evidence[:3],
                            "network_skill": net_s.skill_name,
                            "network_evidence": net_s.network_evidence[:3],
                        },
                        description=(
                            f"Skill '{cred_s.skill_name}' accesses credentials while "
                            f"skill '{net_s.skill_name}' can send data over the network. "
                            f"Together these could form a credential exfiltration chain."
                        ),
                    ))

        # Pattern 2: Env Var Harvesting + Network
        # One skill reads env vars, another sends data over network
        for env_s in env_skills:
            for net_s in net_skills:
                if env_s.skill_name != net_s.skill_name:
                    # Don't duplicate if already caught as credential_relay
                    already_found = any(
                        c.threat_type == "credential_relay"
                        and set(c.skills_involved) == {env_s.skill_name, net_s.skill_name}
                        for c in correlations
                    )
                    if not already_found:
                        correlations.append(CrossSkillCorrelation(
                            threat_type="env_harvest_relay",
                            severity="critical",
                            skills_involved=[env_s.skill_name, net_s.skill_name],
                            evidence={
                                "env_skill": env_s.skill_name,
                                "env_evidence": env_s.env_evidence[:3],
                                "network_skill": net_s.skill_name,
                                "network_evidence": net_s.network_evidence[:3],
                            },
                            description=(
                                f"Skill '{env_s.skill_name}' harvests environment variables while "
                                f"skill '{net_s.skill_name}' can send data over the network. "
                                f"Together these could exfiltrate API keys and secrets."
                            ),
                        ))

        # Pattern 3: Exfiltration Chain (read + encode + send across 3 skills)
        if cred_skills and enc_skills and net_skills:
            involved = set()
            for s in cred_skills:
                involved.add(s.skill_name)
            for s in enc_skills:
                involved.add(s.skill_name)
            for s in net_skills:
                involved.add(s.skill_name)

            if len(involved) >= 3:
                correlations.append(CrossSkillCorrelation(
                    threat_type="exfil_chain",
                    severity="high",
                    skills_involved=sorted(involved),
                    evidence={
                        "credential_skills": [s.skill_name for s in cred_skills],
                        "encoding_skills": [s.skill_name for s in enc_skills],
                        "network_skills": [s.skill_name for s in net_skills],
                    },
                    description=(
                        f"Three or more skills form a potential exfiltration chain: "
                        f"credential access → encoding → network send. "
                        f"Skills: {', '.join(sorted(involved))}"
                    ),
                ))

        # Pattern 4: Shared Suspicious Host
        # Same suspicious host referenced in 2+ skills
        host_to_skills: Dict[str, List[str]] = {}
        for s in all_signals:
            for host in s.suspicious_hosts:
                host_to_skills.setdefault(host, []).append(s.skill_name)

        for host, skill_names in host_to_skills.items():
            if len(skill_names) >= 2:
                correlations.append(CrossSkillCorrelation(
                    threat_type="shared_exfil_host",
                    severity="high",
                    skills_involved=skill_names,
                    evidence={
                        "host": host,
                        "skills": skill_names,
                    },
                    description=(
                        f"Suspicious host '{host}' referenced in multiple skills: "
                        f"{', '.join(skill_names)}. This may indicate coordinated exfiltration."
                    ),
                ))

        return correlations
