"""Three-tier OWASP-grounded attack taxonomy for Tweek pattern enrichment.

Three-tier hierarchy (matching crab-trap oracle):
  Tier 1 — Risk Categories (10):  OWASP Agentic Top 10 (ASI01–ASI10)
  Tier 2 — Agentic Threats (17):  OWASP Agentic Threats Taxonomy (T01–T17)
  Tier 3 — Attack Categories (17): Internal categories (CTAP-compatible)

Each category maps to exactly one threat (total function).
Each threat maps to exactly one risk (total function).
The composition Category → Risk is therefore also total.

Also provides many-to-many secondary mappings (MITRE ATLAS, OWASP LLM Top 10,
OWASP Agentic Top 10) for richer pattern tagging.

Taxonomy sources:
  - MITRE ATLAS: https://atlas.mitre.org
  - OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
  - OWASP Agentic Top 10: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/
  - OWASP Agentic Threats: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/

Attribution: Taxonomy structure adapted from crab-trap CTAP v1.0.
Tier 2 (T01–T17) and total-function mappings from crab-trap oracle (Feb 2026).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# MITRE ATLAS — AI/ML Threat Techniques
# ---------------------------------------------------------------------------

MITRE_ATLAS: dict[str, dict[str, str]] = {
    "AML.T0047": {
        "name": "ML Model Inference API Access",
        "description": "Adversary gains access to an ML model inference API to craft adversarial inputs.",
        "tactic": "ML Attack Staging",
    },
    "AML.T0048": {
        "name": "Prompt Injection",
        "description": "Adversary crafts input to manipulate an LLM into performing unintended actions.",
        "tactic": "Initial Access",
    },
    "AML.T0049": {
        "name": "Data Poisoning",
        "description": "Adversary contaminates training data to influence model behavior.",
        "tactic": "ML Attack Staging",
    },
    "AML.T0050": {
        "name": "LLM Jailbreak",
        "description": "Adversary bypasses LLM safety guardrails to elicit restricted outputs.",
        "tactic": "Defense Evasion",
    },
    "AML.T0051": {
        "name": "LLM Prompt Injection — Direct",
        "description": "Adversary provides direct instructions to override the system prompt.",
        "tactic": "Initial Access",
    },
    "AML.T0052": {
        "name": "LLM Prompt Injection — Indirect",
        "description": "Adversary embeds instructions in external content the LLM ingests.",
        "tactic": "Initial Access",
    },
    "AML.T0053": {
        "name": "Data Exfiltration via LLM",
        "description": "Adversary uses an LLM to extract sensitive data from its context or tools.",
        "tactic": "Exfiltration",
    },
    "AML.T0054": {
        "name": "LLM Meta-Prompt Extraction",
        "description": "Adversary extracts the system prompt or hidden instructions from an LLM.",
        "tactic": "Collection",
    },
    "AML.T0055": {
        "name": "Unsafe LLM Output Handling",
        "description": "Adversary exploits downstream consumption of unvalidated LLM output.",
        "tactic": "Impact",
    },
    "AML.T0056": {
        "name": "LLM Plugin Exploitation",
        "description": "Adversary exploits insecure plugin or tool interfaces exposed to the LLM.",
        "tactic": "Execution",
    },
    "AML.T0057": {
        "name": "Excessive LLM Agency",
        "description": "Adversary leverages overly permissive LLM agent capabilities for unauthorized actions.",
        "tactic": "Privilege Escalation",
    },
}

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025)
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10: dict[str, dict[str, str]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": (
            "Manipulating LLMs via crafted inputs to cause unintended actions, "
            "bypassing filters or manipulating the LLM to ignore instructions."
        ),
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "description": (
            "Failure to validate, sanitize, or handle LLM outputs before passing "
            "them to downstream systems, leading to XSS, SSRF, code execution, etc."
        ),
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "description": (
            "Manipulating training or fine-tuning data to introduce vulnerabilities, "
            "backdoors, or biases into the model."
        ),
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "description": (
            "Consuming excessive resources through crafted inputs that degrade "
            "model performance or availability."
        ),
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Compromise of LLM components, training pipelines, or dependencies "
            "introducing weaknesses into the system."
        ),
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "description": (
            "LLM inadvertently revealing confidential data — credentials, PII, "
            "proprietary algorithms, or system configuration."
        ),
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "description": (
            "Plugins lacking proper input validation, access controls, or "
            "providing excessive permissions to the LLM."
        ),
    },
    "LLM08": {
        "name": "Excessive Agency",
        "description": (
            "LLM agent performs damaging actions due to excessive permissions, "
            "insufficient guardrails, or blind trust in model outputs."
        ),
    },
    "LLM09": {
        "name": "Overreliance",
        "description": (
            "Blindly trusting LLM output without verification, leading to "
            "misinformation, security vulnerabilities, or legal exposure."
        ),
    },
    "LLM10": {
        "name": "Model Theft",
        "description": (
            "Unauthorized access, extraction, or replication of proprietary LLM "
            "models, weights, or architectures."
        ),
    },
}

# ---------------------------------------------------------------------------
# OWASP Top 10 for Agentic Applications (ASI01-ASI10)
# ---------------------------------------------------------------------------

OWASP_AGENTIC_TOP_10: dict[str, dict[str, str]] = {
    "ASI01": {
        "name": "Agent Goal Hijack",
        "description": (
            "Adversary manipulates an agent's goals or objectives to perform "
            "unintended actions, typically through prompt injection or context manipulation."
        ),
    },
    "ASI02": {
        "name": "Tool Misuse & Exploitation",
        "description": (
            "Adversary exploits insecure tool implementations, parameter validation "
            "gaps, or excessive tool permissions to perform unauthorized operations."
        ),
    },
    "ASI03": {
        "name": "Identity & Privilege Abuse",
        "description": (
            "Adversary exploits identity, authentication, or authorization mechanisms "
            "to gain elevated privileges or impersonate other agents/users."
        ),
    },
    "ASI04": {
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Compromise of agent components, MCP packages, plugins, or dependencies "
            "introducing weaknesses into the agentic system."
        ),
    },
    "ASI05": {
        "name": "Unexpected Code Execution",
        "description": (
            "Adversary triggers unintended code execution through sandboxing failures, "
            "deserialization attacks, or dynamic code evaluation."
        ),
    },
    "ASI06": {
        "name": "Memory & Context Poisoning",
        "description": (
            "Adversary manipulates persistent memory, conversation history, or RAG "
            "retrieval pipelines to inject instructions across sessions."
        ),
    },
    "ASI07": {
        "name": "Insecure Inter-Agent Communication",
        "description": (
            "Adversary intercepts, modifies, or injects messages between agents in "
            "a multi-agent system to redirect behavior."
        ),
    },
    "ASI08": {
        "name": "Cascading Failures",
        "description": (
            "Adversary triggers chain reactions across multiple agents or tools "
            "where a failure in one component cascades through the system."
        ),
    },
    "ASI09": {
        "name": "Human-Agent Trust Exploitation",
        "description": (
            "Adversary exploits human approval mechanisms, making dangerous actions "
            "appear benign in confirmation dialogs or audit logs."
        ),
    },
    "ASI10": {
        "name": "Rogue Agents",
        "description": (
            "An agent deviates from intended behavior due to compromised skills, "
            "poisoned training, or adversarial manipulation of orchestration logic."
        ),
    },
}

# ---------------------------------------------------------------------------
# Tier 2: OWASP Agentic Threats Taxonomy (T01-T17)
# Intermediate mapping layer between attack categories and risk categories.
# Each threat maps to exactly one ASI risk (proven total in Lean oracle).
# ---------------------------------------------------------------------------

AGENTIC_THREATS: dict[str, dict[str, str]] = {
    "T01": {
        "name": "Agentic System Prompt Injection",
        "description": "Adversary injects instructions via system prompt manipulation.",
        "parent_risk": "ASI01",
    },
    "T02": {
        "name": "Agentic Data Exfiltration",
        "description": "Adversary uses agent tools to extract sensitive data.",
        "parent_risk": "ASI01",
    },
    "T03": {
        "name": "Direct Resource Access by Agent",
        "description": "Agent accesses resources beyond intended scope.",
        "parent_risk": "ASI02",
    },
    "T04": {
        "name": "Identity Impersonation & Delegation Exploits",
        "description": "Adversary exploits agent identity or delegation mechanisms.",
        "parent_risk": "ASI03",
    },
    "T05": {
        "name": "Privilege Compromise via Agent Manipulation",
        "description": "Adversary manipulates agent to escalate privileges.",
        "parent_risk": "ASI03",
    },
    "T06": {
        "name": "Uncontrolled Agentic Actions",
        "description": "Agent takes actions without proper authorization checks.",
        "parent_risk": "ASI02",
    },
    "T07": {
        "name": "Denial of Agentic Service",
        "description": "Adversary disrupts agent availability or throughput.",
        "parent_risk": "ASI08",
    },
    "T08": {
        "name": "Agent State & Memory Exploitation",
        "description": "Adversary manipulates agent memory or conversation state.",
        "parent_risk": "ASI06",
    },
    "T09": {
        "name": "Agent Communication & Negotiation Manipulation",
        "description": "Adversary intercepts or manipulates inter-agent communication.",
        "parent_risk": "ASI07",
    },
    "T10": {
        "name": "Tool & Integration Manipulation",
        "description": "Adversary exploits tool interfaces or return values.",
        "parent_risk": "ASI02",
    },
    "T11": {
        "name": "Agent Fingerprinting & Reconnaissance",
        "description": "Adversary probes agent capabilities and configuration.",
        "parent_risk": "ASI03",
    },
    "T12": {
        "name": "Repudiation of Agent Actions",
        "description": "Agent actions lack accountability or audit trail.",
        "parent_risk": "ASI09",
    },
    "T13": {
        "name": "Cross-Agent Escalation & Trust Exploitation",
        "description": "Adversary exploits trust between agents to escalate attacks.",
        "parent_risk": "ASI07",
    },
    "T14": {
        "name": "Rogue Agents",
        "description": "Agent deviates from intended behavior due to compromise.",
        "parent_risk": "ASI10",
    },
    "T15": {
        "name": "Agentic Workflow Disruption",
        "description": "Adversary disrupts multi-step agentic workflows.",
        "parent_risk": "ASI08",
    },
    "T16": {
        "name": "Supply Chain Vulnerabilities in Agentic Systems",
        "description": "Compromise of agent components, plugins, or dependencies.",
        "parent_risk": "ASI04",
    },
    "T17": {
        "name": "Insecure Code Generation & Execution",
        "description": "Agent generates or executes unsafe code.",
        "parent_risk": "ASI05",
    },
}

# ---------------------------------------------------------------------------
# Total-function mappings (proven in Lean oracle)
# Each category maps to exactly one primary threat (T01-T17).
# Each threat maps to exactly one parent risk (ASI01-ASI10).
# ---------------------------------------------------------------------------

# Category → primary Agentic Threat (total function, 1:1)
CATEGORY_TO_THREAT: dict[str, str] = {
    "credential_theft": "T04",        # → Identity Impersonation
    "prompt_injection": "T01",        # → System Prompt Injection
    "tool_abuse": "T10",              # → Tool & Integration Manipulation
    "skill_injection": "T10",         # → Tool & Integration Manipulation
    "data_exfiltration": "T02",       # → Agentic Data Exfiltration
    "privilege_escalation": "T05",    # → Privilege Compromise
    "social_engineering": "T09",      # → Communication Manipulation
    "encoding_evasion": "T01",        # → System Prompt Injection
    "context_overflow": "T08",        # → State & Memory Exploitation
    "multi_turn_manipulation": "T13", # → Cross-Agent Escalation
    "code_security": "T17",           # → Insecure Code Generation
    "rag_poisoning": "T08",           # → State & Memory Exploitation
    "return_injection": "T10",        # → Tool & Integration Manipulation
    "serialization_attack": "T17",    # → Insecure Code Generation
    "supply_chain_attack": "T16",     # → Supply Chain Vulnerabilities
    "approval_bypass": "T06",         # → Uncontrolled Agentic Actions
    "multimodal_injection": "T01",    # → System Prompt Injection
}

# Threat → parent Risk (total function, 1:1) — derived from AGENTIC_THREATS
THREAT_TO_RISK: dict[str, str] = {
    tid: t["parent_risk"] for tid, t in AGENTIC_THREATS.items()
}

# ---------------------------------------------------------------------------
# Internal Attack Categories (CTAP-compatible)
# ---------------------------------------------------------------------------

ATTACK_CATEGORIES: list[str] = [
    "credential_theft",
    "prompt_injection",
    "tool_abuse",
    "skill_injection",
    "data_exfiltration",
    "privilege_escalation",
    "social_engineering",
    "encoding_evasion",
    "context_overflow",
    "multi_turn_manipulation",
    "code_security",
    "rag_poisoning",
    "return_injection",
    "serialization_attack",
    "supply_chain_attack",
    "approval_bypass",
    "multimodal_injection",
]

# ---------------------------------------------------------------------------
# Category → MITRE ATLAS mapping
# ---------------------------------------------------------------------------

_CATEGORY_TO_MITRE: dict[str, list[str]] = {
    "credential_theft": ["AML.T0053", "AML.T0054"],
    "prompt_injection": ["AML.T0048", "AML.T0051", "AML.T0052"],
    "tool_abuse": ["AML.T0056", "AML.T0057"],
    "skill_injection": ["AML.T0052", "AML.T0056"],
    "data_exfiltration": ["AML.T0053", "AML.T0054"],
    "privilege_escalation": ["AML.T0057", "AML.T0050"],
    "social_engineering": ["AML.T0048", "AML.T0051"],
    "encoding_evasion": ["AML.T0050", "AML.T0048"],
    "context_overflow": ["AML.T0048", "AML.T0055"],
    "multi_turn_manipulation": ["AML.T0051", "AML.T0052", "AML.T0048"],
    "code_security": ["AML.T0055", "AML.T0056"],
    "rag_poisoning": ["AML.T0049", "AML.T0052"],
    "return_injection": ["AML.T0055", "AML.T0052"],
    "serialization_attack": ["AML.T0055"],
    "supply_chain_attack": ["AML.T0049", "AML.T0056"],
    "approval_bypass": ["AML.T0057"],
    "multimodal_injection": ["AML.T0048", "AML.T0051"],
}

# ---------------------------------------------------------------------------
# Category → OWASP LLM Top 10 mapping
# ---------------------------------------------------------------------------

_CATEGORY_TO_OWASP: dict[str, list[str]] = {
    "credential_theft": ["LLM01", "LLM06"],
    "prompt_injection": ["LLM01"],
    "tool_abuse": ["LLM07", "LLM08"],
    "skill_injection": ["LLM05", "LLM07"],
    "data_exfiltration": ["LLM01", "LLM06"],
    "privilege_escalation": ["LLM08"],
    "social_engineering": ["LLM01", "LLM09"],
    "encoding_evasion": ["LLM01", "LLM02"],
    "context_overflow": ["LLM04"],
    "multi_turn_manipulation": ["LLM01", "LLM08"],
    "code_security": ["LLM02", "LLM07"],
    "rag_poisoning": ["LLM03", "LLM06"],
    "return_injection": ["LLM02", "LLM07"],
    "serialization_attack": ["LLM02"],
    "supply_chain_attack": ["LLM05"],
    "approval_bypass": ["LLM08", "LLM09"],
    "multimodal_injection": ["LLM01"],
}

# ---------------------------------------------------------------------------
# Category → OWASP Agentic Top 10 mapping
# ---------------------------------------------------------------------------

_CATEGORY_TO_OWASP_AGENTIC: dict[str, list[str]] = {
    "credential_theft": ["ASI03", "ASI06"],
    "prompt_injection": ["ASI01"],
    "tool_abuse": ["ASI02"],
    "skill_injection": ["ASI01", "ASI10"],
    "data_exfiltration": ["ASI01", "ASI06"],
    "privilege_escalation": ["ASI03", "ASI02"],
    "social_engineering": ["ASI01", "ASI09"],
    "encoding_evasion": ["ASI01", "ASI05"],
    "context_overflow": ["ASI08", "ASI01"],
    "multi_turn_manipulation": ["ASI01", "ASI07"],
    "code_security": ["ASI05", "ASI02"],
    "rag_poisoning": ["ASI06"],
    "return_injection": ["ASI02", "ASI08"],
    "serialization_attack": ["ASI05"],
    "supply_chain_attack": ["ASI04"],
    "approval_bypass": ["ASI09"],
    "multimodal_injection": ["ASI01"],
}

# ---------------------------------------------------------------------------
# Attack Surface → OWASP Agentic mapping
# ---------------------------------------------------------------------------

SURFACE_TO_ASI: dict[str, list[str]] = {
    "llm": ["ASI01"],
    "tools": ["ASI02"],
    "mcp": ["ASI02", "ASI04"],
    "skills": ["ASI01", "ASI10"],
    "memory": ["ASI06"],
    "orchestration": ["ASI07", "ASI08"],
    "code_execution": ["ASI05"],
    "rag": ["ASI06"],
    "output_parsing": ["ASI02", "ASI05"],
    "tool_return": ["ASI02", "ASI08"],
    "auth": ["ASI03"],
    "supply_chain": ["ASI04"],
    "human_loop": ["ASI09"],
    "multimodal": ["ASI01"],
    "serialization": ["ASI05"],
    "tool_use": ["ASI02"],
}

# ---------------------------------------------------------------------------
# Tweek Family → CTAP Category mapping
# ---------------------------------------------------------------------------

FAMILY_TO_CATEGORY: dict[str, str] = {
    "credential_theft": "credential_theft",
    "prompt_injection": "prompt_injection",
    "data_exfiltration": "data_exfiltration",
    "privilege_escalation": "privilege_escalation",
    "code_injection": "code_security",
    "evasion_techniques": "encoding_evasion",
    "mcp_attacks": "tool_abuse",
    "persistence": "privilege_escalation",
    "sandbox_escape": "privilege_escalation",
    "supply_chain": "supply_chain_attack",
    "system_recon": "data_exfiltration",
    "path_traversal": "tool_abuse",
    "destructive_ops": "tool_abuse",
    "covert_channels": "data_exfiltration",
}

# ---------------------------------------------------------------------------
# Tweek Family → Attack Surface mapping
# ---------------------------------------------------------------------------

FAMILY_TO_SURFACE: dict[str, str] = {
    "credential_theft": "tool_use",
    "prompt_injection": "llm",
    "data_exfiltration": "tool_use",
    "privilege_escalation": "tool_use",
    "code_injection": "code_execution",
    "evasion_techniques": "llm",
    "mcp_attacks": "mcp",
    "persistence": "tool_use",
    "sandbox_escape": "code_execution",
    "supply_chain": "supply_chain",
    "system_recon": "tool_use",
    "path_traversal": "tool_use",
    "destructive_ops": "tool_use",
    "covert_channels": "tool_use",
}

# ---------------------------------------------------------------------------
# Tweek Family → Target Type mapping
# ---------------------------------------------------------------------------

FAMILY_TO_TARGET: dict[str, str] = {
    "credential_theft": "agent",
    "prompt_injection": "llm",
    "data_exfiltration": "agent",
    "privilege_escalation": "system",
    "code_injection": "system",
    "evasion_techniques": "llm",
    "mcp_attacks": "tool",
    "persistence": "system",
    "sandbox_escape": "system",
    "supply_chain": "system",
    "system_recon": "agent",
    "path_traversal": "agent",
    "destructive_ops": "system",
    "covert_channels": "agent",
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def map_family_to_category(family: str) -> str:
    """Return the CTAP category for a Tweek pattern family."""
    return FAMILY_TO_CATEGORY.get(family, "tool_abuse")


def map_family_to_surface(family: str) -> str:
    """Return the attack surface for a Tweek pattern family."""
    return FAMILY_TO_SURFACE.get(family, "tool_use")


def map_family_to_target(family: str) -> str:
    """Return the target type for a Tweek pattern family."""
    return FAMILY_TO_TARGET.get(family, "agent")


def map_category_to_mitre(category: str) -> list[str]:
    """Return MITRE ATLAS technique IDs for the given category."""
    return list(_CATEGORY_TO_MITRE.get(category, []))


def map_category_to_owasp(category: str) -> list[str]:
    """Return OWASP LLM Top 10 IDs for the given category."""
    return list(_CATEGORY_TO_OWASP.get(category, []))


def map_category_to_owasp_agentic(category: str) -> list[str]:
    """Return OWASP Agentic Top 10 IDs for the given category."""
    return list(_CATEGORY_TO_OWASP_AGENTIC.get(category, []))


def map_surface_to_asi(surface: str) -> list[str]:
    """Return OWASP Agentic risk IDs for the given attack surface."""
    return list(SURFACE_TO_ASI.get(surface, []))


# ---------------------------------------------------------------------------
# Three-tier chain: Category → Threat → Risk (total functions)
# ---------------------------------------------------------------------------


def map_category_to_threat(category: str) -> str | None:
    """Return the primary Agentic Threat ID (T01-T17) for an attack category.

    Total function over ATTACK_CATEGORIES — returns None only for unknown categories.
    """
    return CATEGORY_TO_THREAT.get(category)


def map_threat_to_risk(threat_id: str) -> str | None:
    """Return the parent OWASP Agentic Risk ID (ASI01-ASI10) for a threat.

    Total function over AGENTIC_THREATS — returns None only for unknown threat IDs.
    """
    return THREAT_TO_RISK.get(threat_id)


def map_category_to_risk(category: str) -> str | None:
    """Compose Category → Threat → Risk in one call.

    Returns the ASI risk ID for a given attack category, or None if unmapped.
    """
    threat = CATEGORY_TO_THREAT.get(category)
    if threat is None:
        return None
    return THREAT_TO_RISK.get(threat)
