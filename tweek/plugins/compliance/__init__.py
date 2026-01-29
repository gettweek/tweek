#!/usr/bin/env python3
"""
Tweek Compliance Plugins

Domain-specific compliance modules for detecting sensitive information:
- Gov: Government classification markings (TS, SECRET, CUI, etc.)
- HIPAA: Healthcare PHI and patient data
- PCI: Payment card industry data (credit cards, CVVs)
- Legal: Attorney-client privilege and confidentiality markers
- SOC2: Security and compliance patterns
- GDPR: EU personal data protection

These are ENTERPRISE tier plugins requiring appropriate licensing.
"""

from tweek.plugins.compliance.gov import GovCompliancePlugin
from tweek.plugins.compliance.hipaa import HIPAACompliancePlugin
from tweek.plugins.compliance.pci import PCICompliancePlugin
from tweek.plugins.compliance.legal import LegalCompliancePlugin
from tweek.plugins.compliance.soc2 import SOC2CompliancePlugin
from tweek.plugins.compliance.gdpr import GDPRCompliancePlugin

__all__ = [
    "GovCompliancePlugin",
    "HIPAACompliancePlugin",
    "PCICompliancePlugin",
    "LegalCompliancePlugin",
    "SOC2CompliancePlugin",
    "GDPRCompliancePlugin",
]
