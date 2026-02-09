# Third-Party Notices

Tweek incorporates code and detection patterns from the following open-source projects.

---

## Cisco AI Defense — skill-scanner

YARA rules in `tweek/rules/yara/`, detection patterns in `tweek/skills/scanner.py`
(coercive injection, autonomy abuse, capability inflation, unicode steganography,
and extended exfiltration host lists), and the dataflow taint analysis architecture
in `tweek/security/taint_analyzer.py` (CFG construction, forward taint propagation,
source/sink detection) are derived from or inspired by:

- **Repository:** https://github.com/cisco-ai-defense/skill-scanner
- **License:** Apache License 2.0
- **Copyright:** 2026 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use these files except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

---

## Knostic — OpenClaw Shield

PII detection patterns in `tweek/security/pii_scanner.py` (email, SSN, credit card,
phone number, IBAN) are adapted from:

- **Repository:** https://github.com/knostic/openclaw-shield
- **License:** Apache License 2.0
- **Copyright:** 2026 Knostic, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use these files except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
