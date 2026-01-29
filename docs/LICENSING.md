# Tweek Licensing Documentation

License tiers, feature gating, activation flow, and developer API.

---

## Overview

Tweek uses a three-tier licensing model. The FREE tier includes the full pattern
library (116 patterns) and core protection. PRO and ENTERPRISE tiers unlock
advanced screening, compliance modules, and enterprise features.

License keys are stored locally at `~/.tweek/license.key`.

**Source:** `tweek/licensing.py`

---

## License Tiers

| Tier         | Price     | Target Audience                          |
|--------------|-----------|------------------------------------------|
| FREE         | $0        | Individual developers                     |
| PRO          | Paid      | Professional developers and small teams   |
| ENTERPRISE   | Custom    | Organizations with compliance needs       |

---

## Feature Breakdown by Tier

### FREE Tier

| Feature              | Description                                       |
|----------------------|---------------------------------------------------|
| `pattern_matching`   | All 116 attack patterns included free              |
| `basic_logging`      | SQLite security event logging                      |
| `vault_storage`      | Credential vault (platform keychain)               |
| `cli_commands`       | Full CLI access                                    |
| `global_install`     | Global hook installation                           |
| `project_install`    | Per-project hook installation                      |

### PRO Tier (includes all FREE features)

| Feature              | Description                                       |
|----------------------|---------------------------------------------------|
| `llm_review`         | Claude Haiku semantic analysis of commands         |
| `session_analysis`   | Cross-turn attack detection                        |
| `rate_limiting`      | Resource theft protection                          |
| `advanced_logging`   | Detailed event metadata                            |
| `log_export`         | CSV export of security logs                        |
| `custom_tiers`       | Per-tool security tier customization               |
| `priority_support`   | Email support                                      |

### ENTERPRISE Tier (includes all FREE + PRO features)

| Feature               | Description                                      |
|-----------------------|---------------------------------------------------|
| `compliance_gov`      | Government classification compliance              |
| `compliance_hipaa`    | HIPAA/PHI compliance                              |
| `compliance_pci`      | PCI-DSS compliance                                |
| `compliance_legal`    | Legal privilege compliance                        |
| `compliance_soc2`     | SOC2 compliance                                   |
| `compliance_gdpr`     | GDPR compliance                                   |
| `custom_patterns`     | Custom regex patterns                             |
| `pattern_allowlisting`| Pattern suppression for known-safe operations     |
| `sso_integration`     | Single sign-on                                    |
| `audit_api`           | Audit log API access                              |
| `sla_support`         | SLA-backed support                                |
| `dedicated_support`   | Dedicated account manager                         |

### Feature Availability Matrix

| Feature                | FREE | PRO | ENTERPRISE |
|------------------------|------|-----|------------|
| 116 attack patterns    | Yes  | Yes | Yes        |
| Basic logging          | Yes  | Yes | Yes        |
| Credential vault       | Yes  | Yes | Yes        |
| CLI commands           | Yes  | Yes | Yes        |
| LLM semantic review    |      | Yes | Yes        |
| Session analysis       |      | Yes | Yes        |
| Rate limiting          |      | Yes | Yes        |
| Log export (CSV)       |      | Yes | Yes        |
| Custom tiers           |      | Yes | Yes        |
| Compliance modules     |      |     | Yes        |
| Custom patterns        |      |     | Yes        |
| Pattern allowlisting   |      |     | Yes        |
| SSO integration        |      |     | Yes        |
| Audit API              |      |     | Yes        |
| SLA support            |      |     | Yes        |

---

## License Key Format

License keys use a `payload.signature` format:

```
base64(json_payload).hmac_sha256_signature
```

### Example Key Structure

```
eyJ0aWVyIjoicHJvIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.a1b2c3d4e5f6
```

### Payload Structure

```json
{
  "tier": "pro",
  "email": "user@example.com",
  "issued_at": 1718400000,
  "expires_at": 1749936000,
  "features": []
}
```

| Field        | Type            | Description                              |
|--------------|-----------------|------------------------------------------|
| `tier`       | string          | `free`, `pro`, or `enterprise`           |
| `email`      | string          | Customer email address                    |
| `issued_at`  | int (Unix ts)   | Issuance timestamp                        |
| `expires_at` | int or null     | Expiration timestamp (null = never)       |
| `features`   | list of strings | Additional feature flags beyond tier      |

### Signature Verification

The signature is the first 32 characters of the HMAC-SHA256 digest of the
base64-encoded payload, computed using the license secret. Verification uses
`hmac.compare_digest` for constant-time comparison.

### LicenseInfo Dataclass

```python
@dataclass
class LicenseInfo:
    tier: Tier               # FREE, PRO, or ENTERPRISE
    email: str               # Customer email
    issued_at: int           # Unix timestamp
    expires_at: Optional[int]# Unix timestamp or None (never expires)
    features: List[str]      # Additional feature flags

    @property
    def is_expired(self) -> bool: ...

    @property
    def is_valid(self) -> bool: ...
```

---

## Activation and Deactivation

### Activation Flow

```
1. User runs: tweek license activate <key>
2. Key is split into payload + signature
3. Signature is verified via HMAC-SHA256
4. Payload is decoded and validated
5. Expiration is checked
6. Key is saved to ~/.tweek/license.key
7. LICENSE_EVENT logged (success or failure)
```

```python
from tweek.licensing import get_license

license = get_license()
success, message = license.activate("eyJ0a...abc123.deadbeef")
# (True, "License activated: PRO tier")
```

### Deactivation Flow

```
1. User runs: tweek license deactivate
2. ~/.tweek/license.key is deleted
3. License reverts to FREE tier
4. LICENSE_EVENT logged
```

```python
success, message = license.deactivate()
# (True, "License deactivated, reverted to FREE tier")
```

### License Properties

```python
license = get_license()

license.tier          # Tier.FREE, Tier.PRO, or Tier.ENTERPRISE
license.info          # LicenseInfo or None
license.is_pro        # True if PRO or ENTERPRISE
license.is_enterprise # True if ENTERPRISE only
```

---

## Feature Gating

### Checking Features

```python
from tweek.licensing import get_license

license = get_license()

# Check specific feature
license.has_feature("llm_review")       # True if PRO+
license.has_feature("custom_patterns")  # True if ENTERPRISE

# Get all available features
features = license.get_available_features()
# ['pattern_matching', 'basic_logging', 'vault_storage', ...]
```

Features are **cumulative** -- higher tiers include all features from lower
tiers. The `has_feature()` method checks:

1. All features for the current tier and below
2. Additional feature flags in `LicenseInfo.features`

### Feature Gating Decorators

Tweek provides four decorators for gating functions by license:

#### @require_tier(Tier)

Require a minimum tier. Raises `LicenseError` if the current tier is
insufficient.

```python
from tweek.licensing import require_tier, Tier

@require_tier(Tier.PRO)
def run_llm_review(command: str):
    """Only available to PRO and ENTERPRISE users."""
    ...

@require_tier(Tier.ENTERPRISE)
def apply_compliance_rules(data: dict):
    """Only available to ENTERPRISE users."""
    ...
```

#### @require_pro

Shorthand for `@require_tier(Tier.PRO)`.

```python
from tweek.licensing import require_pro

@require_pro
def session_analysis():
    ...
```

#### @require_enterprise

Shorthand for `@require_tier(Tier.ENTERPRISE)`.

```python
from tweek.licensing import require_enterprise

@require_enterprise
def custom_pattern_engine():
    ...
```

#### @require_feature(feature_name)

Require a specific feature string. Useful for granular gating beyond tier
level.

```python
from tweek.licensing import require_feature

@require_feature("llm_review")
def semantic_analysis():
    ...

@require_feature("compliance_hipaa")
def hipaa_check():
    ...
```

### LicenseError

When a gated function is called without the required license:

```python
from tweek.licensing import LicenseError

try:
    run_llm_review(command)
except LicenseError as e:
    print(e)
    # "This feature requires Tweek PRO.
    #  Visit https://gettweek.com/pricing to upgrade."
```

---

## CLI Commands

### Check License Status

```bash
tweek license status
```

Displays current tier, email, and expiration status.

### Activate License

```bash
tweek license activate <license-key>
```

Validates the key, saves it to `~/.tweek/license.key`, and reports the
activated tier.

### Deactivate License

```bash
tweek license deactivate
```

Removes the license key and reverts to the FREE tier.

---

## License Singleton Pattern

The `License` class uses a thread-safe singleton with double-checked locking:

```python
from tweek.licensing import get_license

# Always returns the same instance
license = get_license()
```

This ensures consistent license state across all modules during a session.

---

## Security Event Logging

All license operations are logged as `LICENSE_EVENT` in the security log:

| Operation    | Decision | Metadata                                |
|--------------|----------|-----------------------------------------|
| `activate`   | `allow`  | `{"operation": "activate", "tier": "pro", "success": true}` |
| `activate`   | `block`  | `{"operation": "activate", "success": false}` + reason |
| `deactivate` | `allow`  | `{"operation": "deactivate", "tier": "pro", "success": true}` |

---

## Tier Detection in Health Checks

The `tweek doctor` command includes a `license_status` check:

```
[     ok] License: PRO license (user@example.com)
[warning] License: PRO license expired
[     ok] License: Free tier active
```

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for more details.

---

## Expired License Behavior

When a license expires:

- The tier reverts to **FREE**
- PRO/ENTERPRISE features raise `LicenseError` when accessed
- Pattern matching (all 116 patterns) continues to work
- Basic logging continues to work
- The `tweek doctor` check reports a warning

No data is lost. Renewing the license restores full functionality immediately.

---

## FAQ

### Do I need internet for license validation?

License keys are validated locally. No internet connection is required after
initial activation.

### Can I transfer my license?

Yes. Deactivate on the old machine, activate on the new one.

### Can I use the FREE tier commercially?

Yes. The FREE tier is available for any use, including commercial projects.

### What about team licenses?

Contact sales@gettweek.com for team pricing and volume discounts.

---

## Purchasing

Visit [gettweek.com/pricing](https://gettweek.com/pricing) to purchase or
renew a license.

---

## License Key Security

- Keys are signed with HMAC-SHA256
- Validation is performed locally (no phone-home)
- Keys cannot be forged without the signing secret
- Expired keys are automatically rejected
- Constant-time comparison prevents timing attacks

---

## Cross-References

- [ATTACK_PATTERNS.md](./ATTACK_PATTERNS.md) -- Pattern library (free for all tiers)
- [LOGGING.md](./LOGGING.md) -- `advanced_logging` and `log_export` are PRO features
- [SANDBOX.md](./SANDBOX.md) -- Sandbox is available on all tiers
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) -- License health check details
