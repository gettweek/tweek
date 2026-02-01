# Tweek Licensing Documentation

License model, feature availability, and future tiers.

---

## Overview

Tweek is **free and open source** (Apache 2.0). All security features are available
to every user with no license key, no usage limits, and no paywalls.

Pro (team management) and Enterprise (compliance) tiers are planned for the future.

**Source:** `tweek/licensing.py`

---

## Current Model: Everything Free

All individual security features ship open source:

| Feature                | Available |
|------------------------|-----------|
| 215 attack patterns    | Yes       |
| Custom pattern authoring | Yes     |
| LLM semantic review (BYOK) | Yes   |
| Session anomaly detection | Yes    |
| Rate limiting + circuit breaker | Yes |
| Sandbox preview        | Yes       |
| Credential vault       | Yes       |
| Security event logging | Yes       |
| NDJSON log export      | Yes       |
| CSV export             | Yes       |
| CLI hooks              | Yes       |
| MCP proxy              | Yes       |
| HTTP proxy             | Yes       |
| Health diagnostics     | Yes       |
| Security presets       | Yes       |
| Plugin architecture    | Yes       |

No license key is required for any of the above features.

---

## Future Tiers (Coming Soon)

### Pro -- Team Management

For teams of 2-50 developers who need centralized security configuration.

| Feature              | Description                                       |
|----------------------|---------------------------------------------------|
| `team_config`        | Centralized team configuration                    |
| `team_licenses`      | Team license management                           |
| `audit_api`          | Audit log API access                              |
| `priority_updates`   | Priority pattern update feed                      |
| `priority_support`   | Email support (48h SLA)                           |

### Enterprise -- Compliance

For regulated organizations with compliance requirements.

| Feature                | Description                                      |
|------------------------|--------------------------------------------------|
| `compliance_gov`       | Government classification compliance             |
| `compliance_hipaa`     | HIPAA/PHI compliance                             |
| `compliance_pci`       | PCI-DSS compliance (with Luhn validation)        |
| `compliance_legal`     | Legal privilege compliance                       |
| `compliance_soc2`      | SOC2 compliance                                  |
| `compliance_gdpr`      | GDPR compliance                                  |
| `bidirectional_scanning` | Bidirectional compliance scanning              |
| `sso_integration`      | Single sign-on (SAML, OIDC)                     |
| `sla_support`          | SLA-backed support                               |
| `dedicated_support`    | Dedicated account manager                        |

---

## License Architecture

The licensing infrastructure exists in `tweek/licensing.py` and supports:

- Three tiers: `FREE`, `PRO`, `ENTERPRISE`
- License key format: `base64(json_payload).hmac_sha256_signature`
- Local validation (no phone-home)
- Feature gating via `has_feature()` and decorator guards

Currently, all features resolve to the FREE tier, which includes everything.
When Pro and Enterprise launch, the feature gating will activate for
team management and compliance features only.

### License Key Format

```
base64(json_payload).hmac_sha256_signature
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

### CLI Commands

```bash
tweek license status                     # Check current status
tweek license activate YOUR_KEY          # Activate Pro/Enterprise (when available)
tweek license deactivate                 # Remove license
```

---

## License Key Security

- Keys are signed with HMAC-SHA256
- Validation is performed locally (no phone-home)
- Keys cannot be forged without the signing secret
- Expired keys are automatically rejected
- Constant-time comparison prevents timing attacks

---

## FAQ

### Do I need a license key?

No. All security features work without a license key. A key will only be
needed for future Pro (team) and Enterprise (compliance) features.

### Can I use Tweek commercially?

Yes. Tweek is Apache 2.0 licensed. Use it however you want.

### What about the LLM review feature?

LLM review uses Claude Haiku for semantic analysis. You provide your own
Anthropic API key via the `ANTHROPIC_API_KEY` environment variable.
Tweek never stores or transmits your API key.

### When will Pro and Enterprise launch?

Join the waitlist at [gettweek.com](https://gettweek.com) for updates.

---

## Cross-References

- [ATTACK_PATTERNS.md](./ATTACK_PATTERNS.md) -- Pattern library (all free)
- [LOGGING.md](./LOGGING.md) -- All logging features are free
- [SANDBOX.md](./SANDBOX.md) -- Sandbox is free
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) -- Diagnostic details
