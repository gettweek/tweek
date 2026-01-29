# Tweek Licensing

Tweek uses a tiered licensing model to balance open-source availability with sustainable development.

## License Tiers

| Tier | Price | Best For |
|------|-------|----------|
| **FREE** | $0 | Individual developers, small projects |
| **PRO** | $19/month | Professional developers, teams |
| **ENTERPRISE** | Contact us | Large organizations, compliance needs |

## Feature Comparison

### FREE Tier (Open Source)

All core security features:

- **Pattern Matching** - 100+ regex patterns for known attack signatures
- **Basic Logging** - SQLite-based security event logging
- **Vault Storage** - Secure credential storage in system keychain
- **CLI Commands** - Full command-line interface
- **Global Install** - Protect all projects
- **Project Install** - Per-project configuration

### PRO Tier

Everything in FREE, plus:

- **LLM Review** - Semantic analysis using Claude Haiku for suspicious commands
- **Session Analysis** - Cross-turn anomaly detection for persistent attacks
- **Rate Limiting** - Protection against resource theft and quota drain
- **Advanced Logging** - Detailed event metadata and context
- **Log Export** - Export security logs to CSV
- **Custom Tiers** - Define custom security tiers per tool/skill
- **Priority Support** - Email support with 24-hour response

### ENTERPRISE Tier

Everything in PRO, plus:

- **Custom Patterns** - Add organization-specific detection patterns
- **Pattern API** - Programmatic pattern management
- **SSO Integration** - SAML/OIDC authentication
- **Audit API** - REST API for security event queries
- **Webhook Alerts** - Real-time notifications to Slack, Teams, etc.
- **SLA Guarantee** - 99.9% uptime for license validation
- **Dedicated Support** - Dedicated support engineer
- **On-Premise** - Self-hosted license server option

## Activating a License

### Via CLI

```bash
# Activate a license key
tweek license activate YOUR_LICENSE_KEY

# Check current status
tweek license status

# Deactivate (revert to FREE)
tweek license deactivate
```

### License Key Format

License keys are issued in the format:

```
eyJ0aWVyIjoicHJvIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.a1b2c3d4e5f6
```

The key contains:
- Tier (free/pro/enterprise)
- Licensed email
- Issue and expiration dates
- Additional feature flags

### License File Location

License keys are stored at:
```
~/.tweek/license.key
```

## Purchasing

Visit [gettweek.com/pricing](https://gettweek.com/pricing) to purchase a license.

### Payment Options

- Monthly subscription (cancel anytime)
- Annual subscription (2 months free)
- Volume discounts for teams (5+ seats)

### Free Trial

All paid features include a 14-day free trial. No credit card required.

## FAQ

### What happens when my license expires?

You revert to the FREE tier. All security events and logs are preserved. Pattern matching and basic logging continue to work.

### Can I use FREE tier commercially?

Yes! The FREE tier is Apache 2.0 licensed and can be used in any commercial project.

### Do I need internet for license validation?

License keys are validated locally. No internet connection is required after initial activation.

### Can I transfer my license?

Yes, licenses can be transferred between machines. Deactivate on the old machine, activate on the new one.

### What about team licenses?

Contact us at sales@gettweek.com for team pricing and volume discounts.

## Support

- FREE tier: GitHub Issues
- PRO tier: Email support (support@gettweek.com)
- ENTERPRISE tier: Dedicated support engineer

## License Key Security

- Keys are signed with HMAC-SHA256
- Validation is performed locally
- Keys cannot be forged without the signing secret
- Expired keys are automatically rejected
