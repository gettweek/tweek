# Tweek License Server

Webhook service for LemonSqueezy integration and license key management.

## How It Works

```
Customer pays $49 on LemonSqueezy
         │
         ▼
LemonSqueezy sends webhook to /webhooks/lemonsqueezy
         │
         ▼
Server generates license key
         │
         ▼
Key stored in database + returned to LemonSqueezy
         │
         ▼
LemonSqueezy emails key to customer
         │
         ▼
Customer runs: tweek license activate <key>
```

## Setup

### 1. Deploy the Server

**Option A: Railway (Recommended)**
```bash
# Install Railway CLI
npm install -g @railway/cli

# Deploy
railway login
railway init
railway up
```

**Option B: Fly.io**
```bash
fly launch
fly secrets set LEMONSQUEEZY_WEBHOOK_SECRET=xxx LICENSE_SECRET=xxx
fly deploy
```

**Option C: Vercel**
```bash
vercel --prod
```

### 2. Configure LemonSqueezy

1. Go to [LemonSqueezy Dashboard](https://app.lemonsqueezy.com)
2. Create a product: "Tweek Pro - $49"
3. Go to Settings → Webhooks
4. Add webhook URL: `https://your-server.com/webhooks/lemonsqueezy`
5. Select events: `order_created`, `order_refunded`
6. Copy the signing secret

### 3. Set Environment Variables

```bash
# On your deployment platform:
LEMONSQUEEZY_WEBHOOK_SECRET=your_webhook_secret_from_lemonsqueezy
LICENSE_SECRET=your_secret_key_for_signing_licenses
ENVIRONMENT=production
DATABASE_PATH=/data/licenses.db  # Or use PostgreSQL
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhooks/lemonsqueezy` | POST | Receives LemonSqueezy webhooks |
| `/api/validate` | POST | Validate a license key (optional) |
| `/api/generate` | GET | Generate test key (dev only) |
| `/health` | GET | Health check |

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn main:app --reload

# Test key generation
curl http://localhost:8000/api/generate?tier=pro&email=test@example.com
```

## Database

By default uses SQLite (`licenses.db`). For production, consider PostgreSQL:

```python
# Modify main.py to use asyncpg or databases library
DATABASE_URL = os.environ.get("DATABASE_URL")
```

## Security Notes

1. Always verify webhook signatures in production
2. Keep `LICENSE_SECRET` secure and matching between server and client
3. Remove `/api/generate` endpoint in production
4. Use HTTPS only
5. Consider rate limiting the validate endpoint

## LemonSqueezy Email Template

Configure your order confirmation email to include:

```
Your Tweek Pro license key:
{{ license_key }}

To activate:
1. Open terminal
2. Run: tweek license activate {{ license_key }}

Thank you for your purchase!
```
