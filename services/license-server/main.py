#!/usr/bin/env python3
"""
Tweek License Server

A simple FastAPI service that:
1. Receives webhooks from LemonSqueezy after purchase
2. Generates license keys
3. Stores license records
4. Validates keys (optional - for future use)

Deploy to: Vercel, Railway, Fly.io, or any Python host

Environment Variables:
    LEMONSQUEEZY_WEBHOOK_SECRET - Webhook signing secret from LemonSqueezy
    LICENSE_SECRET - Secret for signing license keys (same as in tweek/licensing.py)
    DATABASE_URL - SQLite or PostgreSQL connection string (optional)
"""

import hashlib
import hmac
import json
import os
import time
import base64
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import sqlite3

# ============================================================
# Configuration
# ============================================================

LEMONSQUEEZY_WEBHOOK_SECRET = os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET", "")
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "tweek-2025-license-secret")
DATABASE_PATH = os.environ.get("DATABASE_PATH", "licenses.db")

# Product ID to tier mapping (configure in LemonSqueezy)
PRODUCT_TIERS = {
    "tweek-pro": "pro",
}

# ============================================================
# Database
# ============================================================

def init_db():
    """Initialize the database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            tier TEXT NOT NULL,
            email TEXT NOT NULL,
            order_id TEXT,
            customer_id TEXT,
            issued_at TEXT NOT NULL,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(key)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email)
    """)
    conn.commit()
    conn.close()

def save_license(key: str, tier: str, email: str, order_id: str = None,
                 customer_id: str = None, expires_at: str = None):
    """Save a license to the database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("""
        INSERT INTO licenses (key, tier, email, order_id, customer_id, issued_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (key, tier, email, order_id, customer_id, datetime.utcnow().isoformat(), expires_at))
    conn.commit()
    conn.close()

def get_license(key: str) -> Optional[dict]:
    """Get license info by key."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()
    conn.close()
    return dict(row) if row else None

def revoke_license(key: str) -> bool:
    """Revoke a license."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.execute("UPDATE licenses SET revoked = 1 WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0

# ============================================================
# License Key Generation
# ============================================================

def generate_license_key(tier: str, email: str, expires_at: Optional[int] = None) -> str:
    """
    Generate a license key.

    Key format: base64(json_payload).signature
    Same format as tweek/licensing.py for compatibility.
    """
    payload = {
        "tier": tier,
        "email": email,
        "issued_at": int(time.time()),
        "expires_at": expires_at,
        "features": [],
    }

    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.b64encode(payload_json.encode()).decode()

    signature = hmac.new(
        LICENSE_SECRET.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).hexdigest()[:32]

    return f"{payload_b64}.{signature}"

# ============================================================
# LemonSqueezy Webhook Handling
# ============================================================

def verify_lemonsqueezy_signature(payload: bytes, signature: str) -> bool:
    """Verify the webhook signature from LemonSqueezy."""
    if not LEMONSQUEEZY_WEBHOOK_SECRET:
        return True  # Skip verification in development

    expected = hmac.new(
        LEMONSQUEEZY_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)

# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(
    title="Tweek License Server",
    description="License key generation and validation for Tweek",
    version="1.0.0"
)

@app.on_event("startup")
async def startup():
    init_db()

class WebhookPayload(BaseModel):
    """LemonSqueezy webhook payload (simplified)."""
    meta: dict
    data: dict

@app.post("/webhooks/lemonsqueezy")
async def lemonsqueezy_webhook(
    request: Request,
    x_signature: str = Header(None, alias="X-Signature")
):
    """
    Handle LemonSqueezy webhooks.

    Triggered on:
    - order_created: Generate and store license key
    - subscription_cancelled: Revoke license (if subscription model)
    - order_refunded: Revoke license
    """
    body = await request.body()

    # Verify signature
    if x_signature and not verify_lemonsqueezy_signature(body, x_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_name = payload.get("meta", {}).get("event_name")
    data = payload.get("data", {})
    attributes = data.get("attributes", {})

    if event_name == "order_created":
        # Extract customer info
        email = attributes.get("user_email")
        order_id = str(data.get("id"))
        customer_id = str(attributes.get("customer_id"))
        product_name = attributes.get("first_order_item", {}).get("product_name", "").lower()

        # Determine tier from product
        tier = "pro"  # Default
        for product_key, product_tier in PRODUCT_TIERS.items():
            if product_key in product_name:
                tier = product_tier
                break

        # Generate license key
        license_key = generate_license_key(tier, email)

        # Save to database
        save_license(
            key=license_key,
            tier=tier,
            email=email,
            order_id=order_id,
            customer_id=customer_id
        )

        # Note: LemonSqueezy will send the key via email using the
        # "License key" field in the order. You can also configure
        # a custom email template that includes the key.

        return {"status": "ok", "license_key": license_key}

    elif event_name in ("order_refunded", "subscription_cancelled"):
        # Find and revoke the license
        order_id = str(data.get("id"))
        # Would need to look up by order_id and revoke
        # For now, just acknowledge
        return {"status": "ok", "action": "revoke_pending"}

    return {"status": "ok", "event": event_name}

@app.post("/api/validate")
async def validate_license(request: Request):
    """
    Validate a license key.

    Optional endpoint for future server-side validation.
    Currently, Tweek validates keys locally.
    """
    body = await request.json()
    key = body.get("key")

    if not key:
        raise HTTPException(status_code=400, detail="Missing key")

    license_info = get_license(key)

    if not license_info:
        return {"valid": False, "reason": "Key not found"}

    if license_info.get("revoked"):
        return {"valid": False, "reason": "License revoked"}

    if license_info.get("expires_at"):
        expires = datetime.fromisoformat(license_info["expires_at"])
        if datetime.utcnow() > expires:
            return {"valid": False, "reason": "License expired"}

    return {
        "valid": True,
        "tier": license_info["tier"],
        "email": license_info["email"]
    }

@app.get("/api/generate")
async def generate_test_key(tier: str = "pro", email: str = "test@example.com"):
    """
    Generate a test license key (for development only).

    Remove or protect this endpoint in production!
    """
    if os.environ.get("ENVIRONMENT") == "production":
        raise HTTPException(status_code=403, detail="Disabled in production")

    key = generate_license_key(tier, email)
    save_license(key=key, tier=tier, email=email)

    return {"key": key, "tier": tier, "email": email}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ============================================================
# Run with: uvicorn main:app --reload
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
