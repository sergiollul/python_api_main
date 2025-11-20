#!/usr/bin/env python3
# /srv/numbux-api/mdm_push_apns.py
import os
import sys
import time
import json
from typing import Optional

import httpx
import psycopg2
from psycopg2.extras import DictCursor


def must_get(key: str) -> str:
    v = os.getenv(key)
    if not v:
        print(f"[FATAL] Missing env var {key}", file=sys.stderr)
        sys.exit(1)
    return v


# --- Load .env (same as FastAPI) ---
ENV_PATH = "/srv/numbux-api/.env"
if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)

DATABASE_URL_RAW = must_get("DATABASE_URL")

def to_psycopg2_dsn(url: str) -> str:
    # Convert SQLAlchemy-style "postgresql+psycopg2://" → "postgresql://"
    if url.startswith("postgresql+psycopg2://"):
        return "postgresql://" + url[len("postgresql+psycopg2://"):]
    return url

DATABASE_DSN = to_psycopg2_dsn(DATABASE_URL_RAW)


# Your MDM client cert/key (from Apple Push Certificates Portal)
APNS_CLIENT_CERT_PATH = os.getenv(
    "APNS_CLIENT_CERT_PATH",
    "/etc/numbux-apns/mdm_client.pem",
)

# If you *ever* wanted sandbox (not for real MDM, but keeping the env var doesn’t hurt)
APNS_USE_SANDBOX = os.getenv("APNS_USE_SANDBOX", "false").lower() == "true"


def get_device(conn, device_id: int) -> Optional[dict]:
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(
            """
            SELECT
                id_mdm_ios_device,
                udid,
                topic,
                push_magic,
                push_token,
                is_enrolled
            FROM numbux.mdm_ios_device
            WHERE id_mdm_ios_device = %s
            """,
            (device_id,),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def send_mdm_push_for_device(device_id: int) -> None:
    conn = psycopg2.connect(DATABASE_DSN)
    try:
        dev = get_device(conn, device_id)
    finally:
        conn.close()

    if not dev:
        print(f"[PUSH] Device {device_id} not found")
        return

    if not dev.get("is_enrolled"):
        print(f"[PUSH] Device {device_id} is not enrolled")
        return

    topic = dev.get("topic")
    push_magic = dev.get("push_magic")
    token_bytes = dev.get("push_token")  # bytea in Postgres

    if not topic or not push_magic or not token_bytes:
        print(f"[PUSH] Device {device_id} missing topic/push_magic/push_token")
        return

    if isinstance(token_bytes, memoryview):
        token_bytes = token_bytes.tobytes()
    token_hex = token_bytes.hex()

    base_url = (
        "https://api.sandbox.push.apple.com"
        if APNS_USE_SANDBOX
        else "https://api.push.apple.com"
    )
    url = f"{base_url}/3/device/{token_hex}"

    payload = {"mdm": push_magic}
    headers = {
        "apns-topic": topic,
        "apns-push-type": "mdm",
        "content-type": "application/json",
    }

    print(f"[PUSH] Sending MDM push to device_id={device_id}, udid={dev['udid']}")
    print(f"[PUSH] APNs URL: {url}")
    print(f"[PUSH] Topic: {topic}")
    print(f"[PUSH] PushMagic: {push_magic}")
    print(f"[PUSH] Using client cert: {APNS_CLIENT_CERT_PATH}")

    # httpx will use the client certificate for TLS mutual auth
    # mdm_client.pem must contain BOTH the private key and certificate.
    with httpx.Client(
        http2=True,
        timeout=10.0,
        cert=APNS_CLIENT_CERT_PATH,
    ) as client:
        resp = client.post(url, headers=headers, content=json.dumps(payload))

    print(f"[PUSH] APNs status={resp.status_code}")
    if resp.content:
        try:
            print("[PUSH] APNs body:", resp.json())
        except Exception:
            print("[PUSH] APNs raw body:", resp.content)


def main():
    if len(sys.argv) != 2:
        print("Usage: mdm_push_apns.py <id_mdm_ios_device>", file=sys.stderr)
        sys.exit(1)

    device_id = int(sys.argv[1])
    send_mdm_push_for_device(device_id)


if __name__ == "__main__":
    main()
