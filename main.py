# /srv/numbux-api/app/main.py
import os
import sys
from datetime import datetime, timedelta, timezone, date
from fastapi import FastAPI, HTTPException, Depends, Header, APIRouter, WebSocket, WebSocketDisconnect, status, Form, BackgroundTasks, Request, Response
import plistlib
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError, ProgrammingError, IntegrityError
from passlib.hash import bcrypt
from jose import jwt, JWTError
from dotenv import load_dotenv
import json, requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GAuthRequest
from typing import List, Optional, Literal
import secrets, base64
import logging
from typing import Optional
import re
import smtplib
from email.message import EmailMessage
from uuid import uuid4
import base64
from pathlib import Path
from mdm_push_apns import send_mdm_push_for_device


ENV_PATH = "/srv/numbux-api/.env"
load_dotenv(ENV_PATH)

def must_get(key: str) -> str:
    val = os.getenv(key)
    if not val:
        sys.stderr.write(f"[FATAL] Missing required env var {key}. Check {ENV_PATH} and/or your systemd EnvironmentFile.\n")
        sys.exit(1)
    return val

# === Config (hardened) ===
DATABASE_URL   = must_get("DATABASE_URL")
JWT_SECRET     = must_get("JWT_SECRET")
JWT_ALGORITHM  = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "60"))

# ✅ NEW: refresh token config
REFRESH_SECRET      = os.getenv("REFRESH_SECRET", JWT_SECRET)  # prefer separate secret
REFRESH_EXPIRE_DAYS = int(os.getenv("REFRESH_EXPIRE_DAYS", "14"))
ROTATE_REFRESH      = os.getenv("ROTATE_REFRESH", "true").lower() == "true"

# === Reset Password ===
RESET_SECRET      = os.getenv("RESET_SECRET", JWT_SECRET)
RESET_EXPIRE_MIN  = int(os.getenv("RESET_EXPIRE_MIN", "15"))  # 15 minutes

# === Apple MDM (iOS) ===
APPLE_MDM_TOPIC = os.getenv("APPLE_MDM_TOPIC", "com.numbux.mdm")  # TODO: real topic from Apple MDM Push cert
APPLE_MDM_SCEP_URL = os.getenv("APPLE_MDM_SCEP_URL", "https://mdm.numbux.com/mdm/scep")
APPLE_MDM_ORG = os.getenv("APPLE_MDM_ORG", "Numbux")
APPLE_MDM_PROFILE_NAME = os.getenv("APPLE_MDM_PROFILE_NAME", "Numbux Device Management")
APPLE_MDM_MDM_NAME = os.getenv("APPLE_MDM_MDM_NAME", "Numbux MDM")

SMTP_HOST      = must_get("SMTP_HOST")
SMTP_PORT      = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER      = must_get("SMTP_USER")
SMTP_PASSWORD  = must_get("SMTP_PASSWORD")
SMTP_FROM      = os.getenv("SMTP_FROM", SMTP_USER)


# Server-side password strength check (same rules as the HTML/JS)
PASSWORD_REGEX = re.compile(
    r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>_\-]).{8,}$'
)

# === DB engine (with clear error) ===
try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
except SQLAlchemyError as e:
    sys.stderr.write(f"[FATAL] Could not create DB engine. Error: {e}\n")
    sys.exit(1)

# === FastAPI app ===
app = FastAPI(title="Numbux API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# IMPORTANT: use ABSOLUTE imports (package: app.*)
# and run uvicorn with "app.main:app" + WorkingDirectory=/srv/numbux-api
from app.routes_classes import router as classes_router
app.include_router(classes_router, prefix="/api")

# ======= /api/license/resolve (mounted under /api) =======
from fastapi import APIRouter, Query

# === Live websocket fanout (global process state) ===
import json
from typing import Dict, Set
import anyio

# classroom_id -> set of active websockets
classroom_subs: Dict[int, Set[WebSocket]] = {}
# (optional) teacher_id -> set(classroom_ids) if you later need it
teacher_index: Dict[int, Set[int]] = {}

async def ws_send(ws: WebSocket, payload: dict):
    await ws.send_text(json.dumps(payload))

def broadcast_to_classrooms(classroom_ids: list[int], payload: dict):
    """
    Can be called from normal (sync) endpoints.
    It schedules the actual send on the WS task using anyio.from_thread.run.
    """
    sent = 0
    for cid in classroom_ids:
        # Copy to avoid 'set changed size during iteration'
        for ws in classroom_subs.get(cid, set()).copy():
            try:
                anyio.from_thread.run(ws_send, ws, payload)
                sent += 1
            except Exception:
                # socket may be closed; best effort
                pass
    return sent


license_router = APIRouter()

class LicenseResolveResponse(BaseModel):
    role: str            # 'student' | 'teacher' | 'admin'
    id_ec: int
    center_name: str | None = None

LICENSE_RESOLVE_SQL = text("""
    SELECT
        l.id_ec,
        l.status,
        l.start_date,
        l.end_date,
        COALESCE(l.in_use, FALSE) AS in_use,
        lt.license_type AS license_type,
        ec.commercial_name AS center_name
    FROM numbux.license l
    JOIN numbux.license_type lt
      ON lt.id_license_type = l.id_license_type
    LEFT JOIN numbux.educational_center ec
      ON ec.id_ec = l.id_ec
    WHERE l.license_code = :code
    LIMIT 1
""")


@license_router.get("/license/resolve", response_model=LicenseResolveResponse)
def resolve_license(license_code: str = Query(..., alias="license_code")):
    with engine.connect() as conn:
        row = conn.execute(LICENSE_RESOLVE_SQL, {"code": license_code}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="License not found")
    if not _is_license_active(row):
        raise HTTPException(status_code=400, detail="License is not active for today")
    if row["in_use"]:
        raise HTTPException(status_code=409, detail="License already used")

    role = (row["license_type"] or "").strip().lower()
    if role not in {"student", "teacher", "admin"}:
        raise HTTPException(status_code=400, detail="Unknown license role")

    return {"role": role, "id_ec": int(row["id_ec"]), "center_name": row.get("center_name")}

# Mount it under /api
app.include_router(license_router, prefix="/api")

# ======= Auth models & helpers =======
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: int
    email: EmailStr
    refresh_token: str | None = None

class RefreshRequest(BaseModel):
    refresh_token: str

class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None

class JoinOpenRequest(BaseModel):
    expires_in_minutes: int = Field(60, ge=5, le=7*24*60)  # 5 min … 7 days

class JoinOpenResponse(BaseModel):
    classroom_id: int
    allow_join_student: bool
    join_token: str
    join_url: str
    join_token_expires_at: datetime | None = None

class JoinCloseResponse(BaseModel):
    classroom_id: int
    allow_join_student: bool

class StudentJoinRequest(BaseModel):
    token: str

class StudentJoinResponse(BaseModel):
    ok: bool
    classroom_id: int | None = None
    status: str | None = None   # "enrolled" | "already_enrolled"

class JoinResolveResponse(BaseModel):
    classroom_id: int
    course: str | None = None
    group: str | None = None
    subject: str | None = None
    center_name: str | None = None
    allow_join_student: bool
    join_token_expires_at: datetime | None = None

log = logging.getLogger("join")

class JoinReq(BaseModel):
    token: str

class JoinResp(BaseModel):
    joined: bool
    classroom_id: int


def _gen_join_token(nbytes: int = 18) -> str:
    # ~144 bits of entropy, URL-safe
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode().rstrip("=")

def _now_utc():
    return datetime.now(tz=timezone.utc)



# === Live broadcast helpers (require: engine, _now_utc, broadcast_to_classrooms) ===
def classrooms_for_student(conn, student_id: int) -> list[int]:
    rows = conn.execute(text("""
        SELECT id_classroom
          FROM numbux.student_classroom
         WHERE id_student = :sid
    """), {"sid": student_id}).fetchall()
    return [r[0] for r in rows]

def broadcast_student_toggle(*, student_id: int, is_locked: bool):
    # gather all classrooms for this student
    with engine.connect() as conn:
        cids = classrooms_for_student(conn, student_id)
    payload = {
        "type": "student_toggle",
        "student_id": student_id,
        "is_locked": is_locked,
        "ts": _now_utc().isoformat(),
    }
    broadcast_to_classrooms(cids, payload)


def create_access_token(payload: dict, minutes: int = JWT_EXPIRE_MIN) -> str:
    to_encode = payload.copy()
    to_encode["typ"] = "access"
    to_encode["exp"] = datetime.now(tz=timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(payload: dict, days: int = REFRESH_EXPIRE_DAYS) -> str:
    to_encode = payload.copy()
    to_encode["typ"] = "refresh"
    to_encode["exp"] = _now_utc() + timedelta(days=days)
    return jwt.encode(to_encode, REFRESH_SECRET, algorithm=JWT_ALGORITHM)

def create_reset_token(email: str, role: str, user_id: int) -> str:
    """
    Short-lived token to reset password.
    """
    to_encode = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "typ": "reset",
        "exp": _now_utc() + timedelta(minutes=RESET_EXPIRE_MIN),
    }
    return jwt.encode(to_encode, RESET_SECRET, algorithm=JWT_ALGORITHM)


def decode_reset_token(token: str) -> dict:
    """
    Validates and decodes reset token; raises HTTPException if invalid.
    """
    try:
        payload = jwt.decode(token, RESET_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "reset":
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


LOOKUP_SQL = text("""
    WITH candidates AS (
        SELECT id::bigint AS user_id, email, password_hash, 'admin_numbux'::text AS role
        FROM numbux.admin_numbux WHERE lower(email) = :email
        UNION ALL
        SELECT id_admin::bigint AS user_id, email, password_hash, 'admin'::text AS role
        FROM numbux.admin WHERE lower(email) = :email
        UNION ALL
        SELECT id_teacher::bigint AS user_id, email, password_hash, 'teacher'::text AS role
        FROM numbux.teacher WHERE lower(email) = :email
        UNION ALL
        SELECT id_student::bigint AS user_id, email, password_hash, 'student'::text AS role
        FROM numbux.student WHERE lower(email) = :email
    )
    SELECT * FROM candidates LIMIT 1
""")

# ======= /login endpoint (replaces /check_email) =======
@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    email_lower = payload.email.lower()
    with engine.connect() as conn:
        row = conn.execute(LOOKUP_SQL, {"email": email_lower}).mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    try:
        ok = bcrypt.verify(payload.password, row["password_hash"])
    except Exception:
        ok = False

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    base_claims = {"sub": str(row["user_id"]), "email": row["email"], "role": row["role"]}
    access  = create_access_token(base_claims)
    refresh = create_refresh_token(base_claims)

    return TokenResponse(
    access_token=access,
    refresh_token=refresh,    # ✅ NEW
    role=row["role"],
    user_id=row["user_id"],
    email=row["email"],
    )


# 2) TOKEN DEPENDENCY + /me ENDPOINT (add this block right after /login)
def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split()[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Ensure it's an access token, not a refresh one
        if payload.get("typ") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        return {
            "user_id": int(payload["sub"]),
            "email": payload["email"],
            "role": payload["role"],
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    

# === MDM client certificate "auth" (no JWT) ===
def require_mdm_client_cert(
    ssl_client_verify: str | None = Header(None, alias="x-ssl-client-verify"),
    ssl_client_subject: str | None = Header(None, alias="x-ssl-client-subject-dn"),
    ssl_client_serial: str | None = Header(None, alias="x-ssl-client-serial"),
):
    """
    Used only on /mdm/* endpoints.
    Nginx/Plesk fills these headers based on TLS client certificates.
    """
    # For now we just log; later you can enforce SUCCESS strictly.
    print("[MDM][CERT]", ssl_client_verify, ssl_client_subject, ssl_client_serial)

    # When you’re ready to enforce:
    # if ssl_client_verify != "SUCCESS":
    #     raise HTTPException(status_code=403, detail="MDM client certificate required")

    return {
        "subject_dn": ssl_client_subject,
        "serial": ssl_client_serial,
    }


def _parse_plist_body(raw: bytes) -> dict:
    try:
        if not raw:
            raise ValueError("Empty body")
        return plistlib.loads(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid plist: {e.__class__.__name__}")


# === Apple MDM check-in & command endpoints (plist, no JWT) ===
mdm_plist_router = APIRouter()


@app.get("/mdm/enroll/profile")
def mdm_enroll_profile():
    """
    Downloadable .mobileconfig to enroll iOS into Numbux MDM.
    Root type: Configuration

    Includes:
      - com.apple.security.pkcs12 payload (device identity certificate)
      - com.apple.mdm payload (device MDM channel)
    """

    org_name = APPLE_MDM_ORG        # e.g. "Numbux"
    base_id  = "com.numbux.mdm"
    enroll_id = "default"

    # === Load PKCS#12 from env (base64) ===
    p12_b64 = must_get("APPLE_MDM_P12_BASE64")
    p12_bytes = base64.b64decode(p12_b64)
    p12_password = os.getenv("APPLE_MDM_P12_PASSWORD", "NumbuxP12Pass123!")

    # === PKCS#12 identity payload ===
    pkcs_payload_uuid = str(uuid4())
    pkcs_payload = {
        "PayloadType": "com.apple.security.pkcs12",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{base_id}.identity.{enroll_id}",
        "PayloadUUID": pkcs_payload_uuid,
        "PayloadDisplayName": "Numbux MDM Identity",
        "PayloadDescription": "Certificado de identidad para Numbux MDM (PKCS#12 embebido).",
        "PayloadOrganization": org_name,

        # Password to unlock the pkcs12
        "Password": p12_password,

        # Raw PKCS#12 bytes → plistlib will encode as <data>...</data>
        "PayloadContent": p12_bytes,
    }

    # === MDM payload ===
    mdm_payload_uuid = str(uuid4())
    checkin_url = "https://mdm.numbux.com/mdm/checkin"
    command_url = "https://mdm.numbux.com/mdm/command"

    topic = os.getenv(
        "APPLE_MDM_TOPIC",
        "com.apple.mgmt.External.f53319ba-1fff-450f-8ab9-a1e8807b48f0",
    )

    mdm_payload = {
        "PayloadType": "com.apple.mdm",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{base_id}.device.{enroll_id}",
        "PayloadUUID": mdm_payload_uuid,
        "PayloadDisplayName": APPLE_MDM_MDM_NAME,
        "PayloadDescription": "Inscripción del dispositivo en Numbux MDM.",
        "PayloadOrganization": org_name,

        "ServerURL": command_url,
        "CheckInURL": checkin_url,
        "Topic": topic,
        "SignMessage": True,
        "CheckOutWhenRemoved": True,

        # 👇 Now reference the PKCS#12 identity payload, not SCEP
        "IdentityCertificateUUID": pkcs_payload_uuid,

        "AccessRights": 8191,
        "ServerCapabilities": ["com.apple.mdm.per-user-connections"],
    }

    # === Root configuration profile ===
    root_profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{base_id}.enroll.{enroll_id}",
        "PayloadUUID": str(uuid4()),
        "PayloadDisplayName": APPLE_MDM_PROFILE_NAME,
        "PayloadDescription": (
            "Perfil para inscribir este dispositivo en Numbux MDM "
            "y permitir el control de apps en el aula."
        ),
        "PayloadOrganization": org_name,
        "PayloadContent": [
            pkcs_payload,
            mdm_payload,
        ],
    }

    data = plistlib.dumps(root_profile)
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": 'attachment; filename="NumbuxMDM.mobileconfig"'
        },
    )



@mdm_plist_router.api_route("/mdm/checkin", methods=["GET", "HEAD", "OPTIONS"])
async def mdm_checkin_probe(request: Request):
    """
    Probe endpoint for iOS during profile installation.

    iOS may do GET/HEAD/OPTIONS to the CheckInURL to verify the server.
    We always return 200 OK with an empty XML body.
    """
    return Response(
        content=b"",
        media_type="application/xml",
    )


@mdm_plist_router.api_route("/mdm/checkin", methods=["POST", "PUT"])
async def mdm_checkin(
    request: Request,
    client_cert = Depends(require_mdm_client_cert),
):
    """
    Apple MDM check-in endpoint.

    iOS may use POST (standard) or PUT (some flows).
    We treat them the same: plist body with MessageType, UDID, etc.
    """
    raw = await request.body()
    payload = _parse_plist_body(raw)

    msg_type = payload.get("MessageType")
    udid     = payload.get("UDID")

    if not msg_type or not udid:
        raise HTTPException(
            status_code=400,
            detail="Missing MessageType or UDID in check-in payload"
        )

    # Common device metadata (keys used by Apple)
    device_name   = payload.get("DeviceName") or payload.get("DeviceNameRaw")
    os_version    = payload.get("OSVersion")
    build_version = payload.get("BuildVersion")
    model         = payload.get("Model") or payload.get("ProductName")
    serial_number = payload.get("SerialNumber")
    imei          = payload.get("IMEI")
    meid          = payload.get("MEID")

    # For TokenUpdate
    topic        = payload.get("Topic")
    push_magic   = payload.get("PushMagic")
    token_bytes  = payload.get("Token")        # bytes from plist
    unlock_bytes = payload.get("UnlockToken")  # bytes from plist

    client_subject = client_cert.get("subject_dn")
    client_serial  = client_cert.get("serial")

    # Encode raw plist into text for mdm_ios_checkin_log.raw_plist
    # Try UTF-8; if it fails (binary plist), fall back to base64.
    import base64
    try:
        raw_plist_str = raw.decode("utf-8")
    except UnicodeDecodeError:
        raw_plist_str = "BASE64:" + base64.b64encode(raw).decode("ascii")

    now_utc = _now_utc()

    try:
        with engine.begin() as conn:
            # Optionally: try to link UDID to an existing student by device_id
            student_row = conn.execute(text("""
                SELECT
                    s.id_student,
                    se.id_ec
                FROM numbux.student s
                LEFT JOIN numbux.student_ec se
                       ON se.id_student = s.id_student
                      AND (se.status ILIKE 'active' OR se.status IS NULL)
                WHERE s.device_id = :udid
                ORDER BY se.start_date DESC NULLS LAST
                LIMIT 1
            """), {"udid": udid}).mappings().first()

            id_student = student_row["id_student"] if student_row else None
            id_ec      = student_row["id_ec"] if student_row else None

            id_mdm_ios_device = None

            if msg_type == "Authenticate":
                # First step: device identifies itself.
                row = conn.execute(text("""
                    INSERT INTO numbux.mdm_ios_device
                        (udid,
                         serial_number,
                         imei,
                         meid,
                         device_name,
                         model,
                         os_version,
                         build_version,
                         id_student,
                         id_ec,
                         cert_subject_dn,
                         cert_serial,
                         is_enrolled,
                         enrolled_at,
                         last_checkin_at,
                         last_seen_at,
                         updated_at)
                    VALUES
                        (:udid,
                         :serial_number,
                         :imei,
                         :meid,
                         :device_name,
                         :model,
                         :os_version,
                         :build_version,
                         :id_student,
                         :id_ec,
                         :cert_subject_dn,
                         :cert_serial,
                         TRUE,
                         :now,
                         :now,
                         :now,
                         :now)
                    ON CONFLICT (udid)
                    DO UPDATE
                       SET serial_number   = COALESCE(EXCLUDED.serial_number,   numbux.mdm_ios_device.serial_number),
                           imei            = COALESCE(EXCLUDED.imei,            numbux.mdm_ios_device.imei),
                           meid            = COALESCE(EXCLUDED.meid,            numbux.mdm_ios_device.meid),
                           device_name     = COALESCE(EXCLUDED.device_name,     numbux.mdm_ios_device.device_name),
                           model           = COALESCE(EXCLUDED.model,           numbux.mdm_ios_device.model),
                           os_version      = COALESCE(EXCLUDED.os_version,      numbux.mdm_ios_device.os_version),
                           build_version   = COALESCE(EXCLUDED.build_version,   numbux.mdm_ios_device.build_version),
                           id_student      = COALESCE(EXCLUDED.id_student,      numbux.mdm_ios_device.id_student),
                           id_ec           = COALESCE(EXCLUDED.id_ec,           numbux.mdm_ios_device.id_ec),
                           cert_subject_dn = COALESCE(EXCLUDED.cert_subject_dn, numbux.mdm_ios_device.cert_subject_dn),
                           cert_serial     = COALESCE(EXCLUDED.cert_serial,     numbux.mdm_ios_device.cert_serial),
                           is_enrolled     = TRUE,
                           last_checkin_at = :now,
                           last_seen_at    = :now,
                           updated_at      = :now
                    RETURNING id_mdm_ios_device
                """), {
                    "udid": udid,
                    "serial_number": serial_number,
                    "imei": imei,
                    "meid": meid,
                    "device_name": device_name,
                    "model": model,
                    "os_version": os_version,
                    "build_version": build_version,
                    "id_student": id_student,
                    "id_ec": id_ec,
                    "cert_subject_dn": client_subject,
                    "cert_serial": client_serial,
                    "now": now_utc,
                }).mappings().first()

                if row:
                    id_mdm_ios_device = row["id_mdm_ios_device"]

            elif msg_type == "TokenUpdate":
                # Second step: APNs token, PushMagic, UnlockToken.
                row = conn.execute(text("""
                    INSERT INTO numbux.mdm_ios_device
                        (udid,
                         serial_number,
                         imei,
                         meid,
                         device_name,
                         model,
                         os_version,
                         build_version,
                         id_student,
                         id_ec,
                         topic,
                         push_token,
                         push_magic,
                         unlock_token,
                         cert_subject_dn,
                         cert_serial,
                         is_enrolled,
                         enrolled_at,
                         last_checkin_at,
                         last_token_update_at,
                         last_seen_at,
                         updated_at)
                    VALUES
                        (:udid,
                         :serial_number,
                         :imei,
                         :meid,
                         :device_name,
                         :model,
                         :os_version,
                         :build_version,
                         :id_student,
                         :id_ec,
                         :topic,
                         :push_token,
                         :push_magic,
                         :unlock_token,
                         :cert_subject_dn,
                         :cert_serial,
                         TRUE,
                         :now,
                         :now,
                         :now,
                         :now,
                         :now)
                    ON CONFLICT (udid)
                    DO UPDATE
                       SET serial_number        = COALESCE(EXCLUDED.serial_number,   numbux.mdm_ios_device.serial_number),
                           imei                 = COALESCE(EXCLUDED.imei,            numbux.mdm_ios_device.imei),
                           meid                 = COALESCE(EXCLUDED.meid,            numbux.mdm_ios_device.meid),
                           device_name          = COALESCE(EXCLUDED.device_name,     numbux.mdm_ios_device.device_name),
                           model                = COALESCE(EXCLUDED.model,           numbux.mdm_ios_device.model),
                           os_version           = COALESCE(EXCLUDED.os_version,      numbux.mdm_ios_device.os_version),
                           build_version        = COALESCE(EXCLUDED.build_version,   numbux.mdm_ios_device.build_version),
                           id_student           = COALESCE(EXCLUDED.id_student,      numbux.mdm_ios_device.id_student),
                           id_ec                = COALESCE(EXCLUDED.id_ec,           numbux.mdm_ios_device.id_ec),
                           topic                = COALESCE(EXCLUDED.topic,           numbux.mdm_ios_device.topic),
                           push_token           = COALESCE(EXCLUDED.push_token,      numbux.mdm_ios_device.push_token),
                           push_magic           = COALESCE(EXCLUDED.push_magic,      numbux.mdm_ios_device.push_magic),
                           unlock_token         = COALESCE(EXCLUDED.unlock_token,    numbux.mdm_ios_device.unlock_token),
                           cert_subject_dn      = COALESCE(EXCLUDED.cert_subject_dn, numbux.mdm_ios_device.cert_subject_dn),
                           cert_serial          = COALESCE(EXCLUDED.cert_serial,     numbux.mdm_ios_device.cert_serial),
                           is_enrolled          = TRUE,
                           last_checkin_at      = :now,
                           last_token_update_at = :now,
                           last_seen_at         = :now,
                           updated_at           = :now
                    RETURNING id_mdm_ios_device
                """), {
                    "udid": udid,
                    "serial_number": serial_number,
                    "imei": imei,
                    "meid": meid,
                    "device_name": device_name,
                    "model": model,
                    "os_version": os_version,
                    "build_version": build_version,
                    "id_student": id_student,
                    "id_ec": id_ec,
                    "topic": topic,
                    "push_token": token_bytes,
                    "push_magic": push_magic,
                    "unlock_token": unlock_bytes,
                    "cert_subject_dn": client_subject,
                    "cert_serial": client_serial,
                    "now": now_utc,
                }).mappings().first()

                if row:
                    id_mdm_ios_device = row["id_mdm_ios_device"]

            else:
                # Other MessageTypes: CheckOut, etc.
                row = conn.execute(text("""
                    SELECT id_mdm_ios_device
                      FROM numbux.mdm_ios_device
                     WHERE udid = :udid
                     LIMIT 1
                """), {"udid": udid}).mappings().first()
                if row:
                    id_mdm_ios_device = row["id_mdm_ios_device"]

                if msg_type == "CheckOut":
                    conn.execute(text("""
                        UPDATE numbux.mdm_ios_device
                           SET is_enrolled     = FALSE,
                               unenrolled_at   = :now,
                               last_checkin_at = :now,
                               last_seen_at    = :now,
                               updated_at      = :now
                         WHERE udid = :udid
                    """), {"udid": udid, "now": now_utc})
                else:
                    # Any other check-in → just bump last_seen/checkin
                    conn.execute(text("""
                        UPDATE numbux.mdm_ios_device
                           SET last_checkin_at = :now,
                               last_seen_at    = :now,
                               updated_at      = :now
                         WHERE udid = :udid
                    """), {"udid": udid, "now": now_utc})

            # Finally: log the raw plist
            conn.execute(text("""
                INSERT INTO numbux.mdm_ios_checkin_log
                    (id_mdm_ios_device, message_type, raw_plist)
                VALUES
                    (:id_dev, :msg_type, :raw_plist)
            """), {
                "id_dev": id_mdm_ios_device,
                "msg_type": msg_type,
                "raw_plist": raw_plist_str,
            })

    except Exception as e:
        # Helpful during bring-up; you can remove once stable.
        print("[MDM][CHECKIN][ERROR]", e.__class__.__name__, str(e))
        raise HTTPException(status_code=500, detail="MDM check-in failed")

    # Apple is happy with an empty 200 OK.
    return Response(content=b"", media_type="application/xml")


@mdm_plist_router.head("/mdm/checkin")
async def mdm_checkin_head():
    """
    Some clients (including Apple during enrollment / verification) may issue
    HEAD requests to the CheckInURL. We return 200 OK with no body.
    """
    return Response(content=b"", media_type="application/xml")



@mdm_plist_router.api_route("/mdm/command", methods=["POST", "PUT"])
async def mdm_command(
    request: Request,
    client_cert = Depends(require_mdm_client_cert),
):
    """
    Apple MDM command channel endpoint.

    - Status = "Idle":
        -> pop next PENDING command for this UDID and return a Command plist
    - Status = "Acknowledged" or "Error":
        -> update mdm_ios_command with result and error details
    """
    raw = await request.body()
    payload = _parse_plist_body(raw)

    status   = payload.get("Status")        # "Idle", "Acknowledged", "Error", ...
    udid     = payload.get("UDID")
    cmd_uuid = payload.get("CommandUUID")

    print("[MDM][CMD] Status=", status, "UDID=", udid, "CommandUUID=", cmd_uuid)

    if not udid:
        # Without UDID we can't map to a device – just return empty 200
        return Response(content=b"", media_type="application/xml")

    now_utc = _now_utc()

    with engine.begin() as conn:
        # --- 1) Find device row ---
        dev_row = conn.execute(text("""
            SELECT id_mdm_ios_device
              FROM numbux.mdm_ios_device
             WHERE udid = :udid
             LIMIT 1
        """), {"udid": udid}).mappings().first()

        device_id = dev_row["id_mdm_ios_device"] if dev_row else None

        if device_id:
            conn.execute(text("""
                UPDATE numbux.mdm_ios_device
                   SET last_seen_at   = :now,
                       last_checkin_at = :now,
                       updated_at      = :now
                 WHERE id_mdm_ios_device = :id_dev
            """), {"now": now_utc, "id_dev": device_id})

        # --- 2) Status = Idle → send next PENDING command ---
        if status == "Idle":
            if not device_id:
                return Response(content=b"", media_type="application/xml")

            cmd = conn.execute(text("""
                SELECT id_mdm_ios_command,
                       command_uuid,
                       request_type,
                       payload_plist
                  FROM numbux.mdm_ios_command
                 WHERE id_mdm_ios_device = :id_dev
                   AND status = 'PENDING'
                 ORDER BY queued_at ASC, id_mdm_ios_command ASC
                 LIMIT 1
            """), {"id_dev": device_id}).mappings().first()

            if not cmd:
                # No pending commands
                return Response(content=b"", media_type="application/xml")

            # Mark as SENT
            conn.execute(text("""
                UPDATE numbux.mdm_ios_command
                   SET status  = 'SENT',
                       sent_at = :now
                 WHERE id_mdm_ios_command = :cid
            """), {"now": now_utc, "cid": cmd["id_mdm_ios_command"]})

            # Build the Command plist
            import base64 as _b64

            try:
                cmd_payload = json.loads(cmd["payload_plist"])
            except Exception:
                cmd_payload = {"RequestType": cmd["request_type"]}

            # 🔥 Special handling for InstallProfile:
            # Payload in DB is base64 STRING, but Apple wants raw bytes (<data>...</data>)
            if cmd_payload.get("RequestType") == "InstallProfile":
                p_b64 = cmd_payload.get("Payload")
                if isinstance(p_b64, str):
                    cmd_payload["Payload"] = _b64.b64decode(p_b64)

            out_plist = {
                "CommandUUID": str(cmd["command_uuid"]),
                "Command": cmd_payload,
            }
            body = plistlib.dumps(out_plist)

            return Response(
                content=body,
                media_type="application/x-apple-aspen-mdm",
            )

        # --- 3) Status = Acknowledged / Error / NotNow ---
        if status in {"Acknowledged", "Error"} and device_id and cmd_uuid:
            # Store full iOS response as JSON text
            try:
                result_json = json.dumps(payload)
            except TypeError:
                result_json = str(payload)

            error_code = None
            error_chain_json = None

            if status == "Error":
                chain = payload.get("ErrorChain")
                if chain is not None:
                    try:
                        error_chain_json = json.dumps(chain)
                        if isinstance(chain, list) and chain:
                            first = chain[0]
                            if isinstance(first, dict):
                                error_code = str(
                                    first.get("ErrorCode")
                                    or first.get("ErrorDomain")
                                    or ""
                                )
                    except Exception:
                        error_chain_json = None

            conn.execute(text("""
                UPDATE numbux.mdm_ios_command
                   SET status          = :new_status,
                       acknowledged_at = :now,
                       result_plist    = :result_plist,
                       error_code      = :error_code,
                       error_chain     = :error_chain
                 WHERE id_mdm_ios_device = :id_dev
                   AND command_uuid       = :cmd_uuid
            """), {
                "new_status": "ACKNOWLEDGED" if status == "Acknowledged" else "ERROR",
                "now": now_utc,
                "result_plist": result_json,
                "error_code": error_code,
                "error_chain": error_chain_json,
                "id_dev": device_id,
                "cmd_uuid": str(cmd_uuid),
            })

        elif status == "NotNow" and device_id and cmd_uuid:
            # 🔁 Requeue + log what iOS sent
            try:
                result_json = json.dumps(payload)
            except TypeError:
                result_json = str(payload)

            conn.execute(text("""
                UPDATE numbux.mdm_ios_command
                   SET status       = 'PENDING',
                       result_plist = :result_plist
                 WHERE id_mdm_ios_device = :id_dev
                   AND command_uuid       = :cmd_uuid
            """), {
                "result_plist": result_json,
                "id_dev": device_id,
                "cmd_uuid": str(cmd_uuid),
            })

        # Any other status → just 200 OK, empty body
        return Response(content=b"", media_type="application/xml")


# Mount Apple MDM plist endpoints (no /api prefix, no JWT)
app.include_router(mdm_plist_router)


def load_profile_base64(path: str) -> str:
    """
    Reads a .mobileconfig profile from disk and returns base64 string
    suitable for the InstallProfile 'Payload' field.
    """
    data = Path(path).read_bytes()
    return base64.b64encode(data).decode("ascii")


def build_app_lock_profile_bytes(bundle_id: str) -> bytes:
    """
    Build a minimal com.apple.app.lock profile for the given bundle_id.
    Returns raw .mobileconfig bytes (XML plist) suitable for InstallProfile.
    """
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.numbux.applock.profile",  # used for RemoveProfile
        "PayloadUUID": "11111111-1111-1111-1111-111111111111",
        "PayloadDisplayName": "Numbux – Single App Mode",
        "PayloadOrganization": APPLE_MDM_ORG,
        "PayloadContent": [
            {
                "PayloadType": "com.apple.app.lock",
                "PayloadVersion": 1,
                "PayloadIdentifier": "com.numbux.applock.payload",
                "PayloadUUID": "22222222-2222-2222-2222-222222222222",
                "PayloadDisplayName": "App Lock",
                "App": {
                    "Identifier": bundle_id,
                },
            }
        ],
    }
    return plistlib.dumps(profile)

class SingleAppModeRequest(BaseModel):
    device_id: int
    bundle_id: str = "com.apple.mobilesafari"  # default: Safari
    enable: bool = True  # True = lock, False = unlock


@app.post("/api/ios/single-app-mode")
def api_single_app_mode(body: SingleAppModeRequest):
    """
    Enable or disable Single App Mode (App Lock) for a given iOS MDM device.

    - enable = True  -> queue a single InstallProfile (dedup old RemoveProfile)
    - enable = False -> queue a single RemoveProfile (dedup old InstallProfile)

    The actual execution may be delayed until the device is unlocked;
    NotNow responses are re-queued by /mdm/command.
    """
    device_id = body.device_id
    desired_enable = body.enable
    bundle_id = body.bundle_id

    with engine.begin() as conn:
        # 1) Ensure device exists
        dev = conn.execute(text("""
            SELECT id_mdm_ios_device
              FROM numbux.mdm_ios_device
             WHERE id_mdm_ios_device = :id
        """), {"id": device_id}).mappings().first()
        if not dev:
            raise HTTPException(status_code=404, detail="MDM device not found")

        # 2) Cancel opposite-type PENDING commands so we don't fight ourselves
        if desired_enable:
            # We want to LOCK → cancel old PENDING RemoveProfile
            conn.execute(text("""
                UPDATE numbux.mdm_ios_command
                   SET status = 'ACKNOWLEDGED'
                 WHERE id_mdm_ios_device = :dev_id
                   AND request_type = 'RemoveProfile'
                   AND status = 'PENDING'
            """), {"dev_id": device_id})
        else:
            # We want to UNLOCK → cancel old PENDING InstallProfile
            conn.execute(text("""
                UPDATE numbux.mdm_ios_command
                   SET status = 'ACKNOWLEDGED'
                 WHERE id_mdm_ios_device = :dev_id
                   AND request_type = 'InstallProfile'
                   AND status = 'PENDING'
            """), {"dev_id": device_id})

        # 3) If there is already a PENDING command of the right type, reuse it
        pending_same = conn.execute(text("""
            SELECT id_mdm_ios_command, command_uuid
              FROM numbux.mdm_ios_command
             WHERE id_mdm_ios_device = :dev_id
               AND request_type = :rtype
               AND status = 'PENDING'
             ORDER BY queued_at ASC, id_mdm_ios_command ASC
             LIMIT 1
        """), {
            "dev_id": device_id,
            "rtype": "InstallProfile" if desired_enable else "RemoveProfile",
        }).mappings().first()

        if pending_same:
            # Idempotent: we already have the right kind of command queued
            return {
                "status": "queued",
                "command_uuid": str(pending_same["command_uuid"]),
                "request_type": "InstallProfile" if desired_enable else "RemoveProfile",
                "device_id": device_id,
                "note": "reused existing pending command",
            }

        # 4) No PENDING of desired type → create a new one
        cmd_uuid = str(uuid4())

        if desired_enable:
            # Build app lock profile for the chosen bundle_id
            profile_bytes = build_app_lock_profile_bytes(bundle_id)
            profile_b64 = base64.b64encode(profile_bytes).decode("ascii")

            payload = {
                "RequestType": "InstallProfile",
                "Payload": profile_b64,
            }
            request_type = "InstallProfile"
        else:
            # Remove the App Lock profile we installed above
            payload = {
                "RequestType": "RemoveProfile",
                "Identifier": "com.numbux.applock.profile",
            }
            request_type = "RemoveProfile"

        payload_json = json.dumps(payload)

        conn.execute(text("""
            INSERT INTO numbux.mdm_ios_command
                (id_mdm_ios_device,
                 command_uuid,
                 request_type,
                 payload_plist,
                 status,
                 queued_at)
            VALUES
                (:dev_id,
                 :cmd_uuid,
                 :rtype,
                 :payload_plist,
                 'PENDING',
                 NOW())
        """), {
            "dev_id": device_id,
            "cmd_uuid": cmd_uuid,
            "rtype": request_type,
            "payload_plist": payload_json,
        })

    # After queueing, trigger APNs push immediately
    push_ok = True
    try:
        send_mdm_push_for_device(device_id)
    except Exception as e:
        push_ok = False
        print("[MDM][PUSH][ERROR]", e)

    return {
        "status": "queued",
        "command_uuid": cmd_uuid,
        "request_type": request_type,
        "device_id": device_id,
        "note": "new command queued",
        "push_triggered": push_ok,
    }



# === FCM (server → device) ===
FCM_PROJECT_ID = must_get("FCM_PROJECT_ID")
GOOGLE_APPLICATION_CREDENTIALS = must_get("GOOGLE_APPLICATION_CREDENTIALS")

_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
_fcm_creds = None  # lazy init

def _fcm_access_token() -> str | None:
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request as GAuthRequest

    global _fcm_creds
    try:
        if _fcm_creds is None:
            _fcm_creds = service_account.Credentials.from_service_account_file(
                GOOGLE_APPLICATION_CREDENTIALS, scopes=_SCOPES
            )
        if not _fcm_creds.valid:
            _fcm_creds.refresh(GAuthRequest())
        return _fcm_creds.token
    except Exception as e:
        print(f"[FCM] credentials error: {e}")
        return None

def send_fcm(
    token: str | None = None,
    data: dict | None = None,
    *,
    topic: str | None = None,
    collapse_key: str | None = None,
    ttl_seconds: int = 300,                 # 0s -> deliver now or drop (no wait)
) -> tuple[bool, str]:
    """
    Send a data-only FCM message using HTTP v1.
    - Use either `token` OR `topic` (one must be provided).
    - data: dict[str, str] (will be converted to string values)
    - Sets Android priority=HIGH and APNs priority=10 for wake behavior.
    """
    access = _fcm_access_token()
    if not access:
        msg = "[FCM] skip send: no access token"
        print(msg)
        return (False, msg)

    url = f"https://fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send"

    # FCM requires data values to be strings
    data = {k: str(v) for k, v in (data or {}).items()}

    message: dict = {
        "data": data,
        "android": {
            "priority": "HIGH",
            # collapse_key only if you pass it
            **({"collapse_key": collapse_key} if collapse_key else {}),
            "ttl": f"{ttl_seconds}s",
        },
        # For iOS clients (if any): make it a high-priority background data msg
        "apns": {
            "headers": {
                "apns-priority": "10",          # high
                # "apns-push-type": "background"  # uncomment if you need background on iOS
            },
            "payload": {
                "aps": {
                    "content-available": 1
                }
            }
        }
    }

    if token:
        message["token"] = token
    elif topic:
        message["topic"] = topic
    else:
        return (False, "[FCM] need token or topic")

    body = {"message": message}
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json; UTF-8",
    }

    try:
        r = requests.post(url, headers=headers, data=json.dumps(body), timeout=10)
        if r.ok:
            return (True, "sent")
        msg = f"[FCM] send error {r.status_code}: {r.text[:300]}"
        print(msg)
        return (False, msg)
    except Exception as e:
        msg = f"[FCM] exception: {e.__class__.__name__}: {e}"
        print(msg)
        return (False, msg)

    
class TeacherClassroom(BaseModel):
    id_classroom: int
    status: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    students_count: int | None = None
    course: str | None = None
    group: str | None = None
    subject: str | None = None

# === Teacher -> create classroom ===
class ClassroomCreate(BaseModel):
    course: Optional[str] = None
    group: Optional[str] = Field(None, alias="group")  # "group" está entre comillas en SQL
    subject: Optional[str] = None
    status: Literal["active", "archived"] = "active"
    start_date: Optional[date] = None  # por defecto: hoy UTC

@app.post("/api/teacher/classrooms", response_model=TeacherClassroom)
def create_classroom(body: ClassroomCreate, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only controllers can create classrooms")

    # Fecha por defecto (UTC)
    start_d = body.start_date or _now_utc().date()

    with engine.begin() as conn:
        # Validar que el profesor tenga centro activo
        if user["role"] == "teacher":
            te = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.teacher_ec
                 WHERE id_teacher = :tid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"tid": user["user_id"]}).mappings().first()
            if not te:
                raise HTTPException(status_code=400, detail="Teacher has no active educational center")

        # 1) Crear la clase
        cid = conn.execute(text("""
            INSERT INTO numbux.classroom
                (status, start_date, end_date,
                 student_count, course, "group", subject,
                 allow_join_student, join_token, join_token_expires_at)
            VALUES
                (:status, :start_date, NULL,
                 0, :course, :group, :subject,
                 FALSE, NULL, NULL)
            RETURNING id_classroom
        """), {
            "status": body.status,
            "start_date": start_d,
            "course": body.course,
            "group": body.group,
            "subject": body.subject,
        }).scalar_one()

        # 2) Vincular al profesor creador
        if user["role"] == "teacher":
            conn.execute(text("""
                INSERT INTO numbux.teacher_classroom
                    (id_teacher, id_classroom, role)
                VALUES
                    (:tid, :cid, 'Teacher/Creator')
            """), {"tid": user["user_id"], "cid": cid})

        # 3) Devolver el registro creado
        row = conn.execute(text("""
            SELECT c.id_classroom,
                   c.status,
                   c.start_date::text AS start_date,
                   c.end_date::text   AS end_date,
                   COALESCE(c.student_count, 0) AS students_count,
                   c.course,
                   c."group" AS "group",
                   c.subject,
                   c.allow_join_student,
                   c.join_token_expires_at::text AS join_token_expires_at
            FROM numbux.classroom c
            WHERE c.id_classroom = :cid
        """), {"cid": cid}).mappings().first()

    return dict(row)


# === Update classroom: course, group, subject (partial) ===
class ClassroomUpdate(BaseModel):
    # Accept partial updates; None means "no change".
    course: Optional[str] = None
    group: Optional[str] = Field(None, alias="group")  # quoted in SQL
    subject: Optional[str] = None

@app.patch("/api/teacher/classrooms/{classroom_id}", response_model=TeacherClassroom)
def update_classroom(classroom_id: int, body: ClassroomUpdate, user=Depends(get_current_user)):
    # Only controllers can modify classrooms
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only controllers can modify classrooms")

    # Build dynamic SET clause only for provided fields
    set_clauses = []
    params = {"cid": classroom_id}

    # Helper to normalize empty strings to NULL (optional; keeps DB tidy)
    def _norm(v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        return v if v != "" else None

    if body.course is not None:
        set_clauses.append("course = :course")
        params["course"] = _norm(body.course)

    if body.group is not None:
        # "group" is reserved; keep it quoted in SQL
        set_clauses.append("\"group\" = :grp")
        params["grp"] = _norm(body.group)

    if body.subject is not None:
        set_clauses.append("subject = :subject")
        params["subject"] = _norm(body.subject)

    if not set_clauses:
        raise HTTPException(status_code=400, detail="No fields to update")

    with engine.begin() as conn:
        # If caller is a teacher, ensure the classroom belongs to them
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(status_code=404, detail="Classroom not found for this teacher")

        # Execute the update
        upd_sql = f"""
            UPDATE numbux.classroom
               SET {', '.join(set_clauses)},
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_classroom = :cid
        """
        res = conn.execute(text(upd_sql), params)
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Classroom not found")

        # Return the updated record (align with TeacherClassroom DTO)
        row = conn.execute(text("""
            SELECT c.id_classroom,
                   c.status,
                   c.start_date::text AS start_date,
                   c.end_date::text   AS end_date,
                   COALESCE(c.student_count, 0) AS students_count,
                   c.course,
                   c."group" AS "group",
                   c.subject
            FROM numbux.classroom c
            WHERE c.id_classroom = :cid
        """), {"cid": classroom_id}).mappings().first()

    return dict(row)

@app.delete("/api/teacher/classrooms/{classroom_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_classroom(classroom_id: int, user=Depends(get_current_user)):
    # Only controllers can delete classrooms
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only controllers can delete classrooms")

    with engine.begin() as conn:
        # For teachers, verify ownership first
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(status_code=404, detail="Classroom not found for this teacher")

        # Delete parent row; ON DELETE CASCADE will remove dependents
        res = conn.execute(text("""
            DELETE FROM numbux.classroom
             WHERE id_classroom = :cid
        """), {"cid": classroom_id})

        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Classroom not found")

    # 204 => no body
    return


SQL_TEACHER_CLASSROOM = text("""
    SELECT c.id_classroom,
           c.status,
           c.start_date::text AS start_date,
           c.end_date::text   AS end_date,
           COALESCE(c.student_count, 0) AS students_count,  -- alias to match DTO
           c.course,
           c."group" AS "group",                            -- keep quotes only if column is named "group"
           c.subject,
           c.allow_join_student,                            -- ✅ new column
           c.join_token_expires_at::text AS join_token_expires_at  -- ✅ new column
    FROM numbux.teacher_classroom tc                        -- singular table name
    JOIN numbux.classroom c ON c.id_classroom = tc.id_classroom
    WHERE tc.id_teacher = :id_teacher
    ORDER BY c.id_classroom DESC
""")

SQL_ADMIN_CENTER_CLASSROOMS = text("""
    SELECT DISTINCT
           c.id_classroom,
           c.status,
           c.start_date::text AS start_date,
           c.end_date::text   AS end_date,
           COALESCE(c.student_count, 0) AS students_count,
           c.course,
           c."group" AS "group",
           c.subject,
           c.allow_join_student,
           c.join_token_expires_at::text AS join_token_expires_at
      FROM numbux.classroom c
      JOIN numbux.teacher_classroom tc
        ON tc.id_classroom = c.id_classroom
      JOIN numbux.teacher_ec te
        ON te.id_teacher = tc.id_teacher
       AND (te.status ILIKE 'active' OR te.status IS NULL)
     WHERE te.id_ec = :id_ec
  ORDER BY c.id_classroom DESC
""")


# === Live websocket for teacher updates (place AFTER SQL_TEACHER_CLASSROOM) ===
@app.websocket("/api/teacher/live")
async def teacher_live(ws: WebSocket):
    await ws.accept()

    # --- Authenticate the websocket like /me ---
    # Try: Authorization: Bearer <access_token>  OR  ?token=<access_token>
    try:
        token = None
        auth = ws.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split()[1]
        if not token:
            token = ws.query_params.get("token")
        if not token:
            await ws.close(code=4401)  # unauthorized
            return

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "access":
            await ws.close(code=4401)
            return
        if payload.get("role") != "teacher":
            await ws.close(code=4403)  # forbidden
            return

        teacher_id = int(payload["sub"])

        # --- Determine which classrooms this teacher owns ---
        with engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT c.id_classroom
                  FROM numbux.teacher_classroom tc
                  JOIN numbux.classroom c ON c.id_classroom = tc.id_classroom
                 WHERE tc.id_teacher = :tid
            """), {"tid": teacher_id}).fetchall()
        classroom_ids = [r[0] for r in rows]

        # Subscribe this socket to each classroom
        for cid in classroom_ids:
            classroom_subs.setdefault(cid, set()).add(ws)

        # Optional: send a hello
        await ws.send_text(json.dumps({
            "type": "hello",
            "teacher_id": teacher_id,
            "classrooms": classroom_ids,
            "ts": _now_utc().isoformat()
        }))

        # Keep alive; you can listen for "ping" and reply "pong"
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")

    except WebSocketDisconnect:
        pass
    except Exception as e:
        # Any error → close gracefully
        try:
            await ws.send_text(json.dumps({"type": "error", "message": str(e)}))
        except Exception:
            pass
    finally:
        # Unsubscribe on exit
        for cid, sockets in list(classroom_subs.items()):
            sockets.discard(ws)


@app.post("/api/teacher/classrooms/{classroom_id}/join/open", response_model=JoinOpenResponse)
def open_class_join(classroom_id: int, body: JoinOpenRequest, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(403, "Only controllers can open join")

    expires_at = _now_utc() + timedelta(minutes=body.expires_in_minutes)
    token = _gen_join_token()

    with engine.begin() as conn:
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1 FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(404, "Classroom not found for this teacher")

        # rotate token every time you open
        conn.execute(text("""
            UPDATE numbux.classroom
               SET allow_join_student = TRUE,
                   join_token = :tok,
                   join_token_expires_at = :exp
             WHERE id_classroom = :cid
        """), {"tok": token, "exp": expires_at, "cid": classroom_id})

        row = conn.execute(text("""
            SELECT course, "group", subject
              FROM numbux.classroom
             WHERE id_classroom = :cid
        """), {"cid": classroom_id}).mappings().first()

    join_url = f"https://api.numbux.com/join?token={token}" #human-/QR-friendly
    return {
        "classroom_id": classroom_id,
        "allow_join_student": True,
        "join_token": token,
        "join_url": join_url,
        "join_token_expires_at": expires_at,
    }


@app.post("/api/teacher/classrooms/{classroom_id}/join/close", response_model=JoinCloseResponse)
def close_class_join(classroom_id: int, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(403, "Only controllers can close join")

    with engine.begin() as conn:
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1 FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(404, "Classroom not found for this teacher")

        conn.execute(text("""
            UPDATE numbux.classroom
               SET allow_join_student = FALSE,
                   join_token = NULL,
                   join_token_expires_at = NULL
             WHERE id_classroom = :cid
        """), {"cid": classroom_id})

    return {"classroom_id": classroom_id, "allow_join_student": False}

@app.post("/api/student/join", response_model=StudentJoinResponse)
def student_join(body: StudentJoinRequest, user = Depends(get_current_user)):
    if not user or user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Only students can join")

    token = (body.token or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Missing token")

    try:
        with engine.begin() as conn:
            cls = conn.execute(text("""
                SELECT
                    c.id_classroom,
                    c.allow_join_student,
                    c.join_token_expires_at
                FROM numbux.classroom c
                WHERE c.join_token = :tok
                LIMIT 1
            """), {"tok": token}).mappings().first()

            if not cls:
                raise HTTPException(status_code=404, detail="Invalid token")

            if not bool(cls["allow_join_student"]):
                raise HTTPException(status_code=403, detail="Class is not open for joining")

            exp_at = cls["join_token_expires_at"]
            if exp_at is not None:
                now_ = _now_utc()
                # handle naive vs aware
                if getattr(exp_at, "tzinfo", None) is None:
                    if exp_at < now_.replace(tzinfo=None):
                        raise HTTPException(status_code=410, detail="Join link expired")
                else:
                    if exp_at < now_:
                        raise HTTPException(status_code=410, detail="Join link expired")

            classroom_id = int(cls["id_classroom"])
            student_id   = int(user["user_id"])

            exists = conn.execute(text("""
                SELECT 1
                  FROM numbux.student_classroom
                 WHERE id_classroom = :cid AND id_student = :sid
                 LIMIT 1
            """), {"cid": classroom_id, "sid": student_id}).first()

            if exists:
                return StudentJoinResponse(ok=True, classroom_id=classroom_id, status="already_enrolled")

            try:
                conn.execute(text("""
                    INSERT INTO numbux.student_classroom
                        (id_classroom, id_student, updated_at)
                    VALUES
                        (:cid, :sid, (now() AT TIME ZONE 'utc'))
                """), {"cid": classroom_id, "sid": student_id})

            except IntegrityError:
                # race → treat as already enrolled
                return StudentJoinResponse(ok=True, classroom_id=classroom_id, status="already_enrolled")

        # (optional) broadcast, wrapped so it never 500s the join
        try:
            broadcast_to_classrooms([classroom_id], {
                "type": "student_joined",
                "student_id": student_id,
                "ts": _now_utc().isoformat()
            })
        except Exception:
            pass

        return StudentJoinResponse(ok=True, classroom_id=classroom_id, status="enrolled")

    except HTTPException:
        raise
    except Exception as e:
        # final safety net: turn unknown errors into a 400 with context during dev
        # swap to 500 in prod if you prefer
        raise HTTPException(status_code=500, detail=f"Join failed: {e.__class__.__name__}")


@app.get("/api/join/resolve", response_model=JoinResolveResponse)
def join_resolve(token: str):
    token = (token or "").strip()
    if not token:
        raise HTTPException(400, "Missing token")

    try:
        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT
                    c.id_classroom,
                    c.allow_join_student,
                    c.join_token_expires_at,
                    c.course,
                    c."group" AS grp,
                    c.subject,
                    ec.commercial_name AS center_name
                FROM numbux.classroom c
                LEFT JOIN numbux.teacher_classroom tc
                       ON tc.id_classroom = c.id_classroom
                LEFT JOIN numbux.teacher_ec te
                       ON te.id_teacher = tc.id_teacher
                      AND (te.status ILIKE 'active' OR te.status IS NULL)
                LEFT JOIN numbux.educational_center ec
                       ON ec.id_ec = te.id_ec
                WHERE c.join_token = :tok
                ORDER BY te.start_date DESC NULLS LAST
                LIMIT 1
            """), {"tok": token}).mappings().first()
    except Exception as e:
        import logging; logging.exception("JOIN_RESOLVE DB error")
        raise HTTPException(status_code=500, detail=f"resolve failed: {e.__class__.__name__}: {e}")

    if not row:
        raise HTTPException(404, "Invalid token")

    return {
        "classroom_id": int(row["id_classroom"]),
        "course": row.get("course"),
        "group": row.get("grp"),
        "subject": row.get("subject"),
        "center_name": row.get("center_name"),
        "allow_join_student": bool(row["allow_join_student"]),
        "join_token_expires_at": row.get("join_token_expires_at"),
    }


@app.get("/api/teacher/classrooms", response_model=list[TeacherClassroom])
def my_teacher_classrooms(user=Depends(get_current_user)):
    if user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can list their classrooms")

    with engine.connect() as conn:
        try:
            rows = conn.execute(SQL_TEACHER_CLASSROOM, {"id_teacher": user["user_id"]}).mappings().all()
        except ProgrammingError as e:
            # Log the error or return an empty list / proper HTTP error
            print(f"Database error: {e}")
            raise HTTPException(status_code=500, detail="Database query failed")

    # Pydantic will serialize date fields automatically
    return [dict(r) for r in rows]


@app.get("/api/admin/classrooms", response_model=list[TeacherClassroom])
def admin_center_classrooms(
    id_ec: Optional[int] = Query(None, description="Educational center ID (required for admin_numbux)"),
    user=Depends(get_current_user)
):
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can list center classrooms")

    with engine.connect() as conn:
        if user["role"] == "admin":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()
            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")
            admin_ec_id = int(row["id_ec"])

            if id_ec is not None and int(id_ec) != admin_ec_id:
                raise HTTPException(status_code=403, detail="Cannot query another educational center")
            id_ec = admin_ec_id

        elif user["role"] == "admin_numbux":
            if id_ec is None:
                raise HTTPException(status_code=400, detail="id_ec is required for platform admins")

        try:
            rows = conn.execute(SQL_ADMIN_CENTER_CLASSROOMS, {"id_ec": int(id_ec)}).mappings().all()
        except ProgrammingError:
            raise HTTPException(status_code=500, detail="Database query failed")

    return [dict(r) for r in rows]


# === Admin EC -> create a 6-digit sign-out PIN for a student (valid 10 minutes) ===
class SignoutPinResponse(BaseModel):
    student_id: int
    pin: str
    expires_at: datetime

@app.post("/api/admin/students/{student_id}/signout-pin", response_model=SignoutPinResponse)
def create_signout_pin(student_id: int, user=Depends(get_current_user)):
    # Only admin_ec can mint sign-out PINs
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create sign-out PINs")

    expires_at = _now_utc() + timedelta(minutes=10)
    pin = f"{secrets.randbelow(1_000_000):06d}"  # zero-padded 6-digit

    with engine.begin() as conn:
        # 1) Admin's active educational center
        admin_ec_row = conn.execute(text("""
            SELECT id_ec
              FROM numbux.admin_ec
             WHERE id_admin = :aid
               AND (status ILIKE 'active' OR status IS NULL)
             ORDER BY start_date DESC NULLS LAST
             LIMIT 1
        """), {"aid": user["user_id"]}).mappings().first()
        if not admin_ec_row:
            raise HTTPException(status_code=400, detail="Admin has no active educational center")

        id_ec = int(admin_ec_row["id_ec"])

        # 2) Student must belong to this center (active)
        stu_ok = conn.execute(text("""
            SELECT 1
              FROM numbux.student_ec
             WHERE id_student = :sid
               AND id_ec = :id_ec
               AND (status ILIKE 'active' OR status IS NULL)
             LIMIT 1
        """), {"sid": student_id, "id_ec": id_ec}).first()
        if not stu_ok:
            raise HTTPException(status_code=404, detail="Student not found in your educational center")

        # 3) Store PIN + expiry on student
        res = conn.execute(text("""
            UPDATE numbux.student
               SET pin_signout = :pin,
                   pin_signout_expires_at = :exp,
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_student = :sid
        """), {"pin": pin, "exp": expires_at, "sid": student_id})

        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Student not found")

    return SignoutPinResponse(student_id=student_id, pin=pin, expires_at=expires_at)



# === Teacher -> list students in a classroom ===
from typing import List

class StudentInClass(BaseModel):
    id_student: int
    full_name: str
    code: str
    is_locked: bool | None = None
    want_lock: str | None = None
    # NEW fields to prefill the edit dialog
    first_name: str | None = None
    first_last_name: str | None = None
    second_last_name: str | None = None

@app.get("/api/teacher/classrooms/{classroom_id}/students", response_model=List[StudentInClass])
def list_students_in_classroom(classroom_id: int, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(403, "Only controllers can list students")

    with engine.connect() as conn:
        # If caller is a teacher, ensure the classroom belongs to them
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(404, "Classroom not found for this teacher")

        rows = conn.execute(text("""
            SELECT
                s.id_student,
                CONCAT_WS(
                    ', ',
                    NULLIF(CONCAT_WS(' ',
                        NULLIF(s.first_last_name, ''),
                        NULLIF(s.second_last_name, '')
                    ), ''),
                    NULLIF(s.first_name, '')
                ) AS full_name,
                s.id_student::text AS code,
                s.is_locked,        -- GLOBAL
                s.want_lock,        -- GLOBAL
                COALESCE(s.first_name, '') AS first_name,
                COALESCE(s.first_last_name, '') AS first_last_name,
                COALESCE(s.second_last_name, '') AS second_last_name
            FROM numbux.student_classroom sc
            JOIN numbux.student s ON s.id_student = sc.id_student
            WHERE sc.id_classroom = :cid
            ORDER BY
                COALESCE(s.first_last_name, ''),
                COALESCE(s.second_last_name, ''),
                COALESCE(s.first_name, '')
        """), {"cid": classroom_id}).mappings().all()

    return [dict(r) for r in rows]



# === Student -> list their classrooms ===
class StudentClassroomOut(BaseModel):
    id_classroom: int
    course: str | None = None
    group: str | None = None
    subject: str | None = None
    teacher_name: str | None = None
    students_count: int | None = None

@app.get("/api/student/classrooms", response_model=list[StudentClassroomOut])
def student_my_classrooms(user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(status_code=403, detail="Only students can list their classrooms")

    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT
                c.id_classroom,
                c.course,
                c."group" AS "group",                       -- ⚠️ quoted if the column is literally named "group"
                c.subject,
                COALESCE(c.student_count, 0) AS students_count,
                (t.first_name || ' ' || t.last_name) AS teacher_name
            FROM numbux.student_classroom sc
            JOIN numbux.classroom c
              ON c.id_classroom = sc.id_classroom
            LEFT JOIN numbux.teacher_classroom tc
              ON tc.id_classroom = c.id_classroom
            LEFT JOIN numbux.teacher t
              ON t.id_teacher = tc.id_teacher
            WHERE sc.id_student = :sid
            ORDER BY c.id_classroom DESC
        """), {"sid": user["user_id"]}).mappings().all()

    return [dict(r) for r in rows]


# === Student -> verify sign-out PIN (one-time, clears on success) ===
class PinVerifyRequest(BaseModel):
    pin: str

class PinVerifyResponse(BaseModel):
    ok: bool

@app.post("/api/student/pin/verify", response_model=PinVerifyResponse)
def verify_signout_pin(body: PinVerifyRequest, user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(status_code=403, detail="Only students can verify PINs")

    pin = (body.pin or "").strip()
    if not (len(pin) == 6 and pin.isdigit()):
        raise HTTPException(status_code=400, detail="PIN must be 6 digits")

    now_utc = _now_utc()

    # Atomic check+clear to prevent reuse/races
    with engine.begin() as conn:
        res = conn.execute(text("""
            UPDATE numbux.student
               SET pin_signout = NULL,
                   pin_signout_expires_at = NULL,
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_student = :sid
               AND pin_signout = :pin
               AND pin_signout_expires_at IS NOT NULL
               AND pin_signout_expires_at >= :now
        """), {"sid": user["user_id"], "pin": pin, "now": now_utc})

        if res.rowcount == 1:
            return PinVerifyResponse(ok=True)

    # Generic error to avoid leaking details
    raise HTTPException(status_code=401, detail="Invalid or expired PIN")



@app.get("/me")
def me(user=Depends(get_current_user)):
    return user

@app.post("/refresh", response_model=RefreshResponse)
def refresh(body: RefreshRequest):
    """Accepts a refresh token, returns a new access token (+ optional rotated refresh)."""
    try:
        payload = jwt.decode(body.refresh_token, REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        # Optional: confirm the user still exists/is active (query by payload["sub"]).
        claims = {"sub": payload["sub"], "email": payload["email"], "role": payload["role"]}

        new_access = create_access_token(claims)
        new_refresh = create_refresh_token(claims) if ROTATE_REFRESH else None
        return RefreshResponse(access_token=new_access, refresh_token=new_refresh)

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    

# === Admin logout (stateless; client must delete tokens) ===
class LogoutRequest(BaseModel):
    # Optional: if the client sends its refresh token, we verify it matches this admin.
    refresh_token: Optional[str] = None

class LogoutResponse(BaseModel):
    ok: bool

@app.post("/api/admin/logout", response_model=LogoutResponse)
def admin_logout(body: LogoutRequest = None, user=Depends(get_current_user)):
    # Only admin_ec can use this endpoint
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can log out via this endpoint")

    # If a refresh token is supplied, validate it belongs to the same admin and is a refresh token
    if body and body.refresh_token:
        try:
            payload = jwt.decode(body.refresh_token, REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get("typ") != "refresh":
                raise HTTPException(status_code=400, detail="Provided token is not a refresh token")
            if str(payload.get("sub")) != str(user["user_id"]) or payload.get("role") != "admin":
                # Don't leak details: just reject
                raise HTTPException(status_code=401, detail="Invalid refresh token for this admin")
        except JWTError:
            # Invalid/expired refresh token – treat as logout anyway but signal client side to clear tokens
            pass

    # Stateless logout: nothing to revoke server-side (JWTs are self-contained).
    # The frontend must delete both access_token and refresh_token.
    return LogoutResponse(ok=True)


# === Teacher logout (stateless; client must delete tokens) ===
@app.post("/api/teacher/logout", response_model=LogoutResponse)
def teacher_logout(body: LogoutRequest = None, user=Depends(get_current_user)):
    if user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can log out via this endpoint")

    # Optional: if a refresh token is supplied, validate it matches this teacher and is indeed a refresh token
    if body and body.refresh_token:
        try:
            payload = jwt.decode(body.refresh_token, REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get("typ") != "refresh":
                raise HTTPException(status_code=400, detail="Provided token is not a refresh token")
            if str(payload.get("sub")) != str(user["user_id"]) or payload.get("role") != "teacher":
                raise HTTPException(status_code=401, detail="Invalid refresh token for this teacher")
        except JWTError:
            # Invalid/expired refresh token – still tell client to clear tokens
            pass

    # Stateless logout: the frontend must delete access_token and refresh_token locally.
    return LogoutResponse(ok=True)

# === Student logout (stateless; client must delete tokens) ===
@app.post("/api/student/logout", response_model=LogoutResponse)
def student_logout(body: LogoutRequest = None, user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(status_code=403, detail="Only students can log out via this endpoint")

    # Optional: if a refresh token is supplied, validate it belongs to this student
    if body and body.refresh_token:
        try:
            payload = jwt.decode(body.refresh_token, REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get("typ") != "refresh":
                raise HTTPException(status_code=400, detail="Provided token is not a refresh token")
            if str(payload.get("sub")) != str(user["user_id"]) or payload.get("role") != "student":
                # Don't leak details: just reject
                raise HTTPException(status_code=401, detail="Invalid refresh token for this student")
        except JWTError:
            # Invalid/expired refresh token – still treat as logout but client must clear tokens
            pass

    # Stateless logout: nothing is revoked server-side. Frontend must delete access + refresh tokens.
    return LogoutResponse(ok=True)

# === MDM minimal endpoints (device token, desired state, ack) ===
mdm_router = APIRouter()

class PushTokenBody(BaseModel):
    device_id: str
    push_token: str

class ToggleReport(BaseModel):
    is_locked: bool
    source: str | None = None  # e.g. 'STUDENT_TOGGLE'

@mdm_router.post("/device/push-token")
def update_push_token(body: PushTokenBody, user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "Only students update device token")
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE numbux.student
               SET device_id = :dev, push_token = :tok
             WHERE id_student = :sid
        """), {"dev": body.device_id, "tok": body.push_token, "sid": user["user_id"]})
    return {"ok": True}

@mdm_router.get("/device/desired-state")
def desired_state(user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "Only students call this")

    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT want_lock, is_locked
              FROM numbux.student
             WHERE id_student = :sid
             LIMIT 1
        """), {"sid": user["user_id"]}).mappings().first()

    if not row:
        return {"want_lock": None, "is_locked": None}

    return {
        "want_lock": row["want_lock"],   # "LOCK" | "UNLOCK" | None
        "is_locked": row["is_locked"],   # bool | None
    }



class AckBody(BaseModel):
    result: str   # "LOCKED" | "UNLOCKED" | "ERROR"
    message: str | None = None

@mdm_router.post("/device/lock-ack")
def lock_ack(body: AckBody, user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "Only students ACK")

    if body.result not in {"LOCKED","UNLOCKED","ERROR"}:
        raise HTTPException(400, "result must be LOCKED | UNLOCKED | ERROR")

    is_locked = True if body.result == "LOCKED" else False if body.result == "UNLOCKED" else None

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE numbux.student
               SET want_lock = CASE WHEN :is_locked IS NOT NULL THEN NULL ELSE want_lock END,
                   is_locked = COALESCE(:is_locked, is_locked),
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_student = :sid
        """), {"is_locked": is_locked, "sid": user["user_id"]})

    if is_locked is not None:
        broadcast_student_toggle(student_id=user["user_id"], is_locked=is_locked)

    return {"ok": True}




@mdm_router.post("/device/toggle-report")
def device_toggle_report(body: ToggleReport, user=Depends(get_current_user)):
    if user["role"] != "student":
        raise HTTPException(403, "Only students report their toggle")

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE numbux.student
               SET is_locked = :locked,
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_student = :sid
        """), {"locked": body.is_locked, "sid": user["user_id"]})

    broadcast_student_toggle(student_id=user["user_id"], is_locked=body.is_locked)
    return {"ok": True}

# Mount JSON MDM endpoints under /api
app.include_router(mdm_router, prefix="/api")


# === Teacher -> order lock/unlock for an entire classroom ===
from typing import List

class OrderBody(BaseModel):
    action: str  # "LOCK" | "UNLOCK"


@app.post("/api/teacher/classrooms/{classroom_id}/order")
def teacher_order_class(classroom_id: int, body: OrderBody, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(403, "Only controllers can order lock/unlock")

    action = (body.action or "").upper()
    if action not in {"LOCK", "UNLOCK"}:
        raise HTTPException(400, "action must be LOCK or UNLOCK")

    now_iso = _now_utc().isoformat()

    with engine.begin() as conn:
        # Ensure the teacher owns the classroom (if role == teacher)
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(404, "Classroom not found for this teacher")

        # === Your block goes here (sets global student.want_lock for the class) ===
        conn.execute(text("""
            UPDATE numbux.student s
               SET want_lock = :w,
                   updated_at = (now() AT TIME ZONE 'utc')
              FROM numbux.student_classroom sc
             WHERE sc.id_classroom = :cid
               AND sc.id_student = s.id_student
        """), {"w": action, "cid": classroom_id})

        rows = conn.execute(text("""
            SELECT s.id_student, s.push_token
              FROM numbux.student s
              JOIN numbux.student_classroom sc
                ON sc.id_student = s.id_student
             WHERE sc.id_classroom = :cid
        """), {"cid": classroom_id}).mappings().all()

    # Fan out the FCM order to every device in the class
    notified = 0
    for r in rows:
        sid = r["id_student"]
        tok = r["push_token"]
        if not tok:
            continue
        ok, _ = send_fcm(
            token=tok,
            data={
                "type": "LOCK_ORDER",
                "action": action,
                "student_id": sid,
                "classroom_id": classroom_id,
                "ts": now_iso,
            },
            collapse_key="lock_order",
            ttl_seconds=300
        )
        if ok:
            notified += 1

    return {"ok": True, "classroom_id": classroom_id, "action": action, "notified": notified}


@app.post("/api/teacher/students/{student_id}/order")
def teacher_order_student_global(student_id: int, body: OrderBody, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(403, "Only controllers can order lock/unlock")

    action = (body.action or "").upper()
    if action not in {"LOCK", "UNLOCK"}:
        raise HTTPException(400, "action must be LOCK or UNLOCK")

    with engine.begin() as conn:
        # Seguridad: si es teacher, debe tener a este alumno en alguna de sus clases
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1
                  FROM numbux.student_classroom sc
                  JOIN numbux.teacher_classroom tc
                    ON tc.id_classroom = sc.id_classroom
                 WHERE tc.id_teacher = :tid
                   AND sc.id_student  = :sid
                 LIMIT 1
            """), {"tid": user["user_id"], "sid": student_id}).first()
            if not own:
                raise HTTPException(404, "Student not found in your classrooms")

        conn.execute(text("""
            UPDATE numbux.student
               SET want_lock = :w,
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_student = :sid
        """), {"w": action, "sid": student_id})

        tok = conn.execute(text("""
            SELECT push_token FROM numbux.student WHERE id_student = :sid
        """), {"sid": student_id}).scalar()

    if tok:
        send_fcm(
            token=tok,
            data={"type": "LOCK_ORDER", "action": action, "student_id": student_id},
            collapse_key="lock_order", ttl_seconds=300
        )

    return {"ok": True, "student_id": student_id, "action": action}

@app.post("/api/teacher/classrooms/{classroom_id}/students/{student_id}/order")
def teacher_order_student(classroom_id: int, student_id: int, body: OrderBody, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(403, "Only controllers can order lock/unlock")

    action = (body.action or "").upper()
    if action not in {"LOCK", "UNLOCK"}:
        raise HTTPException(400, "action must be LOCK or UNLOCK")

    now_iso = _now_utc().isoformat()

    with engine.begin() as conn:
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1 FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(404, "Classroom not found for this teacher")

        enrolled = conn.execute(text("""
            SELECT 1 FROM numbux.student_classroom
             WHERE id_classroom = :cid AND id_student = :sid
             LIMIT 1
        """), {"cid": classroom_id, "sid": student_id}).first()
        if not enrolled:
            raise HTTPException(404, "Student not in this classroom")

        conn.execute(text("""
            UPDATE numbux.student
            SET want_lock = :w,
                updated_at = (now() AT TIME ZONE 'utc')
            WHERE id_student = :sid
        """), {"w": action, "sid": student_id})

        tok = conn.execute(text("""
            SELECT push_token
              FROM numbux.student
             WHERE id_student = :sid
        """), {"sid": student_id}).scalar()

    if tok:
        send_fcm(
            token=tok,
            data={
                "type": "LOCK_ORDER",
                "action": action,
                "student_id": student_id,
                "classroom_id": classroom_id,
                "ts": now_iso,
            },
            collapse_key="lock_order",
            ttl_seconds=0
        )

    return {"ok": True, "student_id": student_id, "action": action}


# --- Remove a student from a classroom ---
@app.delete("/api/teacher/classrooms/{classroom_id}/students/{student_id}", status_code=204)
def remove_student_from_classroom(classroom_id: int, student_id: int, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only controllers can remove students")

    with engine.begin() as conn:
        # If teacher → ensure class ownership
        if user["role"] == "teacher":
            own = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_classroom
                 WHERE id_teacher = :tid AND id_classroom = :cid
                 LIMIT 1
            """), {"tid": user["user_id"], "cid": classroom_id}).first()
            if not own:
                raise HTTPException(status_code=404, detail="Classroom not found for this teacher")

        # Ensure the student is enrolled in this classroom
        enrolled = conn.execute(text("""
            SELECT 1
              FROM numbux.student_classroom
             WHERE id_classroom = :cid AND id_student = :sid
             LIMIT 1
        """), {"cid": classroom_id, "sid": student_id}).first()
        if not enrolled:
            raise HTTPException(status_code=404, detail="Student not in this classroom")

        # Remove enrollment
        res = conn.execute(text("""
            DELETE FROM numbux.student_classroom
             WHERE id_classroom = :cid AND id_student = :sid
        """), {"cid": classroom_id, "sid": student_id})

        # Recalculate student_count to keep it accurate
        conn.execute(text("""
            UPDATE numbux.classroom
               SET student_count = (
                       SELECT COUNT(*) FROM numbux.student_classroom
                        WHERE id_classroom = :cid
                   ),
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_classroom = :cid
        """), {"cid": classroom_id})

    # Optional: notify live sockets the student list changed
    try:
        broadcast_to_classrooms([classroom_id], {
            "type": "student_removed",
            "student_id": student_id,
            "classroom_id": classroom_id,
            "ts": _now_utc().isoformat()
        })
    except Exception:
        pass

    return


# === Teacher/Admin -> update a student's name fields (partial) ===
class StudentUpdate(BaseModel):
    # Accept partial updates; None => no change
    first_name: Optional[str] = None
    first_last_name: Optional[str] = None
    second_last_name: Optional[str] = None

class StudentUpdatedOut(BaseModel):
    id_student: int
    first_name: Optional[str] = None
    first_last_name: Optional[str] = None
    second_last_name: Optional[str] = None
    # optional helper for display, keep consistent with your list query
    full_name: Optional[str] = None

@app.patch("/api/teacher/students/{student_id}", response_model=StudentUpdatedOut)
def update_student_partial(student_id: int, body: StudentUpdate, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only controllers can modify students")

    set_clauses = []
    params = {"sid": student_id}

    def _norm(v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        return v if v != "" else None  # "" -> None

    # helper to add only when normalized value is present
    def _maybe_add(field: str, column: str, value: Optional[str]):
        norm = _norm(value)
        if value is None:
            return  # field not sent -> no change
        if norm is None:
            return  # blank string -> treat as no change (avoid NOT NULL issues)
        set_clauses.append(f"{column} = :{field}")
        params[field] = norm

    _maybe_add("first_name",       "first_name",       body.first_name)
    _maybe_add("first_last_name",  "first_last_name",  body.first_last_name)
    _maybe_add("second_last_name", "second_last_name", body.second_last_name)

    if not set_clauses:
        raise HTTPException(status_code=400, detail="No fields to update")

    try:
        with engine.begin() as conn:
            if user["role"] == "teacher":
                own = conn.execute(text("""
                    SELECT 1
                      FROM numbux.student_classroom sc
                      JOIN numbux.teacher_classroom tc
                        ON tc.id_classroom = sc.id_classroom
                     WHERE tc.id_teacher = :tid
                       AND sc.id_student  = :sid
                     LIMIT 1
                """), {"tid": user["user_id"], "sid": student_id}).first()
                if not own:
                    raise HTTPException(status_code=404, detail="Student not found in your classrooms")

            upd_sql = f"""
                UPDATE numbux.student
                   SET {', '.join(set_clauses)},
                       updated_at = (now() AT TIME ZONE 'utc')
                 WHERE id_student = :sid
            """
            res = conn.execute(text(upd_sql), params)
            if res.rowcount == 0:
                raise HTTPException(status_code=404, detail="Student not found")

            row = conn.execute(text("""
                SELECT
                    id_student,
                    COALESCE(first_name, '') AS first_name,
                    COALESCE(first_last_name, '') AS first_last_name,
                    COALESCE(second_last_name, '') AS second_last_name,
                    CONCAT_WS(
                        ', ',
                        NULLIF(CONCAT_WS(' ',
                            NULLIF(first_last_name, ''),
                            NULLIF(second_last_name, '')
                        ), ''),
                        NULLIF(first_name, '')
                    ) AS full_name
                FROM numbux.student
                WHERE id_student = :sid
            """), {"sid": student_id}).mappings().first()

        return dict(row)
    except IntegrityError as e:
        # Return a clean 400 instead of 500 if constraints fail
        raise HTTPException(status_code=400, detail=f"Invalid value: {str(e.orig)[:200]}")
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Database error")

# === Admin -> create a new student account ===
class AdminCreateStudent(BaseModel):
    first_name: str
    first_last_name: Optional[str] = None
    second_last_name: Optional[str] = None
    email: EmailStr
    password: str
    phone: Optional[str] = None
    # For admin_numbux; admin_ec will default to their own center
    id_ec: Optional[int] = None


class AdminStudentOut(BaseModel):
    id_student: int
    first_name: Optional[str] = None
    first_last_name: Optional[str] = None
    second_last_name: Optional[str] = None
    full_name: Optional[str] = None
    email: EmailStr
    id_ec: int

class AdminStudentWithStatusOut(AdminStudentOut):
    is_locked: Optional[bool] = None
    want_lock: Optional[str] = None
    code: Optional[str] = None

class CenterStudentCount(BaseModel):
    id_ec: int
    active_students: int

class CenterTeacherCount(BaseModel):
    id_ec: int
    active_teachers: int

class CenterActiveLicenses(BaseModel):
    id_ec: int
    total_active_licenses: int

class AdminTeacherOut(BaseModel):
    id_teacher: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    full_name: Optional[str] = None
    email: EmailStr
    id_ec: int

class AdminCreateTeacher(BaseModel):
    first_name: str
    last_name: Optional[str] = None
    email: EmailStr
    password: str
    phone: Optional[str] = None
    # For admin_numbux; admin_ec will default to their own center
    id_ec: Optional[int] = None

class AdminUpdateTeacher(BaseModel):
    # Accept partial updates; None => no change
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None



@app.get("/api/admin/center-students", response_model=list[AdminStudentWithStatusOut])
def admin_list_center_students(
    id_ec: Optional[int] = Query(None),
    user = Depends(get_current_user),
):
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can list students")

    with engine.begin() as conn:
        if user["role"] == "admin":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()
            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")
            resolved_id_ec = int(row["id_ec"])
        else:
            if id_ec is None:
                raise HTTPException(status_code=400, detail="id_ec is required for platform admins")
            resolved_id_ec = int(id_ec)

        rows = conn.execute(text("""
            SELECT
                s.id_student,
                s.email,
                COALESCE(s.first_name, '')       AS first_name,
                COALESCE(s.first_last_name, '')  AS first_last_name,
                COALESCE(s.second_last_name, '') AS second_last_name,
                :id_ec                           AS id_ec,
                CONCAT_WS(
                    ', ',
                    NULLIF(CONCAT_WS(' ',
                        NULLIF(s.first_last_name, ''),
                        NULLIF(s.second_last_name, '')
                    ), ''),
                    NULLIF(s.first_name, '')
                ) AS full_name
            FROM numbux.student s
            JOIN numbux.student_ec se
              ON se.id_student = s.id_student
             AND se.id_ec = :id_ec
             AND (se.status ILIKE 'active' OR se.status IS NULL)
            ORDER BY
                s.first_last_name NULLS LAST,
                s.second_last_name NULLS LAST,
                s.first_name NULLS LAST
        """), {"id_ec": resolved_id_ec}).mappings().all()

    # is_locked / want_lock / code can be None or default False, etc.
    return [
        AdminStudentWithStatusOut(
            id_student=row["id_student"],
            first_name=row["first_name"] or None,
            first_last_name=row["first_last_name"] or None,
            second_last_name=row["second_last_name"] or None,
            full_name=row["full_name"],
            email=row["email"],
            id_ec=row["id_ec"],
            is_locked=False,
            want_lock=None,
            code=None,
        )
        for row in rows
    ]

@app.get("/api/admin/center-students/count", response_model=CenterStudentCount)
def admin_center_student_count(
    id_ec: Optional[int] = Query(None),
    user = Depends(get_current_user),
):
    """
    Returns the number of *active* students in an educational center.

    - admin: counts for their own active center (ignores other id_ec).
    - admin_numbux: must pass id_ec explicitly.
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can see student counts")

    with engine.begin() as conn:
        # --- Resolve center depending on admin role ---
        if user["role"] == "admin":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND status ILIKE 'active'
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            resolved_id_ec = int(row["id_ec"])

        else:  # admin_numbux
            if id_ec is None:
                raise HTTPException(status_code=400, detail="id_ec is required for platform admins")
            resolved_id_ec = int(id_ec)

        # --- Count active students in that center ---
        row = conn.execute(text("""
            SELECT COUNT(DISTINCT se.id_student) AS cnt
              FROM numbux.student_ec se
             WHERE se.id_ec = :id_ec
               AND se.status ILIKE 'active'
               AND se.role = 'student'
        """), {"id_ec": resolved_id_ec}).mappings().first()

        count = int(row["cnt"]) if row and row["cnt"] is not None else 0

    return CenterStudentCount(id_ec=resolved_id_ec, active_students=count)


@app.get("/api/admin/center-teachers/count", response_model=CenterTeacherCount)
def admin_center_teacher_count(
    id_ec: Optional[int] = Query(None),
    user = Depends(get_current_user),
):
    """
    Returns the number of *active* teachers in an educational center.

    - admin: counts for their own active center (ignores other id_ec).
    - admin_numbux: must pass id_ec explicitly.
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can see teacher counts")

    with engine.begin() as conn:
        # --- Resolve center depending on admin role ---
        if user["role"] == "admin":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND status ILIKE 'active'
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            resolved_id_ec = int(row["id_ec"])

        else:  # admin_numbux
            if id_ec is None:
                raise HTTPException(status_code=400, detail="id_ec is required for platform admins")
            resolved_id_ec = int(id_ec)

        # --- Count active teachers in that center ---
        row = conn.execute(text("""
            SELECT COUNT(DISTINCT te.id_teacher) AS cnt
              FROM numbux.teacher_ec te
             WHERE te.id_ec = :id_ec
               AND te.status ILIKE 'active'
               AND te.role = 'teacher'
        """), {"id_ec": resolved_id_ec}).mappings().first()

        count = int(row["cnt"]) if row and row["cnt"] is not None else 0

    return CenterTeacherCount(id_ec=resolved_id_ec, active_teachers=count)

@app.get("/api/admin/center-licenses/active", response_model=CenterActiveLicenses)
def admin_center_total_active_licenses(
    id_ec: Optional[int] = Query(None),
    user = Depends(get_current_user),
):
    """
    Returns total active licenses for an educational center:
    - active teachers
    - active students
    - active admin users (role = 'admin')
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can access license counts")

    with engine.begin() as conn:

        # --- Resolve center based on role ---
        if user["role"] == "admin":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            resolved_id_ec = int(row["id_ec"])

        else:  # admin_numbux
            if id_ec is None:
                raise HTTPException(status_code=400, detail="id_ec is required for platform admins")
            resolved_id_ec = int(id_ec)

        # --- Count total active licenses ---
        row = conn.execute(text("""
            SELECT
                -- Active teachers
                (SELECT COUNT(*)
                   FROM numbux.teacher_ec
                  WHERE id_ec = :id_ec
                    AND status ILIKE 'active'
                    AND role = 'teacher')
                +
                -- Active students
                (SELECT COUNT(*)
                   FROM numbux.student_ec
                  WHERE id_ec = :id_ec
                    AND status ILIKE 'active'
                    AND role = 'student')
                +
                -- Active admin users
                (SELECT COUNT(*)
                   FROM numbux.admin_ec
                  WHERE id_ec = :id_ec
                    AND status ILIKE 'active'
                    AND role = 'admin')
                AS total_active_licenses
        """), {"id_ec": resolved_id_ec}).mappings().first()

        total = int(row["total_active_licenses"]) if row else 0

    return CenterActiveLicenses(
        id_ec=resolved_id_ec,
        total_active_licenses=total
    )

@app.get("/api/admin/center-teachers", response_model=list[AdminTeacherOut])
def admin_list_center_teachers(
    id_ec: Optional[int] = Query(None),
    user = Depends(get_current_user),
):
    """
    List teachers in an educational center.

    - admin: lists teachers for *their* active center (ignores other id_ec).
    - admin_numbux: must pass id_ec explicitly.
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can list teachers")

    with engine.begin() as conn:
        # Resolve center depending on admin role
        if user["role"] == "admin":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()
            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")
            resolved_id_ec = int(row["id_ec"])
        else:  # admin_numbux
            if id_ec is None:
                raise HTTPException(status_code=400, detail="id_ec is required for platform admins")
            resolved_id_ec = int(id_ec)

        # Fetch teachers linked to this center (active teacher_ec)
        rows = conn.execute(text("""
            SELECT
                t.id_teacher,
                t.email,
                COALESCE(t.first_name, '') AS first_name,
                COALESCE(t.last_name, '')  AS last_name,
                :id_ec                      AS id_ec,
                CONCAT_WS(
                    ', ',
                    NULLIF(t.last_name, ''),
                    NULLIF(t.first_name, '')
                ) AS full_name
            FROM numbux.teacher t
            JOIN numbux.teacher_ec te
              ON te.id_teacher = t.id_teacher
             AND te.id_ec      = :id_ec
             AND (te.status ILIKE 'active' OR te.status IS NULL)
            ORDER BY
                t.last_name  NULLS LAST,
                t.first_name NULLS LAST
        """), {"id_ec": resolved_id_ec}).mappings().all()

    return [
        AdminTeacherOut(
            id_teacher=row["id_teacher"],
            first_name=row["first_name"] or None,
            last_name=row["last_name"] or None,
            full_name=row["full_name"],
            email=row["email"],
            id_ec=row["id_ec"],
        )
        for row in rows
    ]

@app.post("/api/admin/teachers", response_model=AdminTeacherOut)
def admin_create_teacher(body: AdminCreateTeacher, user=Depends(get_current_user)):
    # Only admins can create teachers
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can create teachers")

    email_lower = body.email.lower()

    with engine.begin() as conn:
        # 1) Ensure email is not already used by any user type
        _ensure_email_not_exists(conn, email_lower)

        # 2) Resolve educational center depending on admin role
        if user["role"] == "admin":
            # Admin EC: must belong to exactly one active center
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            admin_ec_id = int(row["id_ec"])

            # If body.id_ec is present, enforce it matches
            if body.id_ec is not None and int(body.id_ec) != admin_ec_id:
                raise HTTPException(
                    status_code=403,
                    detail="Cannot create teachers in another educational center"
                )

            id_ec = admin_ec_id

        else:  # admin_numbux
            # Platform admin must explicitly choose the center
            if body.id_ec is None:
                raise HTTPException(
                    status_code=400,
                    detail="id_ec is required for platform admins"
                )
            id_ec = int(body.id_ec)

        # 3) Insert into numbux.teacher
        teacher_id = conn.execute(text("""
            INSERT INTO numbux.teacher
                (first_name, last_name, email, phone, password_hash)
            VALUES
                (:first_name, :last_name, :email, :phone, :password_hash)
            RETURNING id_teacher
        """), {
            "first_name": body.first_name,
            "last_name": body.last_name,
            "email": email_lower,
            "phone": body.phone,
            "password_hash": _hash_password(body.password),
        }).scalar_one()

        # 4) Link teacher to the center in numbux.teacher_ec
        conn.execute(text("""
            INSERT INTO numbux.teacher_ec
                (id_ec, id_teacher, academic_year, start_date, end_date,
                 status, license_code, role)
            VALUES
                (:id_ec, :id_teacher, :academic_year, :start_date, NULL,
                 'active', NULL, 'teacher')
        """), {
            "id_ec": id_ec,
            "id_teacher": teacher_id,
            "academic_year": None,
            "start_date": _today_utc_date(),
        })

        # 5) Read back a normalized view of the teacher
        row = conn.execute(text("""
            SELECT
                t.id_teacher,
                COALESCE(t.first_name, '') AS first_name,
                COALESCE(t.last_name, '')  AS last_name,
                t.email,
                :id_ec                     AS id_ec,
                CONCAT_WS(
                    ', ',
                    NULLIF(t.last_name, ''),
                    NULLIF(t.first_name, '')
                ) AS full_name
            FROM numbux.teacher t
            WHERE t.id_teacher = :tid
        """), {"tid": teacher_id, "id_ec": id_ec}).mappings().first()

    return AdminTeacherOut(**row)


@app.patch("/api/admin/teachers/{teacher_id}", response_model=AdminTeacherOut)
def admin_update_teacher(teacher_id: int, body: AdminUpdateTeacher, user=Depends(get_current_user)):
    """
    Edit a teacher's basic data (name, email, phone).

    - admin: can only edit teachers that belong to their active educational center.
    - admin_numbux: can edit any teacher (but teacher must be linked to some center).
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can edit teachers")

    # Helper to normalize strings; treat blank "" as "no change"
    def _norm(v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        return v if v != "" else None

    # helper to add only when normalized value is present
    def _maybe_add(field: str, column: str, value: Optional[str],
                   set_clauses: list[str], params: dict):
        if value is None:
            return  # field not sent -> no change
        norm = _norm(value)
        if norm is None:
            return  # blank string -> treat as no change
        set_clauses.append(f"{column} = :{field}")
        params[field] = norm

    with engine.begin() as conn:
        # --- Ensure teacher exists and get current email ---
        teacher_row = conn.execute(text("""
            SELECT email
              FROM numbux.teacher
             WHERE id_teacher = :tid
        """), {"tid": teacher_id}).mappings().first()

        if not teacher_row:
            raise HTTPException(status_code=404, detail="Teacher not found")

        current_email_lower = (teacher_row["email"] or "").lower()

        # --- Resolve educational center and enforce scope ---
        if user["role"] == "admin":
            admin_ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not admin_ec_row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            resolved_id_ec = int(admin_ec_row["id_ec"])

            # Teacher must belong (active) to this center
            teacher_ok = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_ec
                 WHERE id_teacher = :tid
                   AND id_ec      = :id_ec
                   AND (status ILIKE 'active' OR status IS NULL)
                 LIMIT 1
            """), {"tid": teacher_id, "id_ec": resolved_id_ec}).first()

            if not teacher_ok:
                raise HTTPException(
                    status_code=404,
                    detail="Teacher not found in your educational center"
                )
        else:
            # admin_numbux: find any active center for this teacher for the response
            ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.teacher_ec
                 WHERE id_teacher = :tid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"tid": teacher_id}).mappings().first()

            if not ec_row:
                raise HTTPException(
                    status_code=400,
                    detail="Teacher is not assigned to any educational center"
                )

            resolved_id_ec = int(ec_row["id_ec"])

        # --- Build dynamic UPDATE ---
        set_clauses: list[str] = []
        params: dict = {"tid": teacher_id}

        _maybe_add("first_name", "first_name", body.first_name, set_clauses, params)
        _maybe_add("last_name",  "last_name",  body.last_name,  set_clauses, params)
        _maybe_add("phone",      "phone",      body.phone,      set_clauses, params)

        # Email change (check uniqueness across all users)
        if body.email is not None:
            new_email_lower = body.email.lower().strip()
            if new_email_lower and new_email_lower != current_email_lower:
                _ensure_email_not_exists(conn, new_email_lower)
                set_clauses.append("email = :email")
                params["email"] = new_email_lower

        if not set_clauses:
            raise HTTPException(status_code=400, detail="No fields to update")

        upd_sql = f"""
            UPDATE numbux.teacher
               SET {', '.join(set_clauses)},
                   updated_at = (now() AT TIME ZONE 'utc')
             WHERE id_teacher = :tid
        """
        res = conn.execute(text(upd_sql), params)
        if res.rowcount == 0:
            # Very unlikely here (we already checked existence) but keep it consistent
            raise HTTPException(status_code=404, detail="Teacher not found")

        # --- Read back normalized view for response ---
        row = conn.execute(text("""
            SELECT
                t.id_teacher,
                COALESCE(t.first_name, '') AS first_name,
                COALESCE(t.last_name, '')  AS last_name,
                t.email,
                :id_ec                     AS id_ec,
                CONCAT_WS(
                    ', ',
                    NULLIF(t.last_name, ''),
                    NULLIF(t.first_name, '')
                ) AS full_name
            FROM numbux.teacher t
            WHERE t.id_teacher = :tid
        """), {"tid": teacher_id, "id_ec": resolved_id_ec}).mappings().first()

    return AdminTeacherOut(**row)


@app.delete("/api/admin/teachers/{teacher_id}", status_code=204)
def admin_delete_teacher(teacher_id: int, user=Depends(get_current_user)):
    """
    Delete a teacher account.

    - admin: can only delete teachers that belong to their active educational center.
    - admin_numbux: can delete any teacher.
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can delete teachers")

    with engine.begin() as conn:
        # --- Scope check for admin_ec ---
        if user["role"] == "admin":
            admin_ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not admin_ec_row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            id_ec = int(admin_ec_row["id_ec"])

            # Teacher must belong (active) to this center
            teacher_ok = conn.execute(text("""
                SELECT 1
                  FROM numbux.teacher_ec
                 WHERE id_teacher = :tid
                   AND id_ec      = :id_ec
                   AND (status ILIKE 'active' OR status IS NULL)
                 LIMIT 1
            """), {"tid": teacher_id, "id_ec": id_ec}).first()

            if not teacher_ok:
                raise HTTPException(
                    status_code=404,
                    detail="Teacher not found in your educational center"
                )

        # --- Try to delete the teacher row itself ---
        try:
            res = conn.execute(text("""
                DELETE FROM numbux.teacher
                 WHERE id_teacher = :tid
            """), {"tid": teacher_id})
        except IntegrityError:
            # Most likely FK references (e.g. classrooms, logs, etc.)
            raise HTTPException(
                status_code=409,
                detail="Cannot delete teacher: still referenced in other records"
            )

        if res.rowcount == 0:
            # For admin_numbux or race conditions
            raise HTTPException(status_code=404, detail="Teacher not found")

    # 204 → no body
    return


@app.post("/api/admin/students", response_model=AdminStudentOut)
def admin_create_student(body: AdminCreateStudent, user=Depends(get_current_user)):
    # Only admins can create students
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can create students")

    email_lower = body.email.lower()

    with engine.begin() as conn:
        # 1) Ensure email is not already used by any user type
        _ensure_email_not_exists(conn, email_lower)

        # 2) Resolve educational center depending on admin role
        if user["role"] == "admin":
            # Admin EC: must belong to exactly one active center
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()
            if not row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            admin_ec_id = int(row["id_ec"])

            # If body.id_ec is present, enforce it matches
            if body.id_ec is not None and int(body.id_ec) != admin_ec_id:
                raise HTTPException(
                    status_code=403,
                    detail="Cannot create students in another educational center"
                )

            id_ec = admin_ec_id

        else:  # admin_numbux
            # Platform admin must explicitly choose the center
            if body.id_ec is None:
                raise HTTPException(
                    status_code=400,
                    detail="id_ec is required for platform admins"
                )
            id_ec = int(body.id_ec)

        # 3) Insert into numbux.student
        student_id = conn.execute(text("""
            INSERT INTO numbux.student
                (first_name, first_last_name, second_last_name,
                 email, phone, password_hash,
                 device_id, push_token, platform)
            VALUES
                (:first_name, :first_last_name, :second_last_name,
                 :email, :phone, :password_hash,
                 NULL, NULL, NULL)
            RETURNING id_student
        """), {
            "first_name": body.first_name,
            "first_last_name": body.first_last_name,
            "second_last_name": body.second_last_name,
            "email": email_lower,
            "phone": body.phone,
            "password_hash": _hash_password(body.password),
        }).scalar_one()

        # 4) Link student to the center in numbux.student_ec
        conn.execute(text("""
            INSERT INTO numbux.student_ec
                (id_ec, id_student, academic_year, start_date, end_date,
                 status, license_code, role)
            VALUES
                (:id_ec, :id_student, :academic_year, :start_date, NULL,
                 'active', NULL, 'student')
        """), {
            "id_ec": id_ec,
            "id_student": student_id,
            "academic_year": None,
            "start_date": _today_utc_date(),
        })

        # 5) Read back a normalized view of the student
        row = conn.execute(text("""
            SELECT
                s.id_student,
                COALESCE(s.first_name, '')         AS first_name,
                COALESCE(s.first_last_name, '')    AS first_last_name,
                COALESCE(s.second_last_name, '')   AS second_last_name,
                s.email,
                :id_ec                              AS id_ec,
                CONCAT_WS(
                    ', ',
                    NULLIF(CONCAT_WS(' ',
                        NULLIF(s.first_last_name, ''),
                        NULLIF(s.second_last_name, '')
                    ), ''),
                    NULLIF(s.first_name, '')
                ) AS full_name
            FROM numbux.student s
            WHERE s.id_student = :sid
        """), {"sid": student_id, "id_ec": id_ec}).mappings().first()

    return AdminStudentOut(**row)

@app.delete("/api/admin/students/{student_id}", status_code=204)
def admin_delete_student(student_id: int, user=Depends(get_current_user)):
    """
    Delete a student account.

    - admin: can only delete students that belong to their active educational center.
    - admin_numbux: can delete any student.
    """
    if user["role"] not in {"admin", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can delete students")

    with engine.begin() as conn:
        # --- Scope check for admin_ec ---
        if user["role"] == "admin":
            admin_ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec
                 WHERE id_admin = :aid
                   AND (status ILIKE 'active' OR status IS NULL)
                 ORDER BY start_date DESC NULLS LAST
                 LIMIT 1
            """), {"aid": user["user_id"]}).mappings().first()

            if not admin_ec_row:
                raise HTTPException(status_code=400, detail="Admin has no active educational center")

            id_ec = int(admin_ec_row["id_ec"])

            # Student must belong (active) to this center
            stu_ok = conn.execute(text("""
                SELECT 1
                  FROM numbux.student_ec
                 WHERE id_student = :sid
                   AND id_ec = :id_ec
                   AND (status ILIKE 'active' OR status IS NULL)
                 LIMIT 1
            """), {"sid": student_id, "id_ec": id_ec}).first()

            if not stu_ok:
                raise HTTPException(
                    status_code=404,
                    detail="Student not found in your educational center"
                )

        # --- Try to delete the student row itself ---
        try:
            res = conn.execute(text("""
                DELETE FROM numbux.student
                 WHERE id_student = :sid
            """), {"sid": student_id})
        except IntegrityError:
            # Most likely FK references (e.g. not cascaded student_classroom, logs, etc.)
            raise HTTPException(
                status_code=409,
                detail="Cannot delete student: still referenced in other records"
            )

        if res.rowcount == 0:
            # For admin_numbux or race conditions
            raise HTTPException(status_code=404, detail="Student not found")

    # 204 → no body
    return

# ======= SignUp models =======
class BaseSignup(BaseModel):
    first_name: str
    last_name: str | None = None
    email: EmailStr
    password: str
    phone: str | None = None
    license_code: str
    # id_ec es opcional: si no viene, lo derivamos desde licenses
    id_ec: int | None = None

class StudentSignup(BaseSignup):
    platform: str | None = None  # 'Android' | 'iOS' | 'Web'
    device_id: str | None = None
    push_token: str | None = None
    second_last_name: str | None = None

class TeacherSignup(BaseSignup):
    pass

class AdminECSignup(BaseSignup):
    pass


# ======= SignUp helpers =======
LICENSE_CHECK_SQL = text("""
    SELECT id_ec, status, start_date, end_date, COALESCE(in_use, false) AS in_use
    FROM numbux.license
    WHERE license_code = :license_code
    LIMIT 1
""")

def _today_utc_date():
    return _now_utc().date()

def _is_license_active(row) -> bool:
    if not row:
        return False
    today = _today_utc_date()
    # status debe ser 'active' y hoy dentro del rango de fechas
    status_ok = (str(row["status"]).lower() == "active")
    start_ok = (row["start_date"] is None) or (row["start_date"] <= today)
    end_ok = (row["end_date"] is None) or (today <= row["end_date"])
    return status_ok and start_ok and end_ok

def _ensure_email_not_exists(conn, email_lower: str):
    existing = conn.execute(LOOKUP_SQL, {"email": email_lower}).mappings().first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

def _claim_license_and_get_center(conn, license_code: str, email: str, id_ec_opt: int | None) -> int:
    """
    Atomically mark license as in_use and return id_ec.
    If already in_use, or not active today, or wrong center, raise appropriate HTTPException.
    """
    today = _today_utc_date()

    base_sql = """
        UPDATE numbux.license
           SET in_use = TRUE,
               used_by_email = :email,
               used_at = (now() AT TIME ZONE 'utc')
         WHERE license_code = :code
           AND (in_use IS FALSE OR in_use IS NULL)
           AND status ILIKE 'active'
           AND (start_date IS NULL OR start_date <= :today)
           AND (end_date   IS NULL OR :today <= end_date)
    """
    params = {"code": license_code, "email": email, "today": today}

    if id_ec_opt is not None:
        base_sql += " AND id_ec = :id_ec"
        params["id_ec"] = int(id_ec_opt)

    base_sql += " RETURNING id_ec"

    claimed = conn.execute(text(base_sql), params).mappings().first()
    if claimed:
        return int(claimed["id_ec"])

    # If no row was updated, figure out why to return a precise error
    lic = conn.execute(LICENSE_CHECK_SQL, {"license_code": license_code}).mappings().first()
    if not lic:
        raise HTTPException(status_code=400, detail="Invalid license code")
    if not _is_license_active(lic):
        raise HTTPException(status_code=400, detail="License is not active for today")
    if lic.get("in_use"):
        raise HTTPException(status_code=409, detail="License already used")
    if id_ec_opt is not None and int(lic["id_ec"]) != int(id_ec_opt):
        raise HTTPException(status_code=400, detail="License code does not belong to the provided educational center")

    # Fallback
    raise HTTPException(status_code=400, detail="Unable to claim license")

MAX_PASSWORD_LENGTH = 50

def _hash_password(pw: str) -> str:
    # Optional: also enforce a minimum length here
    if len(pw) > MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        )
    return bcrypt.hash(pw)

def _update_user_password(conn, email_lower: str, role: str, new_hash: str):
    """
    Update password_hash for the user with the given email + role.
    Uses the same role labels as LOOKUP_SQL: admin_numbux, admin, teacher, student.
    """
    role = (role or "").lower()

    if role == "student":
        table = "numbux.student"
    elif role == "teacher":
        table = "numbux.teacher"
    elif role == "admin":
        table = "numbux.admin"
    elif role == "admin_numbux":
        table = "numbux.admin_numbux"
    else:
        raise HTTPException(status_code=400, detail="Unknown role for password reset")

    sql = text(f"""
        UPDATE {table}
           SET password_hash = :ph
         WHERE lower(email) = :email
    """)

    res = conn.execute(sql, {"ph": new_hash, "email": email_lower})
    if res.rowcount == 0:
        # Should not happen if token is legit, but just in case
        raise HTTPException(status_code=404, detail="User not found")

def _issue_tokens(user_id: int, email: str, role: str) -> TokenResponse:
    base_claims = {"sub": str(user_id), "email": email, "role": role}
    access  = create_access_token(base_claims)
    refresh = create_refresh_token(base_claims)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        role=role,
        user_id=user_id,
        email=email,
    )

def send_reset_email(to_email: str, reset_url: str):
    """
    Envía un email de restablecimiento de contraseña con el enlace reset_url.
    Usa la cuenta info@numbux.com (SMTP_SSL, puerto 465).
    """
    msg = EmailMessage()
    msg["Subject"] = "Numbux – Restablece tu contraseña"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    text_body = (
        "Has solicitado restablecer tu contraseña de NumbuX.\n"
        "Si tú no has solicitado este cambio, puedes ignorar este correo.\n\n"
        f"Para continuar, haz clic en el siguiente enlace:\n{reset_url}\n\n"
        "Si tú no has solicitado este cambio, puedes ignorar este correo."
    )


    html_body = f"""
    <html>
        <body>
            <p>
            Has solicitado restablecer tu contraseña de <strong>NumbuX</strong>.
            </p>

            <p style="font-size: 0.9em; color: #666;">
            Si tú no has solicitado este cambio, puedes ignorar este correo.
            </p>

            <p>
            Para continuar, haz clic en el siguiente enlace:<br>
            <a href="{reset_url}">{reset_url}</a>
            </p>

            <p style="font-size: 0.9em; color: #666;">
            Si tú no has solicitado este cambio, puedes ignorar este correo.
            </p>
        </body>
    </html>
    """


    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    # Tu servidor: SSL/TLS en puerto 465 -> SMTP_SSL
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)


# ======= /signup/student =======
@app.post("/signup/student", response_model=TokenResponse)
def signup_student(body: StudentSignup):
    email_lower = body.email.lower()
    with engine.begin() as conn:  # transaction
        _ensure_email_not_exists(conn, email_lower)
        id_ec = _claim_license_and_get_center(conn, body.license_code, email_lower, body.id_ec)

        insert_student = text("""
            INSERT INTO numbux.student
                (first_name, first_last_name, second_last_name, email, phone, password_hash, device_id, push_token, platform)
            VALUES
                (:first_name, :first_last_name, :second_last_name, :email, :phone, :password_hash, :device_id, :push_token, :platform)
            RETURNING id_student
        """)


        student_id = conn.execute(
            insert_student,
            {
                "first_name": body.first_name,
                "first_last_name": body.last_name,                 # maps to first_last_name
                "second_last_name": body.second_last_name,         # NEW
                "email": email_lower,
                "phone": body.phone,                               # keep nullable
                "password_hash": _hash_password(body.password),
                "device_id": body.device_id,
                "push_token": body.push_token,
                "platform": body.platform,
            }
        ).scalar_one()



        insert_students_ec = text("""
            INSERT INTO numbux.student_ec (id_ec, id_student, academic_year, start_date, end_date, status, license_code, role)
            VALUES (:id_ec, :id_student, :academic_year, :start_date, NULL, 'active', :license_code, 'student')
        """)
        conn.execute(
            insert_students_ec,
            {
                "id_ec": id_ec,
                "id_student": student_id,
                "academic_year": None,
                "start_date": _today_utc_date(),
                "license_code": body.license_code,
            }
        )

    return _issue_tokens(student_id, email_lower, "student")



# ======= /signup/teacher =======
@app.post("/signup/teacher", response_model=TokenResponse)
def signup_teacher(body: TeacherSignup):
    email_lower = body.email.lower()
    with engine.begin() as conn:
        _ensure_email_not_exists(conn, email_lower)
        id_ec = _claim_license_and_get_center(conn, body.license_code, email_lower, body.id_ec)

        insert_teacher = text("""
            INSERT INTO numbux.teacher (first_name, last_name, email, phone, password_hash)
            VALUES (:first_name, :last_name, :email, :phone, :password_hash)
            RETURNING id_teacher
        """)
        teacher_id = conn.execute(
            insert_teacher,
            {
                "first_name": body.first_name,
                "last_name": body.last_name,
                "email": email_lower,
                "phone": body.phone,
                "password_hash": _hash_password(body.password),
            }
        ).scalar_one()

        insert_teachers_ec = text("""
            INSERT INTO numbux.teacher_ec (id_ec, id_teacher, academic_year, start_date, end_date, status, license_code, role)
            VALUES (:id_ec, :id_teacher, :academic_year, :start_date, NULL, 'active', :license_code, 'teacher')
        """)
        conn.execute(
            insert_teachers_ec,
            {
                "id_ec": id_ec,
                "id_teacher": teacher_id,
                "academic_year": None,
                "start_date": _today_utc_date(),
                "license_code": body.license_code,
            }
        )

    return _issue_tokens(teacher_id, email_lower, "teacher")


# ======= /signup/admin-ec (administrador del centro) =======
@app.post("/signup/admin-ec", response_model=TokenResponse)
def signup_admin_ec(body: AdminECSignup):
    email_lower = body.email.lower()
    with engine.begin() as conn:
        _ensure_email_not_exists(conn, email_lower)
        id_ec = _claim_license_and_get_center(conn, body.license_code, email_lower, body.id_ec)

        insert_admin_ec = text("""
            INSERT INTO numbux.admin (first_name, last_name, email, phone, password_hash)
            VALUES (:first_name, :last_name, :email, :phone, :password_hash)
            RETURNING id_admin
        """)
        admin_ec_id = conn.execute(
            insert_admin_ec,
            {
                "first_name": body.first_name,
                "last_name": body.last_name,
                "email": email_lower,
                "phone": body.phone,
                "password_hash": _hash_password(body.password),
            }
        ).scalar_one()

        insert_admin_ec_ec = text("""
            INSERT INTO numbux.admin_ec (id_ec, id_admin, academic_year, start_date, end_date, status, license_code, role)
            VALUES (:id_ec, :id_admin, :academic_year, :start_date, NULL, 'active', :license_code, 'admin')
        """)
        conn.execute(
            insert_admin_ec_ec,
            {
                "id_ec": id_ec,
                "id_admin": admin_ec_id,
                "academic_year": None,
                "start_date": _today_utc_date(),
                "license_code": body.license_code,
            }
        )

    return _issue_tokens(admin_ec_id, email_lower, "admin")


# === Send Email with link to Reset Password ===
class PasswordResetRequest(BaseModel):
    email: EmailStr

@app.post("/password/reset-link")
def create_reset_link(
    body: PasswordResetRequest,
    background_tasks: BackgroundTasks,
):
    """
    Dado un email, si existe un usuario:
    - genera un token de reset
    - envía un email con el enlace de reseteo

    Siempre devuelve una respuesta genérica para evitar user-enumeration.
    """
    email_lower = body.email.lower()

    with engine.connect() as conn:
        row = conn.execute(LOOKUP_SQL, {"email": email_lower}).mappings().first()

    # Respuesta genérica (tanto si el usuario existe como si no)
    generic_response = {
        "ok": True,
        "message": "Si ese email existe, recibirás un enlace para restablecer la contraseña en unos minutos.",
    }

    # Si no existe ningún usuario con ese email → no hacemos nada más
    if not row:
        return generic_response

    # Usuario encontrado → generamos el token y la URL
    token = create_reset_token(email_lower, row["role"], row["user_id"])
    reset_url = f"https://api.numbux.com/reset-password?token={token}"

    # Enviar el email en segundo plano (sin bloquear la respuesta)
    background_tasks.add_task(send_reset_email, email_lower, reset_url)

    return generic_response

RESET_PASSWORD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Restablecer Contraseña</title>

  <style>
    :root {
      --accent: #ff6300;
      --bg: #000;
      --text: #fff;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      font-family: Arial, sans-serif;
    }

    body {
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 40px;
    }

    html, body {
        height: 100%;
        overflow-y: auto;
    }

    .container {
      width: 100%;
      max-width: 900px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 60px 80px;
      border-radius: 25px;
      text-align: center;
      box-shadow: 0 0 60px rgba(0, 0, 0, 0.8);
    }

    .logo-img {
      width: 400px;
      height: auto;
      display: block;
      margin: 0 auto 30px;
    }

    .title {
      font-size: 34px;
      margin-bottom: 12px;
      font-weight: 700;
    }

    .subtitle {
      font-size: 18px;
      color: #ccc;
      margin-bottom: 20px;
    }

    form {
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 30px;
    }

    .field {
      position: relative;
    }

    .field input {
      width: 100%;
      padding: 22px 18px;
      font-size: 20px;
      background: transparent;
      border: 3px solid #555;
      border-radius: 12px;
      color: #fff;
      outline: none;
      transition: 0.2s;
    }

    .field input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(255, 99, 0, 0.5);
    }

    .field label {
      position: absolute;
      left: 18px;
      top: 50%;
      transform: translateY(-50%);
      color: #aaa;
      background: var(--bg);
      padding: 0 8px;
      transition: 0.2s;
      pointer-events: none;
      font-size: 18px;
    }

    .field input:focus + label,
    .field input:not(:placeholder-shown) + label {
      top: 0;
      font-size: 15px;
      color: var(--accent);
      transform: translateY(-50%);
    }

    .hint {
      font-size: 16px;
      color: #bbb;
      text-align: left;
      margin-top: -15px;
      margin-bottom: 5px;
    }

    button {
      width: 100%;
      padding: 22px;
      background: var(--accent);
      border: none;
      border-radius: 40px;
      font-size: 22px;
      font-weight: bold;
      color: #000;
      cursor: pointer;
      transition: 0.2s;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-top: 10px;
    }

    button:hover {
      opacity: 0.9;
      transform: translateY(-3px);
      box-shadow: 0 10px 25px rgba(255, 99, 0, 0.4);
    }

    #passwordError {
        color: #ff4d4d;
        font-size: 14px;
        margin-top: -10px;
        text-align: left;
    }

    .server-message {
      margin: 10px 0 20px;
      text-align: left;
      font-size: 15px;
      padding: 10px 12px;
      border-radius: 10px;
    }

    .server-error {
      background: rgba(255, 77, 77, 0.1);
      border: 1px solid #ff4d4d;
      color: #ffb3b3;
    }

    .server-success {
      background: rgba(34, 197, 94, 0.12);
      border: 1px solid #22c55e;
      color: #bbf7d0;
    }

    @media (min-width: 1200px) and (min-height: 800px) {
      body {
          display: flex;
          align-items: center;
          justify-content: center;
      }
    }

    @media (min-width: 1024px) {
      #passwordError {
          font-size: 20px;
          line-height: 1.4;
      }
    }

    @media (max-width: 1366px) {
      body {
          display: block;
          padding: 3vh 3vw;
      }

      .container {
          margin: 1vh auto;
          padding: 30px 20px;
          max-width: 520px;
      }

      .logo-img {
          max-width: 200px;
          margin-bottom: 15px;
      }

      .title {
          font-size: 28px;
      }

      .subtitle {
          font-size: 16px;
          margin-bottom: 20px;
      }

      .field input {
          font-size: 18px;
          padding: 14px;
      }

      button {
          font-size: 20px;
          padding: 16px;
      }
    }

    @media (max-width: 600px) {
      body {
          display: block;
          padding: 2vh 4vw;
          align-items: flex-start;
      }

      .container {
          max-width: 95%;
          margin: 3vh auto;
          padding: 35px 25px;
      }

      .logo-img {
          max-width: 220px;
          margin-bottom: 20px;
      }

      .title {
          font-size: 24px;
      }

      .subtitle {
          font-size: 14px;
      }

      .field input {
          font-size: 16px;
          padding: 16px;
      }

      button {
          font-size: 18px;
          padding: 16px;
      }
    }
  </style>
</head>

<body>
  <div class="container">
    <img 
        class="logo-img"
        src="data:image/png;base64,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"
        alt="Numbux Logo"
    />

    <div class="title">Reset your password</div>
    <div class="subtitle">Escribe tu contraseña dos veces para confirmar</div>

    <!-- Server-side message placeholder -->
    {{MESSAGE_BLOCK}}

    <form id="resetForm" method="post" action="/reset-password">
        <!-- Hidden reset token -->
        <input type="hidden" name="token" value="{{TOKEN}}" />

        <div class="field">
          <input type="password" id="password" name="password" required placeholder=" " />
          <label>Nueva Contraseña</label>
        </div>

        <div class="field">
          <input type="password" id="confirmPassword" name="confirm_password" required placeholder=" " />
          <label>Confirmación de la Contraseña</label>
        </div>

        <div class="hint">Longitud mínima 8 caracteres. Debe incluir mayúscula, minúscula, número y caracter especial.</div>

        <div id="passwordError" style="display:none; color:#ff8080; text-align:left; margin-top:5px;">
          Passwords do not match.
        </div>

        <button type="submit">Actualizar Contraseña</button>
    </form>
  </div>

  <script>
    const form = document.getElementById('resetForm');
    const password = document.getElementById('password');
    const confirmPassword = document.getElementById('confirmPassword');
    const errorText = document.getElementById('passwordError');

    function validatePasswordStrength(pwd) {
        const regex = /^(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*(),.?":{}|<>_\\-]).{8,}$/;
        return regex.test(pwd);
    }

    function checkPasswords() {
        let message = "";

        if (!validatePasswordStrength(password.value)) {
          message = "Contraseña debe contener una mayúscula, minúscula, número y caracter especial.";
        } else if (password.value !== confirmPassword.value) {
          message = "Las contraseñas no coinciden.";
        }

        if (message) {
          errorText.style.display = "block";
          errorText.textContent = message;
          return false;
        } else {
          errorText.style.display = "none";
          return true;
        }
    }

    password.addEventListener("input", checkPasswords);
    confirmPassword.addEventListener("input", checkPasswords);

    form.addEventListener("submit", function (e) {
        if (!checkPasswords()) {
          e.preventDefault();
        }
    });
  </script>
</body>
</html>
"""

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(token: str):
    """
    Displays the HTML page with a form to set a new password.
    Link format: /reset-password?token=<RESET_TOKEN>
    """
    message_block = ""

    try:
        decode_reset_token(token)
    except HTTPException as exc:
        message_block = f'<div class="server-message server-error">{exc.detail}</div>'

    html = (
        RESET_PASSWORD_HTML
        .replace("{{TOKEN}}", token)
        .replace("{{MESSAGE_BLOCK}}", message_block)
    )
    return HTMLResponse(content=html)


@app.post("/reset-password", response_class=HTMLResponse)
def reset_password_submit(
    token: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    try:
        payload = decode_reset_token(token)
    except HTTPException as exc:
        message_block = f'<div class="server-message server-error">{exc.detail}</div>'
        html = (
            RESET_PASSWORD_HTML
            .replace("{{TOKEN}}", token)
            .replace("{{MESSAGE_BLOCK}}", message_block)
        )
        return HTMLResponse(content=html, status_code=400)

    if not PASSWORD_REGEX.match(password):
        message_block = (
            '<div class="server-message server-error">'
            'Contraseña debe contener una mayúscula, minúscula, número y caracter especial.'
            '</div>'
        )
        html = (
            RESET_PASSWORD_HTML
            .replace("{{TOKEN}}", token)
            .replace("{{MESSAGE_BLOCK}}", message_block)
        )
        return HTMLResponse(content=html, status_code=400)

    if password != confirm_password:
        message_block = (
            '<div class="server-message server-error">'
            'Las contraseñas no coinciden.'
            '</div>'
        )
        html = (
            RESET_PASSWORD_HTML
            .replace("{{TOKEN}}", token)
            .replace("{{MESSAGE_BLOCK}}", message_block)
        )
        return HTMLResponse(content=html, status_code=400)

    email_lower = (payload["email"] or "").lower()
    role = payload["role"]

    new_hash = _hash_password(password)

    with engine.begin() as conn:
        _update_user_password(conn, email_lower, role, new_hash)

    message_block = (
        '<div class="server-message server-success">'
        'Tu contraseña ha sido actualizada correctamente. '
        'Ya puedes cerrar esta página e iniciar sesión con tu nueva contraseña.'
        '</div>'
    )

    html = (
        RESET_PASSWORD_HTML
        .replace("{{TOKEN}}", "")  # invalidate form token
        .replace("{{MESSAGE_BLOCK}}", message_block)
    )
    return HTMLResponse(content=html)

