# /srv/numbux-api/app/main.py
import os
import sys
from datetime import datetime, timedelta, timezone, date
from fastapi import FastAPI, HTTPException, Depends, Header, APIRouter, WebSocket, WebSocketDisconnect, status
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
    role: str            # 'student' | 'teacher' | 'admin_ec'
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
    if role not in {"student", "teacher", "admin_ec"}:
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

LOOKUP_SQL = text("""
    WITH candidates AS (
        SELECT id::bigint AS user_id, email, password_hash, 'admin_numbux'::text AS role
        FROM numbux.admin_numbux WHERE lower(email) = :email
        UNION ALL
        SELECT id_admin_ec::bigint AS user_id, email, password_hash, 'admin_ec'::text AS role
        FROM numbux.admin_ec WHERE lower(email) = :email
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can list center classrooms")

    with engine.connect() as conn:
        if user["role"] == "admin_ec":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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
    if user["role"] != "admin_ec":
        raise HTTPException(status_code=403, detail="Only admin_ec can create sign-out PINs")

    expires_at = _now_utc() + timedelta(minutes=10)
    pin = f"{secrets.randbelow(1_000_000):06d}"  # zero-padded 6-digit

    with engine.begin() as conn:
        # 1) Admin's active educational center
        admin_ec_row = conn.execute(text("""
            SELECT id_ec
              FROM numbux.admin_ec_ec
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] != "admin_ec":
        raise HTTPException(status_code=403, detail="Only admin_ec can log out via this endpoint")

    # If a refresh token is supplied, validate it belongs to the same admin and is a refresh token
    if body and body.refresh_token:
        try:
            payload = jwt.decode(body.refresh_token, REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get("typ") != "refresh":
                raise HTTPException(status_code=400, detail="Provided token is not a refresh token")
            if str(payload.get("sub")) != str(user["user_id"]) or payload.get("role") != "admin_ec":
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




# Mount under /api
app.include_router(mdm_router, prefix="/api")


# === Teacher -> order lock/unlock for an entire classroom ===
from typing import List

class OrderBody(BaseModel):
    action: str  # "LOCK" | "UNLOCK"


@app.post("/api/teacher/classrooms/{classroom_id}/order")
def teacher_order_class(classroom_id: int, body: OrderBody, user=Depends(get_current_user)):
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"teacher", "admin_ec", "admin_numbux"}:
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
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can list students")

    with engine.begin() as conn:
        if user["role"] == "admin_ec":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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

@app.get("/api/admin/center-teachers", response_model=list[AdminTeacherOut])
def admin_list_center_teachers(
    id_ec: Optional[int] = Query(None),
    user = Depends(get_current_user),
):
    """
    List teachers in an educational center.

    - admin_ec: lists teachers for *their* active center (ignores other id_ec).
    - admin_numbux: must pass id_ec explicitly.
    """
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can list teachers")

    with engine.begin() as conn:
        # Resolve center depending on admin role
        if user["role"] == "admin_ec":
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can create teachers")

    email_lower = body.email.lower()

    with engine.begin() as conn:
        # 1) Ensure email is not already used by any user type
        _ensure_email_not_exists(conn, email_lower)

        # 2) Resolve educational center depending on admin role
        if user["role"] == "admin_ec":
            # Admin EC: must belong to exactly one active center
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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

    - admin_ec: can only edit teachers that belong to their active educational center.
    - admin_numbux: can edit any teacher (but teacher must be linked to some center).
    """
    if user["role"] not in {"admin_ec", "admin_numbux"}:
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
        if user["role"] == "admin_ec":
            admin_ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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

    - admin_ec: can only delete teachers that belong to their active educational center.
    - admin_numbux: can delete any teacher.
    """
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can delete teachers")

    with engine.begin() as conn:
        # --- Scope check for admin_ec ---
        if user["role"] == "admin_ec":
            admin_ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can create students")

    email_lower = body.email.lower()

    with engine.begin() as conn:
        # 1) Ensure email is not already used by any user type
        _ensure_email_not_exists(conn, email_lower)

        # 2) Resolve educational center depending on admin role
        if user["role"] == "admin_ec":
            # Admin EC: must belong to exactly one active center
            row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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

    - admin_ec: can only delete students that belong to their active educational center.
    - admin_numbux: can delete any student.
    """
    if user["role"] not in {"admin_ec", "admin_numbux"}:
        raise HTTPException(status_code=403, detail="Only admins can delete students")

    with engine.begin() as conn:
        # --- Scope check for admin_ec ---
        if user["role"] == "admin_ec":
            admin_ec_row = conn.execute(text("""
                SELECT id_ec
                  FROM numbux.admin_ec_ec
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

def _hash_password(pw: str) -> str:
    return bcrypt.hash(pw)

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
            INSERT INTO numbux.admin_ec (first_name, last_name, email, phone, password_hash)
            VALUES (:first_name, :last_name, :email, :phone, :password_hash)
            RETURNING id_admin_ec
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
            INSERT INTO numbux.admin_ec_ec (id_ec, id_admin, academic_year, start_date, end_date, status, license_code, role)
            VALUES (:id_ec, :id_admin, :academic_year, :start_date, NULL, 'active', :license_code, 'admin_ec')
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

    return _issue_tokens(admin_ec_id, email_lower, "admin_ec")