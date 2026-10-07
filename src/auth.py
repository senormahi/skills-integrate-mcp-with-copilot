import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

TEACHERS_FILE = Path(__file__).with_name("teachers.json")
PASSWORD_ITERATIONS = 600_000
SESSION_COOKIE = "teacher_session"
SESSION_TTL = 8 * 60 * 60
SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not SESSION_SECRET:
    if os.environ.get("ENVIRONMENT", "development").lower() == "production":
        raise RuntimeError("SESSION_SECRET must be configured in production")
    SESSION_SECRET = secrets.token_urlsafe(32)
COOKIE_SECURE = os.environ.get(
    "COOKIE_SECURE",
    "true" if os.environ.get("ENVIRONMENT", "development").lower() == "production" else "false",
).lower() == "true"

router = APIRouter(prefix="/auth")


class LoginRequest(BaseModel):
    username: str
    password: str


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return "$".join(
        (
            "pbkdf2_sha256",
            str(PASSWORD_ITERATIONS),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if iterations < 1:
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
    except (ValueError, UnicodeError):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(actual, expected)


def load_teacher_credentials() -> dict[str, str]:
    if not TEACHERS_FILE.exists():
        return {}
    try:
        credentials = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Unable to read teacher credentials") from error
    if not isinstance(credentials, dict) or not all(
        isinstance(username, str) and isinstance(password_hash, str)
        for username, password_hash in credentials.items()
    ):
        raise RuntimeError("Teacher credentials must map usernames to password hashes")
    return credentials


def save_teacher_credentials(credentials: dict[str, str]) -> None:
    TEACHERS_FILE.write_text(
        json.dumps(credentials, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(TEACHERS_FILE, 0o600)


def _encode_token_part(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_token_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_session_token(username: str, password_hash: str) -> str:
    payload = json.dumps(
        {
            "username": username,
            "expires": int(time.time()) + SESSION_TTL,
            "credential": hashlib.sha256(password_hash.encode("utf-8")).hexdigest(),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = _encode_token_part(payload)
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{encoded_payload}.{_encode_token_part(signature)}"


def get_session_teacher(token: str | None) -> str | None:
    if not token or len(token) > 4096:
        return None
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        signature = _decode_token_part(encoded_signature)
        expected_signature = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None

        payload = json.loads(_decode_token_part(encoded_payload))
        username = payload["username"]
        if not isinstance(username, str) or payload["expires"] < time.time():
            return None
        password_hash = load_teacher_credentials().get(username)
        if not password_hash:
            return None
        credential_fingerprint = hashlib.sha256(
            password_hash.encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(payload["credential"], credential_fingerprint):
            return None
        return username
    except (ValueError, TypeError, KeyError, UnicodeError, json.JSONDecodeError):
        return None


def require_teacher(request: Request) -> str:
    username = get_session_teacher(request.cookies.get(SESSION_COOKIE))
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


@router.post("/login")
def login(payload: LoginRequest, response: Response):
    username = payload.username.strip()
    password_hash = load_teacher_credentials().get(username)
    if not password_hash or not verify_password(payload.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session_token(username, password_hash),
        max_age=SESSION_TTL,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"authenticated": True, "username": username}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )
    return {"authenticated": False}


@router.get("/status")
def status(request: Request):
    username = get_session_teacher(request.cookies.get(SESSION_COOKIE))
    if username is None:
        return {"authenticated": False}
    return {"authenticated": True, "username": username}