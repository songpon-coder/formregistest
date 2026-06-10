#!/usr/bin/env python3
"""
แบบสอบถาม - เซิร์ฟเวอร์หน้าบ้าน + หลังบ้าน (Python stdlib เท่านั้น)

หน้าบ้าน  : http://localhost:8000/            (ฟอร์มแบบสอบถาม - คนทั่วไป)
หลังบ้าน  : http://localhost:8000/admin       (ต้อง login)

รัน:  python3 server.py
"""

import json
import os
import re
import io
import csv
import time
import hmac
import base64
import hashlib
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# ค่าคงที่ / ที่อยู่ไฟล์
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
ADMIN_DIR = os.path.join(BASE_DIR, "admin")
DATA_DIR = os.path.join(BASE_DIR, "data")
RESPONSES_FILE = os.path.join(DATA_DIR, "responses.json")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

HOST = "0.0.0.0"
PORT = 8000

PHONE_RE = re.compile(r"^0\d{8,9}$")
SESSION_TTL = 60 * 60 * 8  # 8 ชั่วโมง

_lock = threading.Lock()
_sessions = {}  # token -> expiry_timestamp


# ---------------------------------------------------------------------------
# จัดการรหัสผ่าน (pbkdf2 - stdlib)
# ---------------------------------------------------------------------------
def hash_password(password, salt=None, iterations=200_000):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password, stored):
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# โหลด/บันทึกข้อมูล
# ---------------------------------------------------------------------------
def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def ensure_config():
    """สร้างบัญชี admin เริ่มต้นถ้ายังไม่มี"""
    if os.path.exists(CONFIG_FILE):
        return load_json(CONFIG_FILE, {})
    default_user = "admin"
    default_pass = "admin123"
    cfg = {"username": default_user, "password_hash": hash_password(default_pass)}
    save_json(CONFIG_FILE, cfg)
    print("=" * 60)
    print("  สร้างบัญชี admin เริ่มต้นแล้ว (กรุณาเปลี่ยนรหัสผ่าน!)")
    print(f"    username : {default_user}")
    print(f"    password : {default_pass}")
    print("=" * 60)
    return cfg


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
def create_session():
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = time.time() + SESSION_TTL
    return token


def is_valid_session(token):
    if not token:
        return False
    with _lock:
        exp = _sessions.get(token)
        if exp is None:
            return False
        if exp < time.time():
            _sessions.pop(token, None)
            return False
        return True


def destroy_session(token):
    with _lock:
        _sessions.pop(token, None)


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "SurveyApp/1.0"

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} - {fmt % args}")

    # ---- helpers ----
    def _send(self, code, body=b"", content_type="text/plain; charset=utf-8", extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra_headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8", extra_headers)

    def _serve_file(self, path, content_type):
        if not os.path.exists(path):
            self._send(404, "Not Found")
            return
        with open(path, "rb") as f:
            self._send(200, f.read(), content_type)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _get_cookie(self, name):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return None

    def _require_auth(self):
        token = self._get_cookie("session")
        if not is_valid_session(token):
            self._json(401, {"error": "unauthorized"})
            return False
        return True

    # ---- GET ----
    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/" or path == "/index.html":
            return self._serve_file(os.path.join(PUBLIC_DIR, "index.html"), "text/html; charset=utf-8")

        if path == "/admin" or path == "/admin/":
            # ถ้ามี session ไปหน้า dashboard, ไม่งั้นไป login
            if is_valid_session(self._get_cookie("session")):
                return self._serve_file(os.path.join(ADMIN_DIR, "dashboard.html"), "text/html; charset=utf-8")
            return self._send(302, "", extra_headers={"Location": "/admin/login"})

        if path == "/admin/login":
            return self._serve_file(os.path.join(ADMIN_DIR, "login.html"), "text/html; charset=utf-8")

        if path == "/api/responses":
            if not self._require_auth():
                return
            data = load_json(RESPONSES_FILE, [])
            return self._json(200, {"responses": data, "count": len(data)})

        if path == "/api/export":
            if not self._require_auth():
                return
            data = load_json(RESPONSES_FILE, [])
            buf = io.StringIO()
            buf.write("﻿")  # BOM ให้ Excel อ่านภาษาไทย
            w = csv.writer(buf)
            w.writerow(["ลำดับ", "ชื่อ-นามสกุล", "เบอร์โทร", "เวลา"])
            for i, r in enumerate(data, 1):
                w.writerow([i, r.get("name", ""), r.get("phone", ""), r.get("time", "")])
            return self._send(200, buf.getvalue(), "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="responses.csv"'})

        if path == "/api/me":
            return self._json(200, {"authenticated": is_valid_session(self._get_cookie("session"))})

        self._send(404, "Not Found")

    # ---- POST ----
    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/submit":
            return self._handle_submit()

        if path == "/api/login":
            return self._handle_login()

        if path == "/api/logout":
            token = self._get_cookie("session")
            destroy_session(token)
            return self._json(200, {"ok": True},
                              {"Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})

        self._send(404, "Not Found")

    # ---- DELETE ----
    def do_DELETE(self):
        path = urlparse(self.path).path
        m = re.match(r"^/api/responses/([\w-]+)$", path)
        if m:
            if not self._require_auth():
                return
            rid = m.group(1)
            with _lock:
                data = load_json(RESPONSES_FILE, [])
                new_data = [r for r in data if r.get("id") != rid]
                save_json(RESPONSES_FILE, new_data)
            return self._json(200, {"ok": True, "count": len(new_data)})
        self._send(404, "Not Found")

    # ---- handlers ----
    def _handle_submit(self):
        body = self._read_body()
        name = str(body.get("name", "")).strip()
        phone = str(body.get("phone", "")).strip()

        errors = {}
        if not name:
            errors["name"] = "กรุณากรอกชื่อ-นามสกุล"
        if not phone:
            errors["phone"] = "กรุณากรอกเบอร์โทรศัพท์"
        elif not PHONE_RE.match(phone):
            errors["phone"] = "เบอร์โทรไม่ถูกต้อง (ตัวเลข 9-10 หลัก ขึ้นต้นด้วย 0)"
        if errors:
            return self._json(400, {"ok": False, "errors": errors})

        record = {
            "id": secrets.token_hex(8),
            "name": name[:200],
            "phone": phone,
            "time": time.strftime("%d/%m/%Y %H:%M:%S"),
            "ts": time.time(),
        }
        with _lock:
            data = load_json(RESPONSES_FILE, [])
            data.append(record)
            save_json(RESPONSES_FILE, data)
        return self._json(200, {"ok": True})

    def _handle_login(self):
        body = self._read_body()
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))
        cfg = load_json(CONFIG_FILE, {})

        if username == cfg.get("username") and verify_password(password, cfg.get("password_hash", "")):
            token = create_session()
            cookie = f"session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax"
            return self._json(200, {"ok": True}, {"Set-Cookie": cookie})
        time.sleep(0.5)  # หน่วงกัน brute force เล็กน้อย
        return self._json(401, {"ok": False, "error": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"})


def main():
    ensure_config()
    if not os.path.exists(RESPONSES_FILE):
        save_json(RESPONSES_FILE, [])
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"\n  เซิร์ฟเวอร์ทำงานแล้ว")
    print(f"  หน้าบ้าน (ฟอร์ม) : http://localhost:{PORT}/")
    print(f"  หลังบ้าน (admin) : http://localhost:{PORT}/admin")
    print(f"  หยุด: กด Ctrl+C\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  ปิดเซิร์ฟเวอร์แล้ว")
        server.shutdown()


if __name__ == "__main__":
    main()
