"""Aplicación didáctica local. No usar ni publicar fuera de este laboratorio."""

from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from collections import deque
from urllib.parse import urlsplit

DB_PATH = "/tmp/lab.db"
SESSION_KEY = secrets.token_bytes(32)
COUNTS = {"open": 0, "protected": 0}
COUNTS_LOCK = threading.Lock()
ATTEMPTS = {}
ATTEMPTS_LOCK = threading.Lock()


def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row
    return db


def initialize_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                username TEXT PRIMARY KEY, password TEXT NOT NULL, display_name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
                price REAL NOT NULL, stock INTEGER NOT NULL
            );
        """)
        db.execute(
            "INSERT OR IGNORE INTO accounts VALUES (?, ?, ?)",
            ("admin", "demo1234", "Cuenta de demostración"),
        )
        db.executemany(
            "INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?, ?)",
            [
                (1, "Café de la casa", "Despensa", 18500, 18),
                (2, "Pan de masa madre", "Panadería", 9200, 7),
                (3, "Mermelada de mora", "Despensa", 12600, 12),
            ],
        )


def make_session(username):
    expires = int(time.time()) + 1800
    payload = f"{username}:{expires}".encode()
    signature = hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()
    return (payload.decode() + ":" + signature)


def valid_session(cookie_header):
    jar = SimpleCookie()
    try:
        jar.load(cookie_header or "")
        token = jar["lab_session"].value
        username, expires, signature = token.split(":", 2)
        payload = f"{username}:{expires}".encode()
        expected = hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()
        return username if int(expires) > time.time() and hmac.compare_digest(signature, expected) else None
    except (KeyError, ValueError):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoApp"
    sys_version = ""
    request_queue_size = 256

    def log_message(self, fmt, *args):
        # Deja trazas HTTP breves en docker logs sin imprimir contraseñas ni cuerpos POST.
        print(f"{self.client_address[0]} {fmt % args}", flush=True)

    def send_json(self, status, data, session=None):
        payload = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if session:
            self.send_header(
                "Set-Cookie",
                f"lab_session={session}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800",
            )
        self.end_headers()
        self.wfile.write(payload)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size < 1 or size > 4096:
            raise ValueError("El cuerpo debe tener entre 1 y 4096 bytes.")
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError("Se esperaba un objeto JSON.")
        return data

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/demo/open":
            self.record_demo("open")
            return self.send_json(200, {"ok": True, "message": "La ruta abierta llegó a la aplicación."})
        if path == "/api/demo/protected":
            self.record_demo("protected")
            return self.send_json(200, {"ok": True, "message": "Nginx permitió esta solicitud."})
        if path == "/api/demo/stats":
            with COUNTS_LOCK:
                return self.send_json(200, dict(COUNTS))
        if path == "/api/monitor":
            if not valid_session(self.headers.get("Cookie")):
                return self.send_json(401, {"ok": False})
            try:
                with open("/monitor/access.log", encoding="utf-8") as log:
                    lines = list(deque(log, maxlen=500))
                entries = []
                for line in lines:
                    try:
                        entry = json.loads(line)
                        if entry.get("path") != "/api/monitor":
                            entries.append(entry)
                    except ValueError:
                        continue
                return self.send_json(200, {"ok": True, "entries": entries[::-1]})
            except FileNotFoundError:
                return self.send_json(200, {"ok": True, "entries": []})
        if path == "/api/products":
            username = valid_session(self.headers.get("Cookie"))
            if not username:
                return self.send_json(401, {"ok": False, "message": "Inicia sesión para ver el inventario."})
            with connect_db() as db:
                rows = db.execute("SELECT name, category, price, stock FROM products ORDER BY id").fetchall()
            return self.send_json(200, {"ok": True, "products": [dict(row) for row in rows]})
        return self.send_json(404, {"ok": False, "message": "Ruta no encontrada."})

    def record_demo(self, mode):
        with COUNTS_LOCK:
            COUNTS[mode] += 1

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            data = self.read_json()
        except (ValueError, json.JSONDecodeError) as error:
            return self.send_json(400, {"ok": False, "message": str(error)})

        username = str(data.get("username", ""))[:80]
        password = str(data.get("password", ""))[:80]
        if path == "/api/auth/login":
            key = username.lower()
            now = time.time()
            with ATTEMPTS_LOCK:
                failures, blocked_until = ATTEMPTS.get(key, (0, 0))
                if blocked_until > now:
                    return self.send_json(429, {"ok": False, "message": "Demasiados intentos. Espera unos segundos."})
                if blocked_until:
                    failures = 0
                    ATTEMPTS.pop(key, None)
                with connect_db() as db:
                    row = db.execute(
                        "SELECT username, display_name FROM accounts WHERE username = ? AND password = ?",
                        (username, password),
                    ).fetchone()
                if not row:
                    failures += 1
                    ATTEMPTS[key] = (failures, now + 30 if failures >= 5 else 0)
                    if failures >= 5:
                        return self.send_json(429, {"ok": False, "message": "Demasiados intentos. Espera 30 segundos."})
                    return self.send_json(401, {"ok": False, "message": "Usuario o contrase?a incorrectos."})
                ATTEMPTS.pop(key, None)
            return self.send_json(200, {"ok": True}, make_session(row["username"]))
        if path == "/api/auth/logout":
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Set-Cookie", "lab_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            self.end_headers()
            self.wfile.write(payload)
            return

        return self.send_json(404, {"ok": False, "message": "Ruta no encontrada."})

    def do_HEAD(self):
        self.send_error(405, "Usa GET para esta ruta.")


if __name__ == "__main__":
    initialize_db()
    print("Aplicación de demostración escuchando en el puerto 8000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
