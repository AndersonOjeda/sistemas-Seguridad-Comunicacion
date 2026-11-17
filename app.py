"""Laboratorio local: aplicación y ejecutor fijo, sin dependencias externas."""

from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import hmac
from http.client import HTTPConnection
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import threading
import time
from urllib.parse import urlsplit

HTML = Path(__file__).parent / "html"
SESSION_TTL = 1800
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
ATTEMPTS = {}
ATTEMPTS_LOCK = threading.Lock()
COUNTS = {"open": 0, "protected": 0}
COUNTS_LOCK = threading.Lock()
HASH_ITERATIONS = 210_000


def password_record(password):
    salt = secrets.token_bytes(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, HASH_ITERATIONS)


# Cuentas ficticias documentadas. En memoria sólo se conservan sal y hash.
ACCOUNTS = {
    "usuario": {"role": "usuario", "password": password_record("UsuarioDemo2026!")},
    "admin": {"role": "admin", "password": password_record("AdminDemo2026!")},
}
DUMMY_PASSWORD = password_record(secrets.token_hex(20))
PRODUCTS = [
    {"name": "Café de la casa", "category": "Despensa", "price": 18500, "stock": 18},
    {"name": "Pan de masa madre", "category": "Panadería", "price": 9200, "stock": 7},
    {"name": "Mermelada de mora", "category": "Despensa", "price": 12600, "stock": 12},
]


def session_from(cookie_header):
    jar = SimpleCookie()
    try:
        jar.load(cookie_header or "")
        token = jar["lab_session"].value
    except (CookieError, KeyError, ValueError):
        return None, None
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if session and session["expires"] > time.time():
            return token, dict(session)
        SESSIONS.pop(token, None)
    return None, None


def new_session(username, old_token):
    now = time.time()
    with SESSIONS_LOCK:
        for token in list(SESSIONS):
            if SESSIONS[token]["expires"] <= now:
                del SESSIONS[token]
        if old_token:
            SESSIONS.pop(old_token, None)
        if len(SESSIONS) >= 2048:
            del SESSIONS[next(iter(SESSIONS))]
        token = secrets.token_urlsafe(32)
        session = {"username": username, "role": ACCOUNTS[username]["role"],
                   "csrf": secrets.token_urlsafe(32), "expires": now + SESSION_TTL}
        SESSIONS[token] = session
    return token, session


def worker_request(method, path):
    # Destino interno fijo. Nunca se aceptan URLs ni comandos del cliente.
    connection = HTTPConnection("172.28.0.20", 8001, timeout=5)
    try:
        body = b"{}" if method == "POST" else None
        connection.request(method, path, body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class LabServer(ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoApp"
    sys_version = ""
    timeout = 10

    def log_message(self, fmt, *args):
        # Sin cuerpos POST, contraseñas ni cookies en los registros.
        print(f"{self.client_address[0]} {fmt % args}", flush=True)

    def send_body(self, status, payload, content_type, cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def send_json(self, status, data, cookie=None):
        self.send_body(status, json.dumps(data, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8", cookie)

    def error(self, status, message):
        return self.send_json(status, {"ok": False, "message": message})

    def read_json(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("No se admite Transfer-Encoding.")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            raise ValueError("Usa Content-Type: application/json.")
        size = int(self.headers.get("Content-Length", "0"))
        if not 1 <= size <= 4096:
            raise ValueError("El cuerpo debe tener entre 1 y 4096 bytes.")
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError("Se esperaba un objeto JSON.")
        return data

    def require_session(self, admin=False):
        token, session = session_from(self.headers.get("Cookie"))
        if not session:
            self.error(401, "Inicia sesión para continuar.")
            return None, None
        if admin and session["role"] != "admin":
            self.error(403, "Esta sección requiere una cuenta administrativa.")
            return None, None
        return token, session

    def same_origin(self):
        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed = urlsplit(origin)
            except ValueError:
                self.error(403, "Origen de solicitud no permitido.")
                return False
            scheme = self.headers.get("X-Forwarded-Proto", "http")
            if parsed.scheme != scheme or parsed.netloc != self.headers.get("Host"):
                self.error(403, "Origen de solicitud no permitido.")
                return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.error(403, "Origen de solicitud no permitido.")
            return False
        return True

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/panel", "/panel/", "/tienda.html", "/admin", "/admin/", "/monitor.html"):
            admin = path in ("/admin", "/admin/", "/monitor.html")
            if not self.require_session(admin)[1]:
                return
            filename = "monitor.html" if admin else "tienda.html"
            return self.send_body(200, (HTML / filename).read_bytes(), "text/html; charset=utf-8")
        if path in ("/api/demo/open", "/api/demo/protected"):
            mode = path.rsplit("/", 1)[1]
            with COUNTS_LOCK:
                COUNTS[mode] += 1
            return self.send_json(200, {"ok": True, "message": "La solicitud llegó a Python."})
        if path == "/api/demo/stats":
            with COUNTS_LOCK:
                return self.send_json(200, dict(COUNTS))
        if path == "/api/session":
            _, session = self.require_session()
            if session:
                return self.send_json(200, {"ok": True, **session})
            return
        if path == "/api/products":
            if self.require_session()[1]:
                return self.send_json(200, {"ok": True, "products": PRODUCTS})
            return
        if path in ("/api/monitor", "/api/admin/load"):
            if not self.require_session(admin=True)[1]:
                return
            if path == "/api/admin/load":
                return self.forward_worker("GET", "/status")
            try:
                with open("/monitor/access.log", encoding="utf-8") as log:
                    lines = deque(log, maxlen=500)
                entries = []
                for line in lines:
                    try:
                        entry = json.loads(line)
                        if entry.get("path") not in ("/api/monitor", "/api/admin/load"):
                            entries.append(entry)
                    except ValueError:
                        continue
                return self.send_json(200, {"ok": True, "entries": entries[::-1]})
            except FileNotFoundError:
                return self.send_json(200, {"ok": True, "entries": []})
        return self.error(404, "Ruta no encontrada.")

    def forward_worker(self, method, path):
        try:
            status, data = worker_request(method, path)
            return self.send_json(status, data)
        except (OSError, ValueError):
            return self.error(502, "El contenedor atacante no está disponible. Revisa Docker Compose.")

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/api/auth/login", "/api/auth/logout", "/api/admin/load"):
            return self.error(403, "Método no permitido en esta ruta.")
        if not self.same_origin():
            return
        session = None
        token = None
        if path != "/api/auth/login":
            token, session = self.require_session(admin=path == "/api/admin/load")
            if not session:
                return
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", "").encode(), session["csrf"].encode()):
                return self.error(403, "Token de sesión incorrecto. Recarga la página.")
        try:
            data = self.read_json()
        except (ValueError, UnicodeError) as error:
            return self.error(400, str(error))
        if path == "/api/admin/load":
            if data:
                return self.error(400, "La prueba no acepta parámetros: destino y carga son fijos.")
            return self.forward_worker("POST", "/run")
        if path == "/api/auth/logout":
            with SESSIONS_LOCK:
                SESSIONS.pop(token, None)
            return self.send_json(200, {"ok": True}, self.session_cookie("", 0))

        username = data.get("username", "")
        password = data.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 80 or len(password) > 128:
            return self.error(400, "Credenciales con formato incorrecto.")
        key = username.lower()
        now = time.time()
        with ATTEMPTS_LOCK:
            for old_key in list(ATTEMPTS):
                if now - ATTEMPTS[old_key][2] > 60:
                    del ATTEMPTS[old_key]
            failures, blocked_until, _ = ATTEMPTS.get(key, (0, 0, now))
            if blocked_until > now:
                return self.error(429, "Demasiados intentos. Espera 30 segundos.")
            if blocked_until:
                failures = 0
                ATTEMPTS.pop(key, None)
        account = ACCOUNTS.get(username)
        salt, expected = account["password"] if account else DUMMY_PASSWORD
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, HASH_ITERATIONS)
        if not hmac.compare_digest(actual, expected) or not account:
            with ATTEMPTS_LOCK:
                current = ATTEMPTS.get(key, (0, 0, now))
                failures = max(failures, current[0]) + 1
                if len(ATTEMPTS) >= 2048 and key not in ATTEMPTS:
                    del ATTEMPTS[next(iter(ATTEMPTS))]
                ATTEMPTS[key] = (failures, now + 30 if failures >= 5 else 0, now)
            if failures >= 5:
                return self.error(429, "Demasiados intentos. Espera 30 segundos.")
            return self.error(401, "Usuario o contraseña incorrectos.")
        with ATTEMPTS_LOCK:
            ATTEMPTS.pop(key, None)
        old_token, _ = session_from(self.headers.get("Cookie"))
        token, session = new_session(username, old_token)
        return self.send_json(200, {"ok": True, **session}, self.session_cookie(token, SESSION_TTL))

    @staticmethod
    def session_cookie(token, age):
        # Secure se admite en http://localhost en navegadores modernos.
        return f"lab_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={age}"


# El mismo archivo se reutiliza en cliente-atacante con --attacker.
LOAD_LOCK = threading.Lock()
LOAD_STATE = {"state": "idle"}
LOAD_TOTAL = 1000
LOAD_CONCURRENCY = 50


def load_once(_):
    # Sin redirecciones, proxy del entorno, URL configurable, shell ni cookie de admin.
    connection = HTTPConnection("172.28.0.10", 80, timeout=10)
    payload = json.dumps({"username": "usuario", "password": "UsuarioDemo2026!"})
    try:
        connection.request("POST", "/api/auth/login", payload,
                           {"Content-Type": "application/json", "Host": "localhost"})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def execute_load():
    started = time.monotonic()
    codes = Counter()
    errors = 0
    try:
        with ThreadPoolExecutor(max_workers=LOAD_CONCURRENCY) as pool:
            futures = [pool.submit(load_once, i) for i in range(LOAD_TOTAL)]
            for future in as_completed(futures):
                try:
                    codes[str(future.result())] += 1
                except Exception as error:
                    # Fallos de transporte aparte; nunca se inventa un código HTTP.
                    errors += 1
                    print(f"Fallo de transporte: {type(error).__name__}", flush=True)
                with LOAD_LOCK:
                    LOAD_STATE.update(completed=sum(codes.values()) + errors, codes=dict(codes),
                                      errors=errors, duration_seconds=round(time.monotonic() - started, 3))
    except Exception as error:
        with LOAD_LOCK:
            LOAD_STATE.update(state="failed", message=f"No se completó la prueba: {type(error).__name__}")
        return
    with LOAD_LOCK:
        # Admitida significa enviada a la aplicación, independientemente del login.
        LOAD_STATE.update(state="done", admitted=sum(codes.get(str(code), 0) for code in (200, 400, 401, 429)),
                          rejected=codes.get("503", 0),
                          other_http=sum(count for code, count in codes.items() if code not in ("200", "400", "401", "429", "503")),
                          duration_seconds=round(time.monotonic() - started, 3))
    print(json.dumps(LOAD_STATE, ensure_ascii=False), flush=True)


class AttackerHandler(Handler):
    def allowed(self):
        if self.client_address[0] != "172.28.0.30":
            self.error(403, "Sólo la aplicación del laboratorio puede controlar esta prueba.")
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        if self.path != "/status":
            return self.error(404, "Ruta no encontrada.")
        with LOAD_LOCK:
            return self.send_json(200, dict(LOAD_STATE))

    def do_POST(self):
        if not self.allowed():
            return
        if self.path != "/run":
            return self.error(404, "Ruta no encontrada.")
        try:
            if self.read_json():
                return self.error(400, "No se aceptan parámetros.")
        except (ValueError, UnicodeError):
            return self.error(400, "Se esperaba un objeto vacío.")
        with LOAD_LOCK:
            if LOAD_STATE["state"] == "running":
                return self.error(409, "Ya hay una prueba activa.")
            LOAD_STATE.clear()
            LOAD_STATE.update(state="running", id=secrets.token_hex(8), total=LOAD_TOTAL,
                              concurrency=LOAD_CONCURRENCY, completed=0, codes={}, errors=0,
                              target="http://172.28.0.10/api/auth/login", method="POST",
                              duration_seconds=0)
            threading.Thread(target=execute_load, daemon=True).start()
            return self.send_json(202, dict(LOAD_STATE))


if __name__ == "__main__":
    attacker = sys.argv[1:] == ["--attacker"]
    port = 8001 if attacker else 8000
    print(f"{'Atacante local' if attacker else 'Aplicación'} escuchando en {port}", flush=True)
    LabServer(("0.0.0.0", port), AttackerHandler if attacker else Handler).serve_forever()
