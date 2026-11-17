"""Validación HTTP real, exclusivamente contra localhost y el Docker del laboratorio.

Ejecutar con los contenedores iniciados: python tests/validate_lab.py
Incluye UNA carga de 1.000 POST, controlada por el administrador y el atacante.
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
from pathlib import Path
import subprocess
import time


HEADERS = {
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
    "x-xss-protection": "0",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
}


def request(path, method="GET", data=None, cookie=None, csrf=None, extra=None):
    # Ritmo inferior a 5 r/s para que la validación no compita con su propio límite.
    time.sleep(0.23)
    connection = HTTPConnection("localhost", 80, timeout=15)
    headers = dict(extra or {})
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CSRF-Token"] = csrf
    body = None
    if data is not None:
        body = json.dumps(data)
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        raw = response.read()
        received_headers = {key.lower(): value for key, value in response.getheaders()}
        result = json.loads(raw) if "application/json" in received_headers.get("content-type", "") else raw.decode()
        for key, expected in HEADERS.items():
            assert received_headers.get(key) == expected, (path, key, received_headers)
        assert received_headers.get("server") == "nginx", received_headers
        assert "default-src 'self'" in received_headers.get("content-security-policy", "")
        return response.status, result, received_headers
    finally:
        connection.close()


def expect(status, path, **kwargs):
    actual, data, headers = request(path, **kwargs)
    assert actual == status, (path, status, actual, data)
    return data, headers


def sign_in(username, password):
    data, headers = expect(200, "/api/auth/login", method="POST", data={"username": username, "password": password})
    jar = SimpleCookie()
    jar.load(headers["set-cookie"])
    cookie = jar["lab_session"]
    assert cookie["httponly"] and cookie["secure"] and cookie["samesite"] == "Strict"
    assert cookie["max-age"] == "1800" and cookie["path"] == "/"
    return f"lab_session={cookie.value}", data["csrf"]


def attack_log_counts():
    code = (
        "import json; from collections import Counter; "
        "rows=[json.loads(line) for line in open('/monitor/access.log')]; "
        "print(json.dumps(dict(Counter(str(r['status']) for r in rows "
        "if r.get('ip')=='172.28.0.20' and r.get('path')=='/api/auth/login' "
        "and r.get('method')=='POST'))))"
    )
    output = subprocess.check_output(["docker", "compose", "exec", "-T", "demo_app", "python", "-c", code], text=True)
    return Counter(json.loads(output))


def main():
    for _ in range(30):
        status, _, _ = request("/api/demo/stats")
        if status == 200:
            break
    else:
        raise AssertionError("La aplicación no está lista detrás de Nginx")
    expect(200, "/")
    expect(200, "/", method="HEAD")
    expect(401, "/admin")
    expect(401, "/api/admin/load")
    expect(401, "/api/admin/load", method="POST", data={})
    expect(401, "/api/auth/login", method="POST", data={"username": "usuario", "password": "incorrecta"})
    user_cookie, user_csrf = sign_in("usuario", "UsuarioDemo2026!")
    expect(200, "/panel", cookie=user_cookie)
    expect(200, "/tienda.html", cookie=user_cookie)
    products, _ = expect(200, "/api/products", cookie=user_cookie)
    assert len(products["products"]) == 3
    for path in ("/admin", "/admin/", "/monitor.html", "/api/monitor", "/api/admin/load"):
        expect(403, path, cookie=user_cookie)
    expect(403, "/api/admin/load", method="POST", data={}, cookie=user_cookie, csrf=user_csrf)
    expect(401, "/api/session", cookie="lab_session=manipulada")
    expect(403, "/api/auth/login", method="POST", data={}, extra={"Origin": "https://otro-origen.invalid"})

    admin_cookie, csrf = sign_in("admin", "AdminDemo2026!")
    expect(200, "/admin", cookie=admin_cookie)
    expect(200, "/admin", method="HEAD", cookie=admin_cookie)
    expect(200, "/monitor.html", cookie=admin_cookie)
    expect(403, "/api/admin/load", method="POST", data={}, cookie=admin_cookie)
    expect(400, "/api/admin/load", method="POST", data={"target": "https://example.invalid", "concurrency": 500}, cookie=admin_cookie, csrf=csrf)
    for method in ("POST", "PUT", "DELETE", "TRACE", "OPTIONS"):
        for path in ("/", "/admin", "/api/products", "/api/monitor", "/api/demo/protected", "/api/no-existe"):
            # Nginx rechaza TRACE con su 405 nativo antes de evaluar limit_except.
            expect(405 if method == "TRACE" else 403, path, method=method,
                   data={} if method == "POST" else None, cookie=admin_cookie)
    expect(403, "/api/admin/load", method="PUT", cookie=admin_cookie)
    expect(403, "/api/auth/login", method="GET")

    # Se conserva el bloqueo original de cuenta, adicional al rate limit de Nginx.
    attempt_account = f"inexistente-{time.time_ns()}"
    for i in range(5):
        expect(401 if i < 4 else 429, "/api/auth/login", method="POST", data={"username": attempt_account, "password": "incorrecta"})

    before = attack_log_counts()
    run, _ = expect(202, "/api/admin/load", method="POST", data={}, cookie=admin_cookie, csrf=csrf)
    expect(409, "/api/admin/load", method="POST", data={}, cookie=admin_cookie, csrf=csrf)
    assert run["target"] == "http://172.28.0.10/api/auth/login" and run["concurrency"] == 50
    deadline = time.monotonic() + 120
    while True:
        state, _ = expect(200, "/api/admin/load", cookie=admin_cookie)
        if state["state"] != "running":
            break
        assert time.monotonic() < deadline, "La prueba excedió 120 s"
        time.sleep(0.5)
    assert state["state"] == "done", state
    assert state["completed"] == state["total"] == 1000, state
    assert sum(state["codes"].values()) + state["errors"] == 1000, state
    assert state["rejected"] > 0 and state["codes"].get("200", 0) > 0, state
    assert state["admitted"] + state["rejected"] + state["errors"] + state["other_http"] == 1000, state
    time.sleep(0.3)
    observed = attack_log_counts() - before
    assert dict(observed) == state["codes"], (observed, state)
    monitor, _ = expect(200, "/api/monitor", cookie=admin_cookie)
    assert any(entry.get("rate_limit") == "REJECTED" and entry["status"] == 503 for entry in monitor["entries"])
    assert all(entry["path"] not in ("/api/monitor", "/api/admin/load") for entry in monitor["entries"])
    expect(200, "/api/auth/logout", method="POST", data={}, cookie=admin_cookie, csrf=csrf)
    expect(401, "/admin", cookie=admin_cookie)
    expect(401, "/api/session", cookie=admin_cookie)
    # Ráfaga breve posterior a la carga: verifica cabeceras y página de un 503 real.
    with ThreadPoolExecutor(max_workers=20) as pool:
        responses = list(pool.map(lambda _: request("/api/demo/protected"), range(20)))
    rejected = [body for status, body, _ in responses if status == 503]
    assert rejected and all("Nginx" in body for body in rejected), responses
    print("OK: login, roles, rutas originales, métodos, CSRF, cookies, logout y cabeceras.")
    print("OK: 1.000 POST del atacante; códigos coinciden exactamente con el log de Nginx.")
    print(json.dumps(state, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    # Ejecutar Docker desde la raíz incluso al invocar el script con una ruta absoluta.
    import os
    os.chdir(Path(__file__).resolve().parent.parent)
    main()
