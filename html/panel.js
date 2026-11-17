"use strict";
const $ = id => document.getElementById(id);
let session = null;
let pollingLoad = false;
let loadTimer;

async function request(url, options = {}) {
  const response = await fetch(url, {cache: "no-store", credentials: "same-origin", ...options});
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : {};
  return {response, data};
}
function failure(response, data) {
  return data.message || (response.status === 503
    ? "Nginx ha limitado esta IP. Espera unos segundos y vuelve a intentar."
    : `No se pudo completar la solicitud (HTTP ${response.status}).`);
}
async function authenticated(url, options = {}) {
  const {response, data} = await request(url, options);
  if (response.status === 401) { location.assign("/"); throw new Error("La sesión ha caducado."); }
  if (!response.ok) throw new Error(failure(response, data));
  return data;
}
function postOptions(data = {}) {
  const headers = {"Content-Type": "application/json"};
  if (session) headers["X-CSRF-Token"] = session.csrf;
  return {method: "POST", headers, body: JSON.stringify(data)};
}
function row(values) {
  const tr = document.createElement("tr");
  for (const value of values) {
    const td = document.createElement("td"); td.textContent = String(value); tr.appendChild(td);
  }
  return tr;
}
function emptyRow(message, columns) {
  const tr = row([message]); tr.firstChild.colSpan = columns; return tr;
}
function codeBadge(value, error) {
  const span = document.createElement("span");
  span.className = `code${error ? " error" : ""}`; span.textContent = value; return span;
}
const form = $("login-form");
if (form) form.addEventListener("submit", async event => {
  event.preventDefault();
  const button = form.querySelector("button"); button.disabled = true;
  $("message").textContent = "Comprobando credenciales…";
  try {
    const {response, data} = await request("/api/auth/login", postOptions({username: $("username").value, password: $("password").value}));
    if (response.status === 200) location.assign(data.role === "admin" ? "/admin" : "/panel");
    else $("message").textContent = `HTTP ${response.status} · ${failure(response, data)}`;
  } catch { $("message").textContent = "No se pudo conectar. Comprueba que Docker está iniciado."; }
  finally { button.disabled = false; }
});
if ($("logout")) $("logout").addEventListener("click", async () => {
  const button = $("logout"); button.disabled = true;
  try {
    if (!session) session = await authenticated("/api/session");
    await authenticated("/api/auth/logout", postOptions());
    location.assign("/");
  } catch (error) { $("page-message").textContent = error.message; }
  finally { button.disabled = false; }
});

let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true; $("refresh").disabled = true;
  try {
    const data = await authenticated("/api/monitor");
    const entries = data.entries;
    for (const [id, status] of [["ok",200], ["unauthorized",401], ["forbidden",403], ["limited",429], ["blocked",503]]) {
      $(id).textContent = entries.filter(entry => entry.status === status).length.toLocaleString("es-CO");
    }
    const body = $("events"); body.replaceChildren();
    if (!entries.length) body.appendChild(emptyRow("Todavía no hay eventos en esta ventana.", 6));
    for (const entry of entries.slice(0, 100)) {
      const reason = entry.rate_limit === "REJECTED" ? "Tasa" : entry.connection_limit === "REJECTED" ? "Conexiones" : "—";
      const tr = row([new Date(entry.time).toLocaleTimeString("es-CO"), entry.method, entry.path, entry.ip, entry.status, reason]);
      tr.children[4].replaceChildren(codeBadge(entry.status, entry.status >= 400)); body.appendChild(tr);
    }
    $("log-message").textContent = `Consultado a las ${new Date().toLocaleTimeString("es-CO")}. ${entries.length} eventos visibles en la ventana.`;
  } catch (error) { $("log-message").textContent = error.message; }
  finally { refreshing = false; $("refresh").disabled = false; }
}
function renderLoad(data) {
  const running = data.state === "running";
  $("traffic").disabled = running;
  $("traffic").textContent = running ? "Prueba en curso…" : "Ejecutar 1.000 POST";
  if (data.state === "idle") {
    $("traffic-result").textContent = "Lista para ejecutar. Aún no hay resultados.";
    return;
  }
  const codes = data.codes || {};
  $("load-progress").value = data.completed || 0;
  const admitted = data.admitted ?? ["200", "400", "401", "429"].reduce((sum, code) => sum + (codes[code] || 0), 0);
  $("load-admitted").textContent = admitted.toLocaleString("es-CO");
  $("load-rejected").textContent = (codes["503"] || 0).toLocaleString("es-CO");
  $("load-duration").textContent = `${Number(data.duration_seconds || 0).toLocaleString("es-CO")} s`;
  $("load-errors").textContent = data.errors || 0;
  $("load-codes").textContent = Object.entries(codes).sort().map(([code, count]) => `HTTP ${code}: ${count.toLocaleString("es-CO")}`).join(" · ") || "Esperando respuestas HTTP…";
  if (data.other_http) $("load-codes").textContent += ` · Otros HTTP: ${data.other_http}`;
  $("traffic-result").textContent = running ? `${data.completed} de 1.000 solicitudes completadas` : data.state === "done" ? `Finalizada: ${data.completed} de 1.000 solicitudes.` : data.message || "La prueba no se completó.";
}
async function pollLoad() {
  if (pollingLoad) return;
  clearTimeout(loadTimer); pollingLoad = true;
  try {
    const data = await authenticated("/api/admin/load"); renderLoad(data);
    if (data.state === "running") loadTimer = setTimeout(pollLoad, 1000);
  } catch (error) {
    $("traffic-result").textContent = `${error.message} Se volverá a consultar el estado.`;
    $("traffic").disabled = true;
    loadTimer = setTimeout(pollLoad, 5000);
  } finally { pollingLoad = false; }
}
async function startLoad() {
  $("traffic").disabled = true;
  $("traffic-result").textContent = "Solicitando la prueba al contenedor atacante…";
  clearTimeout(loadTimer);
  try {
    const {response, data} = await request("/api/admin/load", postOptions());
    if (response.status === 401) { location.assign("/"); return; }
    if (response.status !== 202 && response.status !== 409) throw new Error(failure(response, data));
    if (response.status === 202) renderLoad(data);
    await pollLoad();
  } catch (error) {
    $("traffic-result").textContent = `${error.message} Comprobando el estado…`;
    loadTimer = setTimeout(pollLoad, 2000);
  }
}
async function audit() {
  $("audit").disabled = true;
  try {
    const response = await fetch("/", {cache: "no-store"});
    await response.text();
    const checks = [
      ["X-Frame-Options", value => value === "SAMEORIGIN"],
      ["X-Content-Type-Options", value => value === "nosniff"],
      ["Content-Security-Policy", value => ["default-src 'self'", "object-src 'none'", "frame-ancestors 'self'", "base-uri 'self'", "form-action 'self'"].every(rule => (value || "").includes(rule))],
      ["X-XSS-Protection", value => value === "0"],
      ["Referrer-Policy", value => value === "strict-origin-when-cross-origin"],
      ["Permissions-Policy", value => ["geolocation=()", "microphone=()", "camera=()"].every(rule => (value || "").includes(rule))],
      ["Server", value => !value || value === "nginx"]
    ];
    $("headers").replaceChildren();
    let passed = 0;
    for (const [name, check] of checks) {
      const value = response.headers.get(name);
      const ok = check(value); if (ok) passed++;
      const tr = row([name, value || "No expuesta", ""]);
      tr.lastChild.appendChild(codeBadge(ok ? "Correcta" : "Revisar", !ok)); $("headers").appendChild(tr);
    }
    $("audit-message").textContent = `GET / → HTTP ${response.status}. ${passed} de ${checks.length} verificaciones correctas. Server se comprueba sin número de versión.`;
  } catch { $("audit-message").textContent = "No se pudo consultar el servidor. Reintenta la auditoría."; }
  finally { $("audit").disabled = false; }
}
async function initPanel() {
  try {
    session = await authenticated("/api/session");
    $("account-role").textContent = session.role === "admin" ? "Cuenta administrativa" : "Cuenta de usuario";
    if ($("account-name")) $("account-name").textContent = session.username;
    if ($("admin-link")) $("admin-link").hidden = session.role !== "admin";
    if ($("products")) {
      const data = await authenticated("/api/products");
      $("total").textContent = data.products.length;
      $("stock").textContent = data.products.reduce((sum, product) => sum + product.stock, 0);
      $("products").replaceChildren(...data.products.map(product => row([product.name, product.category, `$${Number(product.price).toLocaleString("es-CO")}`, product.stock])));
    }
    if ($("events")) {
      $("refresh").addEventListener("click", refresh);
      $("traffic").addEventListener("click", startLoad);
      $("audit").addEventListener("click", audit);
      await Promise.all([refresh(), pollLoad()]);
      setInterval(() => { if (!document.hidden) refresh(); }, 5000);
    }
  } catch (error) { $("page-message").textContent = error.message; }
}
if (document.body.dataset.page) initPanel();
