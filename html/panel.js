"use strict";
const $ = id => document.getElementById(id);
async function request(url, options = {}) {
  const response = await fetch(url, {cache:"no-store", ...options});
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : {};
  return {response, data};
}
const form = $("login-form");
if (form) form.addEventListener("submit", async event => {
  event.preventDefault();
  const button = form.querySelector("button"); button.disabled = true;
  $("message").textContent = "";
  try {
    const {response, data} = await request("/api/auth/login", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({username:$("username").value,password:$("password").value})});
    if (response.ok) location.href = "/tienda.html";
    else $("message").textContent = data.message || (response.status === 503 ? "Demasiadas solicitudes. Espera un momento." : "No fue posible iniciar sesi?n.");
  } catch { $("message").textContent = "No se pudo conectar con el servidor."; }
  finally { button.disabled = false; }
});
if ($("logout")) $("logout").addEventListener("click", async () => {
  try { await request("/api/auth/logout", {method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}); location.href = "/"; }
  catch { alert("No se pudo cerrar la sesi?n. Int?ntalo de nuevo."); }
});
async function authenticated(url) {
  const result = await request(url);
  if (result.response.status === 401) { location.href = "/"; return null; }
  if (!result.response.ok) throw new Error("Servicio no disponible");
  return result.data;
}
function row(values) {
  const tr = document.createElement("tr");
  for (const value of values) { const td = document.createElement("td"); td.textContent = value; tr.appendChild(td); }
  return tr;
}
if ($("products")) authenticated("/api/products").then(data => {
  if (!data) return;
  $("total").textContent = data.products.length;
  $("stock").textContent = data.products.reduce((sum,p) => sum + p.stock, 0);
  data.products.forEach(p => $("products").appendChild(row([p.name,p.category,`$${Number(p.price).toLocaleString("es-CO")}`,p.stock])));
}).catch(() => { $("products").appendChild(row(["No se pudo cargar el inventario."])); });
async function refresh() {
  try {
    const data = await authenticated("/api/monitor"); if (!data) return;
    const entries = data.entries;
    $("total").textContent = entries.length;
    for (const [id,status] of [["ok",200],["unauthorized",401],["limited",429],["blocked",503]]) $(id).textContent = entries.filter(e => e.status === status).length;
    const body = $("events"); body.replaceChildren();
    if (!entries.length) body.appendChild(row(["Todav?a no hay solicitudes registradas."]));
    entries.slice(0,100).forEach(e => {
      const tr = row([new Date(e.time).toLocaleTimeString("es-CO"),e.method,e.path,e.ip,e.status]);
      const badge = document.createElement("span"); badge.className = `code ${e.status >= 400 ? "error" : ""}`; badge.textContent = e.status; tr.lastChild.replaceChildren(badge); body.appendChild(tr);
    });
  } catch { $("events").replaceChildren(row(["No se pudo cargar la actividad."])); }
}
if ($("events")) {
  refresh(); setInterval(refresh, 5000); $("refresh").addEventListener("click", refresh);
  $("traffic").addEventListener("click", async () => {
    const button = $("traffic"); button.disabled = true; let next = 0, done = 0, rejected = 0, errors = 0;
    $("traffic-result").textContent = "Enviando solicitudes?";
    async function worker() { while (next < 1000) { next++; try { const r = await fetch("/api/demo/protected",{cache:"no-store"}); if (r.status === 503) rejected++; await r.arrayBuffer(); } catch { errors++; } done++; if (done % 100 === 0) $("traffic-result").textContent = `${done} de 1.000 solicitudes`; } }
    await Promise.all(Array.from({length:20},worker));
    $("traffic-result").textContent = `Finalizado: ${rejected} respuestas 503; ${errors} errores de conexi?n.`; button.disabled = false; refresh();
  });
}
