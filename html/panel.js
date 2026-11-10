"use strict";

const byId = (id) => document.getElementById(id);
const buttons = [...document.querySelectorAll("[data-test]")];
const headerCells = [...document.querySelectorAll("[data-header]")];
const statusNames = { 200: "OK", 403: "Forbidden", 503: "Service Unavailable" };
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let running = false;

function updateCounters(counts, completed, total) {
    for (const key of Object.keys(counts)) {
        byId(`count-${key}`).textContent = counts[key];
        byId(`bar-${key}`).style.width = `${counts[key] / total * 100}%`;
    }
    byId("progress-label").textContent = `${completed} de ${total} completadas`;
    byId("meter").setAttribute("aria-label", `${counts.ok} permitidas, ${counts.denied} rechazadas, ${counts.other} con otros códigos y ${counts.error} errores. ${completed} de ${total} completadas.`);
    byId("log-count").textContent = `(${completed})`;
}

function showHeaders(headers, status) {
    let found = 0;
    for (const cell of headerCells) {
        const value = headers.get(cell.dataset.header);
        cell.textContent = value || "No recibida";
        if (value !== null) found++;
    }
    byId("audit-summary").textContent = `${found} de ${headerCells.length} cabeceras recibidas en una respuesta HTTP ${status}. Puedes leer sus valores en la tabla.`;
}

async function request(method, index, runId) {
    const start = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
        // Siempre el mismo origen. La consulta única evita reutilizar una respuesta en caché.
        const response = await fetch(`/?lab=${runId}-${index}`, {
            method, cache: "no-store", signal: controller.signal
        });
        const body = await response.text();
        return { index, method, status: response.status, headers: response.headers, body, ms: Math.round(performance.now() - start) };
    } catch (error) {
        return { index, method, status: 0, reason: error.name === "AbortError" ? "Espera agotada (5 s)" : "Sin conexión", ms: Math.round(performance.now() - start) };
    } finally {
        clearTimeout(timeout);
    }
}

function addLog(result) {
    const row = document.createElement("tr");
    const values = [result.index, result.method, result.status ? `${result.status} ${statusNames[result.status] || ""}` : result.reason, `${result.ms} ms`];
    for (const value of values) {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
    }
    row.children[2].className = result.status >= 200 && result.status < 300 ? "response-ok" : [403, 503].includes(result.status) ? "response-denied" : "response-other";
    byId("request-log").appendChild(row);
}

function explain(type, results) {
    const statuses = results.map((result) => result.status);
    if (statuses.every((status) => status === 0)) return "No se recibió respuesta. Comprueba que Docker y Nginx estén en ejecución y abre http://localhost, en lugar de abrir el archivo HTML directamente.";
    if (type === "normal") return statuses[0] === 200 ? "200 OK: Nginx permitió la consulta. Revisa debajo las cabeceras reales de esta respuesta." : `Se recibió HTTP ${statuses[0]}. Si aparece 503, espera unos segundos: otras peticiones de tu IP también consumen el límite.`;
    if (type === "method") return statuses[0] === 403 ? "403 Forbidden: Nginx rechazó POST porque esta ruta solo permite GET y HEAD. La restricción se aplica en el servidor." : `Se recibió HTTP ${statuses[0]}, en lugar del 403 esperado. Revisa la configuración y los registros de Nginx.`;
    const rejected = statuses.filter((status) => status === 503).length;
    return rejected ? `Nginx respondió 503 a ${rejected} de las 40 solicitudes. La ráfaga superó los límites del laboratorio; el panel sigue abierto para analizar los resultados.` : "La ráfaga terminó sin respuestas 503. Si el navegador o la red espaciaron las solicitudes, quizá no superaron el límite. Consulta el registro y la configuración de Nginx.";
}

async function runTest(type) {
    if (running) return;
    running = true;
    buttons.forEach((button) => { button.disabled = true; });
    byId("response-preview").hidden = true;
    byId("error-preview").removeAttribute("srcdoc");
    byId("request-log").replaceChildren();
    byId("test-note").textContent = "Enviando peticiones reales a este servidor…";
    byId("audit-summary").textContent = "Comprobando las cabeceras de esta prueba…";
    headerCells.forEach((cell) => { cell.textContent = "Comprobando…"; });
    const total = type === "burst" ? 40 : 1;
    const method = type === "method" ? "POST" : "GET";
    const counts = { ok: 0, denied: 0, other: 0, error: 0 };
    const results = [];
    const runId = Date.now();
    let next = 0;
    let previewShown = false;
    updateCounters(counts, 0, total);
    byId("test-message").textContent = type === "burst" ? "Enviando 40 consultas, con un máximo de 6 en paralelo…" : `Enviando una petición ${method}…`;
    byId("result-title").scrollIntoView({ block: "start" });
    const started = performance.now();

    async function worker() {
        while (next < total) {
            const result = await request(method, ++next, runId);
            results.push(result);
            const group = result.status === 0 ? "error" : result.status >= 200 && result.status < 300 ? "ok" : [403, 503].includes(result.status) ? "denied" : "other";
            counts[group]++;
            addLog(result);
            updateCounters(counts, results.length, total);
            if (result.headers) {
                showHeaders(result.headers, result.status);
                byId("connection").textContent = "Servidor con respuesta HTTP";
                byId("connection").classList.add("connected");
            }
            if (result.status === 503 && !previewShown) {
                // Se muestra el HTML que Nginx devolvió, sin ejecutar scripts ni pedir otra página.
                byId("error-preview").srcdoc = result.body;
                byId("response-preview").hidden = false;
                previewShown = true;
            }
        }
    }

    try {
        await Promise.all(Array.from({ length: Math.min(6, total) }, worker));
        byId("test-message").textContent = explain(type, results);
        const elapsed = ((performance.now() - started) / 1000).toFixed(2);
        const failures = counts.error ? ` ${counts.error} solicitudes no recibieron respuesta HTTP.` : "";
        const measurement = `Última prueba: ${results.length} ${total === 1 ? "solicitud" : "solicitudes"} en ${elapsed} s.${failures} Los resultados dependen del ritmo de envío y del tráfico de tu IP.`;
        if (counts.error === total) {
            byId("connection").textContent = "Sin respuesta del servidor";
            byId("connection").classList.remove("connected");
            byId("audit-summary").textContent = "No se recibieron cabeceras en esta prueba.";
            headerCells.forEach((cell) => { cell.textContent = "Sin respuesta"; });
        }
        // El bucket de 10 a 5 r/s se recupera en unos 2 s sin tráfico adicional.
        for (let seconds = 3; seconds > 0; seconds--) {
            byId("test-note").textContent = `${measurement} Próxima prueba disponible en ${seconds} s.`;
            await wait(1000);
        }
        byId("test-note").textContent = `${measurement} Puedes ejecutar otra prueba.`;
    } catch {
        byId("test-message").textContent = "No se pudo completar la prueba. Recarga el panel y comprueba los registros del servidor.";
    } finally {
        running = false;
        buttons.forEach((button) => { button.disabled = false; });
    }
}

if (["http:", "https:"].includes(location.protocol)) {
    buttons.forEach((button) => {
        button.disabled = false;
        button.addEventListener("click", () => runTest(button.dataset.test));
    });
} else {
    byId("test-message").textContent = "Abre http://localhost con el laboratorio Docker encendido. Abrir index.html directamente no permite probar las defensas de Nginx.";
    byId("connection").textContent = "Abrir desde Nginx";
}
