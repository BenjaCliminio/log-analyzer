from collections import defaultdict
from datetime import timedelta
from typing import List, Dict
 
 
# ---------------------------------------------------------------------------
# Config por defecto (ajustable al llamar a las funciones)
# ---------------------------------------------------------------------------
 
UMBRAL_FUERZA_BRUTA = 5          # intentos fallidos
VENTANA_FUERZA_BRUTA_SEG = 60    # en esta ventana de tiempo
 
UMBRAL_ESCANEO_RUTAS = 10        # requests con 404
VENTANA_ESCANEO_RUTAS_SEG = 60
 
HORA_INICIO_LABORAL = 8
HORA_FIN_LABORAL = 20
 
USER_AGENTS_SOSPECHOSOS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirb",
    "wpscan", "curl", "wget", "python-requests", "go-http-client",
    "hydra", "nuclei", "zgrab",
]
 
# Patrones de inyección SQL (case-insensitive) sobre ruta/query string
PATRONES_SQLI = [
    r"'\s*or\s*'?1'?\s*=\s*'?1", r"union\s+select", r"select\s+.+\s+from",
    r"drop\s+table", r"--\s", r";\s*--", r"or\s+1\s*=\s*1", r"'\s*;\s*--",
    r"sleep\(\d+\)", r"benchmark\(",
]
 
# Patrones de XSS
PATRONES_XSS = [
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
    r"<img[^>]+src", r"document\.cookie", r"<svg[^>]+onload",
]
 
# Patrones de path traversal (bonus, mismo estilo)
PATRONES_TRAVERSAL = [
    r"\.\./", r"\.\.\\", r"/etc/passwd", r"boot\.ini", r"win\.ini",
]
 
import re
_RE_SQLI = re.compile("|".join(PATRONES_SQLI), re.IGNORECASE)
_RE_XSS = re.compile("|".join(PATRONES_XSS), re.IGNORECASE)
_RE_TRAVERSAL = re.compile("|".join(PATRONES_TRAVERSAL), re.IGNORECASE)
 
 
def _nueva_alerta(tipo, severidad, ip, detalle, evidencia, timestamp=None):
    return {
        "tipo": tipo,
        "severidad": severidad,   # "baja" | "media" | "alta" | "crítica"
        "ip": ip,
        "detalle": detalle,
        "evidencia": evidencia,
        "timestamp": timestamp.isoformat() if timestamp else None,
    }
 
 
# ---------------------------------------------------------------------------
# Detectores sobre logs de autenticación
# ---------------------------------------------------------------------------
 
def detectar_fuerza_bruta(eventos: List[Dict],
                           umbral: int = UMBRAL_FUERZA_BRUTA,
                           ventana_seg: int = VENTANA_FUERZA_BRUTA_SEG) -> List[Dict]:
    """
    Agrupa intentos fallidos de login por IP y busca ráfagas: si hay
    >= umbral fallos dentro de una ventana deslizante de N segundos,
    genera una alerta de fuerza bruta.
    """
    alertas = []
    fallos_por_ip = defaultdict(list)
 
    for ev in eventos:
        if ev["tipo"] == "auth" and not ev["exitoso"] and ev["timestamp"]:
            fallos_por_ip[ev["ip"]].append(ev)
 
    for ip, intentos in fallos_por_ip.items():
        intentos.sort(key=lambda e: e["timestamp"])
        for i in range(len(intentos)):
            ventana = [
                e for e in intentos[i:]
                if e["timestamp"] <= intentos[i]["timestamp"] + timedelta(seconds=ventana_seg)
            ]
            if len(ventana) >= umbral:
                alertas.append(_nueva_alerta(
                    tipo="fuerza_bruta_ssh",
                    severidad="alta",
                    ip=ip,
                    detalle=f"{len(ventana)} intentos fallidos de login en {ventana_seg}s "
                            f"(usuarios probados: {', '.join(sorted(set(e['usuario'] for e in ventana)))[:120]})",
                    evidencia=[e["raw"] for e in ventana[:5]],
                    timestamp=intentos[i]["timestamp"],
                ))
                break  # una alerta por IP alcanza, no repetir por cada sub-ventana
 
    return alertas
 
 
def detectar_horario_anomalo(eventos: List[Dict],
                              hora_inicio: int = HORA_INICIO_LABORAL,
                              hora_fin: int = HORA_FIN_LABORAL) -> List[Dict]:
    """Marca logins EXITOSOS que ocurren fuera del rango horario esperado."""
    alertas = []
    for ev in eventos:
        if ev["tipo"] == "auth" and ev["exitoso"] and ev["timestamp"]:
            hora = ev["timestamp"].hour
            if hora < hora_inicio or hora >= hora_fin:
                alertas.append(_nueva_alerta(
                    tipo="login_horario_anomalo",
                    severidad="media",
                    ip=ev["ip"],
                    detalle=f"Login exitoso de '{ev['usuario']}' a las {ev['timestamp'].strftime('%H:%M')} "
                            f"(fuera del rango habitual {hora_inicio}:00-{hora_fin}:00)",
                    evidencia=[ev["raw"]],
                    timestamp=ev["timestamp"],
                ))
    return alertas
 
 
# ---------------------------------------------------------------------------
# Detectores sobre logs web
# ---------------------------------------------------------------------------
 
def detectar_escaneo_rutas(eventos: List[Dict],
                            umbral: int = UMBRAL_ESCANEO_RUTAS,
                            ventana_seg: int = VENTANA_ESCANEO_RUTAS_SEG) -> List[Dict]:
    """
    Detecta ráfagas de respuestas 404 desde la misma IP: patrón típico de
    herramientas de descubrimiento de rutas/directorios (gobuster, dirb, etc.)
    """
    alertas = []
    notfound_por_ip = defaultdict(list)
 
    for ev in eventos:
        if ev["tipo"] == "web" and ev["status"] == 404 and ev["timestamp"]:
            notfound_por_ip[ev["ip"]].append(ev)
 
    for ip, hits in notfound_por_ip.items():
        hits.sort(key=lambda e: e["timestamp"])
        for i in range(len(hits)):
            ventana = [
                e for e in hits[i:]
                if e["timestamp"] <= hits[i]["timestamp"] + timedelta(seconds=ventana_seg)
            ]
            if len(ventana) >= umbral:
                rutas_ejemplo = ", ".join(sorted(set(e["ruta"] for e in ventana))[:5])
                alertas.append(_nueva_alerta(
                    tipo="escaneo_de_rutas",
                    severidad="alta",
                    ip=ip,
                    detalle=f"{len(ventana)} respuestas 404 en {ventana_seg}s "
                            f"(posible directory busting). Ejemplos: {rutas_ejemplo}",
                    evidencia=[e["raw"] for e in ventana[:5]],
                    timestamp=hits[i]["timestamp"],
                ))
                break
 
    return alertas
 
 
def detectar_user_agents_sospechosos(eventos: List[Dict]) -> List[Dict]:
    alertas = []
    for ev in eventos:
        if ev["tipo"] != "web":
            continue
        ua = (ev.get("user_agent") or "").lower()
        for patron in USER_AGENTS_SOSPECHOSOS:
            if patron in ua:
                alertas.append(_nueva_alerta(
                    tipo="user_agent_sospechoso",
                    severidad="baja",
                    ip=ev["ip"],
                    detalle=f"User-Agent asociado a herramientas automatizadas/ofensivas: '{ev['user_agent']}'",
                    evidencia=[ev["raw"]],
                    timestamp=ev["timestamp"],
                ))
                break
    return alertas
 
 
def detectar_inyecciones(eventos: List[Dict]) -> List[Dict]:
    """
    Busca patrones de SQLi, XSS y path traversal en la ruta/query del
    request. Decodifica URL-encoding primero (%27, %20, etc.) porque en
    tráfico real los ataques casi siempre llegan codificados.
    """
    from urllib.parse import unquote
 
    alertas = []
    for ev in eventos:
        if ev["tipo"] != "web":
            continue
        ruta_original = ev.get("ruta", "")
        ruta = unquote(ruta_original)
 
        if _RE_SQLI.search(ruta):
            alertas.append(_nueva_alerta(
                tipo="posible_sqli",
                severidad="crítica",
                ip=ev["ip"],
                detalle=f"Patrón de SQL Injection detectado en la request: {ruta}",
                evidencia=[ev["raw"]],
                timestamp=ev["timestamp"],
            ))
        if _RE_XSS.search(ruta):
            alertas.append(_nueva_alerta(
                tipo="posible_xss",
                severidad="alta",
                ip=ev["ip"],
                detalle=f"Patrón de Cross-Site Scripting detectado en la request: {ruta}",
                evidencia=[ev["raw"]],
                timestamp=ev["timestamp"],
            ))
        if _RE_TRAVERSAL.search(ruta):
            alertas.append(_nueva_alerta(
                tipo="posible_path_traversal",
                severidad="alta",
                ip=ev["ip"],
                detalle=f"Patrón de Path Traversal detectado en la request: {ruta}",
                evidencia=[ev["raw"]],
                timestamp=ev["timestamp"],
            ))
 
    return alertas
 
 
# ---------------------------------------------------------------------------
# Orquestador
# ---------------------------------------------------------------------------
 
def ejecutar_todos_los_detectores(eventos: List[Dict]) -> List[Dict]:
    alertas = []
    alertas += detectar_fuerza_bruta(eventos)
    alertas += detectar_horario_anomalo(eventos)
    alertas += detectar_escaneo_rutas(eventos)
    alertas += detectar_user_agents_sospechosos(eventos)
    alertas += detectar_inyecciones(eventos)
 
    orden_severidad = {"crítica": 0, "alta": 1, "media": 2, "baja": 3}
    alertas.sort(key=lambda a: orden_severidad.get(a["severidad"], 9))
    return alertas