import re
from datetime import datetime
from typing import Optional, List, Dict
 
# ---------------------------------------------------------------------------
# Auth log (SSH) - formato típico de syslog
# ---------------------------------------------------------------------------
# Ej:
# Aug  5 10:15:32 server sshd[1234]: Failed password for invalid user admin \
#     from 203.0.113.5 port 51234 ssh2
# Aug  5 10:15:35 server sshd[1234]: Accepted password for root \
#     from 203.0.113.5 port 51235 ssh2
 
AUTH_LINE_RE = re.compile(
    r"^(?P<mes_dia>\w{3}\s+\d{1,2})\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<resultado>Failed password|Accepted password)\s+"
    r"(?:for\s+(?:invalid user\s+)?(?P<usuario>\S+)\s+)?"
    r"from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<puerto>\d+)"
)
 
 
def parsear_auth_log(lineas: List[str], año_actual: int = None) -> List[Dict]:
    """Convierte líneas de un auth.log en eventos estructurados de login."""
    if año_actual is None:
        año_actual = datetime.now().year
 
    eventos = []
    for linea in lineas:
        match = AUTH_LINE_RE.search(linea)
        if not match:
            continue
 
        datos = match.groupdict()
        try:
            fecha_str = f"{datos['mes_dia']} {año_actual} {datos['hora']}"
            timestamp = datetime.strptime(fecha_str, "%b %d %Y %H:%M:%S")
        except ValueError:
            timestamp = None
 
        eventos.append({
            "tipo": "auth",
            "timestamp": timestamp,
            "ip": datos["ip"],
            "usuario": datos.get("usuario") or "desconocido",
            "exitoso": datos["resultado"] == "Accepted password",
            "raw": linea.strip(),
        })
 
    return eventos
 
 
# ---------------------------------------------------------------------------
# Web log - Combined Log Format (Apache/Nginx)
# ---------------------------------------------------------------------------
# Ej:
# 127.0.0.1 - - [05/Aug/2026:10:15:32 +0000] "GET /wp-login.php HTTP/1.1" \
#     404 512 "-" "curl/7.68.0"
 
WEB_LINE_RE = re.compile(
    r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+'
    r'\[(?P<fecha>[^\]]+)\]\s+'
    r'"(?P<metodo>[A-Z]+)\s+(?P<ruta>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<tamaño>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)
 
 
def parsear_web_log(lineas: List[str]) -> List[Dict]:
    """Convierte líneas de un access.log (Combined Log Format) en eventos."""
    eventos = []
    for linea in lineas:
        match = WEB_LINE_RE.search(linea)
        if not match:
            continue
 
        datos = match.groupdict()
        try:
            timestamp = datetime.strptime(datos["fecha"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            timestamp = None
 
        eventos.append({
            "tipo": "web",
            "timestamp": timestamp,
            "ip": datos["ip"],
            "metodo": datos["metodo"],
            "ruta": datos["ruta"],
            "status": int(datos["status"]),
            "user_agent": datos["user_agent"],
            "raw": linea.strip(),
        })
 
    return eventos
 
 
def detectar_formato(lineas: List[str]) -> Optional[str]:
    """Heurística simple para detectar si un archivo es auth log o web log."""
    for linea in lineas[:20]:
        if AUTH_LINE_RE.search(linea):
            return "auth"
        if WEB_LINE_RE.search(linea):
            return "web"
    return None