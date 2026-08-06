# log-analyzer

Detector de anomalías en logs de autenticación (SSH) y logs web
(Apache/Nginx), pensado como herramienta de **blue team** para
complementar proyectos ofensivos de un portfolio de ciberseguridad.

Parsea logs, aplica un set de reglas de detección, geolocaliza las
IPs sospechosas y genera un reporte JSON + un mapa interactivo con
los orígenes de los ataques.

## Qué detecta

| Detección | Fuente | Descripción |
|---|---|---|
| Fuerza bruta SSH | `auth.log` | Ráfagas de intentos fallidos de login desde la misma IP en una ventana de tiempo corta |
| Login en horario anómalo | `auth.log` | Logins **exitosos** fuera del rango horario configurado (por defecto 8:00-20:00) |
| Escaneo de rutas / directory busting | `access.log` | Ráfagas de respuestas 404 desde la misma IP (patrón típico de gobuster/dirb/dirbuster) |
| User-Agents sospechosos | `access.log` | Requests hechos con herramientas como sqlmap, nikto, nmap, gobuster, hydra, curl, etc. |
| SQL Injection | `access.log` | Patrones de inyección SQL en la ruta/query, con decodificación de URL-encoding previa |
| Cross-Site Scripting (XSS) | `access.log` | Patrones de XSS reflejado en la ruta/query |
| Path Traversal | `access.log` | Intentos de acceso a archivos fuera del directorio raíz (`../../etc/passwd`, etc.) |
| Geolocalización de IPs sospechosas | Ambos | Marca como "país inesperado" cualquier IP alertada que no venga de los países configurados |

## Instalación

```bash
git clone <tu-repo>
cd log-analyzer
pip install -r requirements.txt
```

## Uso

```bash
# Analiza uno o más logs, autodetectando el formato de cada uno
python3 analyzer.py sample_logs/auth.log sample_logs/access.log

# Sin consultar geolocalización (más rápido, sin llamadas de red)
python3 analyzer.py sample_logs/auth.log --sin-geoip

# Ajustando qué países se consideran "esperados" (para no marcar
# como anómalo todo el tráfico legítimo desde otro país)
python3 analyzer.py sample_logs/access.log --paises-esperados AR UY
```

El repo incluye logs de muestra **sintéticos** en `sample_logs/` con
tráfico normal mezclado con patrones de ataque simulados, para poder
probar la herramienta sin necesitar logs reales.

### Salida

- Resumen en consola, ordenado por severidad (crítica → alta → media → baja)
- `reporte_alertas.json` — todas las alertas + datos de geolocalización, en formato estructurado
- `mapa_alertas.html` — mapa interactivo con las IPs sospechosas ubicadas geográficamente (rojo = país inesperado, naranja = país esperado pero con actividad sospechosa)

## Diseño técnico

El proyecto está separado en módulos para mantener responsabilidades
claras:

```
log_analyzer/
├── parsers.py    # convierte líneas de log crudas en eventos estructurados
├── detectors.py  # reglas de detección sobre los eventos ya parseados
├── geoip.py      # geolocalización en lote de IPs sospechosas (ip-api.com)
└── report.py     # salida en consola, JSON y mapa HTML
analyzer.py       # CLI que orquesta todo el pipeline
```

Este diseño permite, por ejemplo, agregar un nuevo tipo de log
(escribiendo solo un parser nuevo) o una nueva regla de detección
(agregando una función en `detectors.py`) sin tocar el resto del
código.

## Notas sobre los proveedores externos

La geolocalización usa el endpoint batch de
[ip-api.com](https://ip-api.com/) (gratuito, hasta 100 IPs por
request, sin API key), consultado **solo sobre las IPs ya marcadas
como sospechosas** — no sobre todo el tráfico — para no agotar el
límite de requests gratuito innecesariamente.

## Limitaciones conocidas

- Los parsers cubren los formatos más comunes (auth.log estilo
  syslog para SSH, Combined Log Format para Apache/Nginx). Logs con
  formato distinto (JSON logs, Windows Event Log, etc.) requerirían
  un parser adicional.
- Los umbrales de detección (intentos de fuerza bruta, cantidad de
  404s, ventana de tiempo) son configurables por parámetro pero
  vienen con valores por defecto pensados para tráfico de ejemplo,
  no ajustados a un entorno productivo real.
- Las reglas de SQLi/XSS/Path Traversal son detección **basada en
  patrones** (no un WAF completo): cubren los casos más comunes,
  pero técnicas de evasión avanzadas podrían no ser detectadas.

