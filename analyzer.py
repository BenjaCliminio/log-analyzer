import argparse
import sys
from pathlib import Path
 
from log_analyzer.parsers import parsear_auth_log, parsear_web_log, detectar_formato
from log_analyzer.detectors import ejecutar_todos_los_detectores
from log_analyzer.geoip import geolocalizar_ips
from log_analyzer.report import imprimir_resumen, guardar_json, generar_mapa
 
 
def leer_lineas(ruta: str) -> list:
    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()
 
 
def analizar_archivo(ruta: str, formato_forzado: str = None) -> list:
    lineas = leer_lineas(ruta)
    formato = formato_forzado or detectar_formato(lineas)
 
    if formato == "auth":
        print(f"[+] '{ruta}' detectado como log de autenticación ({len(lineas)} líneas)")
        return parsear_auth_log(lineas)
    elif formato == "web":
        print(f"[+] '{ruta}' detectado como log web ({len(lineas)} líneas)")
        return parsear_web_log(lineas)
    else:
        print(f"[!] No se pudo determinar el formato de '{ruta}'. Se omite.")
        return []
 
 
def main():
    parser = argparse.ArgumentParser(
        description="Detector de anomalías en logs de autenticación y web."
    )
    parser.add_argument(
        "archivos", nargs="+",
        help="Uno o más archivos de log a analizar (auth.log, access.log, etc.)"
    )
    parser.add_argument(
        "--formato", choices=["auth", "web"], default=None,
        help="Forzar el formato de TODOS los archivos pasados (por defecto se autodetecta cada uno)"
    )
    parser.add_argument(
        "--sin-geoip", action="store_true",
        help="No consultar geolocalización de IPs (más rápido, sin llamadas de red)"
    )
    parser.add_argument(
        "--paises-esperados", nargs="*", default=["AR"],
        help="Códigos de país (ISO) esperados para el tráfico legítimo. Ej: --paises-esperados AR UY"
    )
    parser.add_argument(
        "--salida-json", default="reporte_alertas.json",
        help="Ruta del reporte JSON de salida"
    )
    parser.add_argument(
        "--salida-mapa", default="mapa_alertas.html",
        help="Ruta del mapa HTML de salida"
    )
    args = parser.parse_args()
 
    todos_los_eventos = []
    for ruta in args.archivos:
        if not Path(ruta).is_file():
            print(f"[!] Archivo no encontrado: {ruta}")
            continue
        todos_los_eventos += analizar_archivo(ruta, args.formato)
 
    if not todos_los_eventos:
        print("\nNo se pudo parsear ningún evento de los archivos indicados.")
        sys.exit(1)
 
    print(f"\n[+] Total de eventos parseados: {len(todos_los_eventos)}")
    print("[+] Ejecutando detectores...")
    alertas = ejecutar_todos_los_detectores(todos_los_eventos)
 
    geo_info = {}
    if alertas and not args.sin_geoip:
        ips_sospechosas = [a["ip"] for a in alertas]
        print(f"[+] Geolocalizando {len(set(ips_sospechosas))} IP(s) única(s) marcada(s)...")
        geo_info = geolocalizar_ips(ips_sospechosas, paises_esperados=args.paises_esperados)
 
    imprimir_resumen(alertas)
    guardar_json(alertas, geo_info, args.salida_json)
    if geo_info:
        generar_mapa(geo_info, alertas, args.salida_mapa)
 
 
if __name__ == "__main__":
    main()