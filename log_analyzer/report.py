import json
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict
 
 
def imprimir_resumen(alertas: List[Dict]):
    print("\n" + "=" * 70)
    print(" RESUMEN DE ALERTAS")
    print("=" * 70)
 
    if not alertas:
        print(" No se detectaron anomalías en los logs analizados.")
        print("=" * 70)
        return
 
    conteo = Counter(a["tipo"] for a in alertas)
    for tipo, cantidad in conteo.most_common():
        print(f"  {tipo:<28} {cantidad}")
 
    print("-" * 70)
    print(f" Total de alertas: {len(alertas)}")
    print("=" * 70)
 
    print("\n Detalle (ordenado por severidad):\n")
    for a in alertas:
        marca = {"crítica": "[CRIT]", "alta": "[ALTA]", "media": "[MEDIA]", "baja": "[BAJA]"}.get(a["severidad"], "[?]")
        print(f" {marca} {a['tipo']:<25} IP: {a['ip']:<15} {a['detalle']}")
 
 
def guardar_json(alertas: List[Dict], geo_info: Dict, ruta_salida: str):
    reporte = {
        "generado": datetime.now(timezone.utc).isoformat(),
        "total_alertas": len(alertas),
        "alertas": alertas,
        "geolocalizacion_ips": geo_info,
    }
    with open(ruta_salida, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)
    print(f"\n[Reporte] JSON guardado en {ruta_salida}")
 
 
def generar_mapa(geo_info: Dict, alertas: List[Dict], ruta_salida: str):
    try:
        import folium
    except ImportError:
        print("[Mapa] Falta la librería 'folium'. Instalá con: pip install folium")
        return
 
    ips_con_coords = {ip: info for ip, info in geo_info.items()
                       if info.get("lat") is not None and info.get("lon") is not None}
 
    if not ips_con_coords:
        print("[Mapa] No hay IPs geolocalizadas para mostrar en el mapa.")
        return
 
    # Centrar el mapa en el promedio de coordenadas
    lat_prom = sum(i["lat"] for i in ips_con_coords.values()) / len(ips_con_coords)
    lon_prom = sum(i["lon"] for i in ips_con_coords.values()) / len(ips_con_coords)
    mapa = folium.Map(location=[lat_prom, lon_prom], zoom_start=2)
 
    alertas_por_ip = {}
    for a in alertas:
        alertas_por_ip.setdefault(a["ip"], []).append(a)
 
    for ip, info in ips_con_coords.items():
        tipos = sorted(set(a["tipo"] for a in alertas_por_ip.get(ip, [])))
        color = "red" if info.get("es_pais_inesperado") else "orange"
        popup = (
            f"<b>{ip}</b><br>"
            f"{info.get('city', '?')}, {info.get('country', '?')}<br>"
            f"Alertas: {', '.join(tipos) if tipos else 'N/D'}"
        )
        folium.Marker(
            [info["lat"], info["lon"]],
            popup=popup,
            tooltip=ip,
            icon=folium.Icon(color=color, icon="warning-sign"),
        ).add_to(mapa)
 
    mapa.save(ruta_salida)
    print(f"[Mapa] Guardado en {ruta_salida} (abrilo en un navegador)")