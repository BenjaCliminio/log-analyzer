from typing import List, Dict
import requests
 
IP_API_BATCH_URL = "http://ip-api.com/batch"
LOTE_MAXIMO = 100  # límite del plan gratuito de ip-api.com por request
 
 
def geolocalizar_ips(ips: List[str], paises_esperados: List[str] = None) -> Dict[str, Dict]:
    """
    Recibe una lista de IPs únicas y devuelve un diccionario
    {ip: {country, countryCode, city, lat, lon, es_pais_inesperado}}.
    Si `paises_esperados` se define (ej. ["AR"]), marca como inesperadas
    las IPs que vengan de otros países - útil para resaltar accesos
    desde geografías no habituales para el negocio.
    """
    resultado = {}
    ips_unicas = list(dict.fromkeys(ips))  # dedupe preservando orden
 
    for i in range(0, len(ips_unicas), LOTE_MAXIMO):
        lote = ips_unicas[i:i + LOTE_MAXIMO]
        payload = [{"query": ip, "fields": "status,message,country,countryCode,city,lat,lon,query"}
                   for ip in lote]
        try:
            resp = requests.post(IP_API_BATCH_URL, json=payload, timeout=15)
            resp.raise_for_status()
            datos = resp.json()
        except Exception as e:
            print(f"[GeoIP] No se pudo geolocalizar el lote de IPs: {e}")
            continue
 
        for entrada in datos:
            if entrada.get("status") != "success":
                continue
            ip = entrada["query"]
            es_inesperado = (
                paises_esperados is not None
                and entrada.get("countryCode") not in paises_esperados
            )
            resultado[ip] = {
                "country": entrada.get("country"),
                "countryCode": entrada.get("countryCode"),
                "city": entrada.get("city"),
                "lat": entrada.get("lat"),
                "lon": entrada.get("lon"),
                "es_pais_inesperado": es_inesperado,
            }
 
    return resultado