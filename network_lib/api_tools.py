import requests
import socket
from urllib.parse import urlparse
from typing import Optional


def fetch_json(url: str, timeout: int = 5) -> Optional[dict]:
    """
    Realiza una petición HTTP GET a la URL indicada y retorna
    el contenido en formato JSON si:

    - El código de estado es 200.
    - El servidor indica que el contenido es JSON.

    Si ocurre un error de conexión, timeout, o la respuesta
    no es JSON válido, retorna None.
    """
    try:
        response = requests.get(url, timeout=timeout)

        # Verificamos código HTTP
        if response.status_code != 200:
            return None

        # Verificamos que el servidor realmente esté enviando JSON
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' not in content_type:
            return None

        return response.json()

    except (requests.RequestException, ValueError):
        # RequestException cubre errores de red
        # ValueError cubre errores al decodificar JSON
        return None


def extract_host(target: str) -> str:
    """
    Recibe una URL o un dominio y devuelve únicamente el hostname.

    Si el usuario no incluye el esquema (http/https), se agrega
    automáticamente para que urlparse pueda interpretarlo
    correctamente.
    """
    if '://' not in target:
        target = 'http://' + target

    parsed = urlparse(target)
    return parsed.hostname


def resolve_host_ips(host: str) -> list:
    """
    Devuelve una lista ordenada de direcciones IP asociadas
    a un host, sin valores repetidos.

    Utiliza la librería estándar socket y no depende
    de APIs externas.

    Si ocurre un error de resolución DNS, retorna una lista vacía.
    """
    ips = set()
    host = extract_host(host)
    try:
        info = socket.getaddrinfo(host, None)
        for entry in info:
            ip = entry[4][0]
            ips.add(ip)
    except socket.gaierror:
        return []

    return sorted(ips)


def get_ip_info(ip: str) -> dict:
    """
    Consulta la API pública freeipapi para obtener información
    asociada a una dirección IP pública.

    Retorna un diccionario con los datos en formato JSON
    o None si la consulta falla.
    """
    url = f"https://free.freeipapi.com/api/json/{ip}"
    return fetch_json(url)
