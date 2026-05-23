import socket
import time
import errno


# Puertos TCP comunes
COMMON_TCP_PORTS = [
    # --- Acceso remoto ---
    22,    # SSH
    23,    # Telnet (inseguro / heredado)
    3389,  # RDP (acceso remoto Windows)

    # --- Servicios web ---
    80,    # HTTP
    443,   # HTTPS
    8080,  # HTTP alternativo / proxies

    # --- Correo ---
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    587,   # SMTP submission / STARTTLS
    993,   # IMAPS
    995,   # POP3S

    # --- DNS ---
    53,    # DNS (TCP)

    # --- Servicios de archivos ---
    21,    # FTP (control)
    20,    # FTP (data)
    445,   # SMB
    139,   # NetBIOS Session Service

    # --- Bases de datos ---
    1433,  # MSSQL
    1521,  # Oracle
    3306,  # MySQL / MariaDB
    5432,  # PostgreSQL
    27017  # MongoDB
]


def scan_port(host: str, port: int, timeout: int = 1) -> dict:
    """
    Escanea un solo puerto TCP usando connect_ex().

    Retorna un diccionario con:
    - host
    - port
    - port_result: 'ok' | 'error' (ejecución del escaneo)
    - port_status: 'open' | 'closed' | 'filtered' | 'unknown' (estado lógico)
    - time_ms: float | None
    - errors: str
    """
    # Validaciones básicas de entrada
    if not host or not isinstance(port, int) or not 1 <= port <= 65535:
        return {
            'host': host,
            'port': port,
            'port_result': 'error',
            'port_status': 'unknown',
            'time_ms': None,
            'errors': 'Host o puerto inválido.'
        }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        t0 = time.perf_counter()
        code = sock.connect_ex((host, port))
        t1 = time.perf_counter()
        time_ms = round((t1 - t0) * 1000, 2)

    except socket.gaierror:
        return {
            'host': host,
            'port': port,
            'port_result': 'error',
            'port_status': 'unknown',
            'time_ms': None,
            'errors': 'Fallo en la resolución DNS'
        }

    except OSError as e:
        return {
            'host': host,
            'port': port,
            'port_result': 'error',
            'port_status': 'unknown',
            'time_ms': None,
            'errors': str(e)
        }

    finally:
        sock.close()

    if code == 0:
        return {
            'host': host,
            'port': port,
            'port_result': 'ok',
            'port_status': 'open',
            'time_ms': time_ms,
            'errors': ''
        }

    if code in (errno.ECONNREFUSED, 10061):
        return {
            'host': host,
            'port': port,
            'port_result': 'ok',
            'port_status': 'closed',
            'time_ms': time_ms,
            'errors': ''
        }

    # Timeouts y casos típicos de filtrado o inaccesibilidad de red
    if code in (
            errno.EAGAIN,  # 11  (Linux: would block)
            errno.EWOULDBLOCK,  # same as EAGAIN
            errno.ETIMEDOUT,  # 110
            errno.EHOSTUNREACH,  # 113
            errno.ENETUNREACH,  # 101
            10035,  # Windows: WSAEWOULDBLOCK
            10060,  # Windows: WSAETIMEDOUT
            10051,  # Windows: WSAENETUNREACH
            10065  # Windows: WSAEHOSTUNREACH
    ):
        return {
            'host': host,
            'port': port,
            'port_result': 'ok',
            'port_status': 'filtered',
            'time_ms': time_ms,
            'errors': ''
        }

    # Cualquier otro código queda como unknown
    return {
        'host': host,
        'port': port,
        'port_result': 'ok',
        'port_status': 'unknown',
        'time_ms': time_ms,
        'errors': f'connect_ex code={code}'
    }


def scan_ports(host: str, ports: list, timeout: int = 1) -> dict:
    """
    Escanea múltiples puertos TCP en un host.

    Retorna un diccionario con:
    - host
    - scan_result: ok | error
    - scan_status: unknown
                   at_least_one_open_port
                   all_closed
                   all_filtered
                   mixed_non_open_states
    - results: lista de resultados individuales (scan_port)
    - errors: str
    """
    # Validmos port_list
    try:
        port_list = list(ports)
    except TypeError:
        return {
            'host': host,
            'scan_result': 'error',
            'scan_status': 'unknown',
            'results': [],
            'errors': 'La lista de puertos no es válida'
        }

    results = []
    for p in port_list:
        results.append(scan_port(host, p, timeout=timeout))

    if not results:
        return {
            'host': host,
            'scan_result': 'error',
            'scan_status': 'unknown',
            'results': [],
            'errors': 'No se pudo escanear los puertos'
        }

    # Determinamos el resultado global
    valid = [r for r in results if r['port_result'] == 'ok']
    statuses = {r['port_status'] for r in valid}
    all_closed = statuses == {'closed'}
    all_filtered = statuses == {'filtered'}

    if not valid:
        scan_status = 'unknown'
    elif 'open' in statuses:
        scan_status = 'at_least_one_open_port'
    elif all_closed:
        scan_status = 'all_closed'
    elif all_filtered:
        scan_status = 'all_filtered'
    else:
        scan_status = 'mixed_non_open_states'
    scan_result = 'ok' if valid else 'error'

    # Construimos un mensaje compacto de errores
    err_list = list(set([r['errors'] for r in results if r['errors']]))
    errors = ' || '.join(err_list[:10])

    return {
        'host': host,
        'scan_result': scan_result,
        'scan_status': scan_status,
        'results': results,
        'errors': errors
    }
