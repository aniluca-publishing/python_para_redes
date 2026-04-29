import subprocess
import re
from .system_tools import get_os
from typing import Optional


IPV4_RE = re.compile(r'\b(\d+\.\d+\.\d+\.\d+)\b')
RTT_RE = re.compile(r'(\d+(?:\.\d+)?)\s*ms', re.I)


def get_ping_loss(os_name: str, ping_output: str) -> Optional[float]:
    """Retorna la pérdida porcentual de paquetes (float) o None
    - Windows: (X% loss|perdidos)  -> captura X
    - Linux/macOS: (X% packet loss)  -> captura X
    """
    if not ping_output:
        return None

    if os_name == 'windows':
        pattern = r"""
        \(                 # Paréntesis   
        \s*                # Espacios
        ([.\d]+)%          # Valor de pérdida
        \s*                # Espacios
        (?:loss|perdidos)  # Palabras claves
        \s*                # Espacios 
        \)                 # Paréntesis        
        """
        m = re.search(pattern, ping_output, re.I | re.X)
    else:
        pattern = r"""
        \s*               # Espacios
        ([.\d]+)%         # Valor de pérdida
        \s*               # Espacios
        packet\s+loss     # Palabras claves
        """
        m = re.search(pattern, ping_output, re.I | re.X)

    if not m:
        return None

    try:
        return float(m.group(1))
    except ValueError:
        return None


def get_ping_rtt(os_name: str, ping_output: str) -> Optional[float]:
    """
    Retorna RTT promedio (avg) en ms (float) o None.
    - Windows:
      Average/Media = Xms   -> captura X
    - Linux/macOS:
      min/avg/max/(mdev|stddev) = a/b/c/d ms  -> captura b
    """
    if not ping_output:
        return None

    if os_name == 'windows':
        pattern = r"""
        (?:Average|Media)  # Palabras claves
        \s*                # Espacios  
        =                  # Símbolo igual
        \s*                # Espacios
        ([.\d]+)           # Valor de RTT
        \s*                # Espacios
        ms                 # Palabra clave
        """
        m = re.search(pattern, ping_output, re.I | re.X)
    else:
        pattern = r"""
        (?:min/avg/max/(?:mdev|stddev))  # Palabras claves
        \s*                              # Espacios  
        =                                # Símbolo igual
        \s*                              # Espacios  
        [.\d]+                           # Valor min
        /                                # Símbolo slash
        ([.\d]+)                         # Valor avg
        /                                # Símbolo slash
        [.\d]+                           # Valor max
        /                                # Símbolo slash
        \s*                              # Espacios
        [.\d]+                           # Valor de stdev
        \s*                              # Espacios
        ms                               # Palabra clave
        """
        m = re.search(pattern, ping_output, re.I | re.X)

    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def execute_ping(host: str, count: int = 4) -> dict:
    """
    Ejecuta ping al host indicado y extrae:
    - host_status: up/down/unknown
    - loss: % (float)
    - rtt: ms promedio (float)
    """

    # Validar sistema operativo
    os_name = get_os()
    if not os_name:
        return {
            'host': host,
            'ping_result': 'error',
            'host_status': None,
            'loss': None,
            'rtt': None,
            'output': None,
            'errors': 'Error al detectar el sistema operativo.'
        }

    # Construcción del comando según el sistema
    if os_name == 'windows':
        cmd = ['ping', '-n', str(count), host]
    else:
        cmd = ['ping', '-c', str(count), host]

    # Ejecución del ping con subprocess
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        return {
            'host': host,
            'ping_result': 'error',
            'host_status': None,
            'loss': None,
            'rtt': None,
            'output': None,
            'errors': str(e)
        }

    # Procesamos la salida del comando ping
    ping_output = (proc.stdout or '').strip()
    stderr = (proc.stderr or '').strip()
    ping_errors = stderr.replace('\n', ' || ') if stderr else ''
    loss = get_ping_loss(os_name, ping_output)
    rtt = get_ping_rtt(os_name, ping_output)
    if not ping_errors:
        if loss is None and rtt is None:
            ping_errors = 'No se pudo extraer las pérdidas ni el RTT'
        elif rtt is None:
            ping_errors = 'No se pudo extraer el RTT'
        elif loss is None:
            ping_errors = 'No se pudo extraer las pérdidas'

    # Definimos el estado del host
    if loss is not None and loss < 100 and rtt is not None:
        host_status = 'up'
    elif loss == 100:
        host_status = 'down'
    else:
        host_status = 'unknown'

    # Definimos el resultado del ping
    returncode = proc.returncode
    if loss is not None and rtt is not None:
        if loss == 0:
            ping_result = 'ok'
        elif loss < 100:
            ping_result = 'degraded'
        else:
            ping_result = 'error'
    else:
        ping_result = 'error'
    # El returncode se conserva solo como información adicional
    if returncode != 0:
        if ping_errors:
            ping_errors = (ping_errors
                           + ' || '
                           + f'ping returncode={returncode}')

    # Retornamos un diccionario
    return {
        'host': host,
        'ping_result': ping_result,
        'host_status': host_status,
        'loss': loss,
        'rtt': rtt,
        'output': ping_output,
        'errors': ping_errors.strip()
    }


def get_traceroute_hops(traceroute_output: str,
                        probes_per_hop: int = 3) -> list:
    """
    Analiza salida de traceroute/tracert en modo numérico (sin DNS).
    Extrae:
      - hop_number
      - hop_ips (lista única de IPs vistas en ese hop)
      - hop_result: 'ok' | 'no answer'
      - hop_loss (0..100)
      - hop_avg_rtt (float o None)
    """
    hops = []

    for line in traceroute_output.splitlines():
        # Solo líneas que empiezan con número de salto
        m = re.match(r'^\s*(\d+)\s+', line)
        if not m:
            continue

        hop_number = int(m.group(1))

        # Contamos timeouts por asteriscos
        timeouts = line.count('*')

        # IPs encontradas (modo -n / -d)
        ips = sorted(set(IPV4_RE.findall(line)))

        # RTTs encontrados (solo números)
        rtts = [float(x) for x in RTT_RE.findall(line)]

        # Si no hay IPs y tampoco RTTs, asumimos "no answer"
        # (típico: "* * *" con texto adicional según SO/idioma)
        if not ips and not rtts and timeouts >= probes_per_hop:
            hops.append({
                'hop_number': hop_number,
                'hop_ips': [],
                'hop_result': 'no answer',
                'hop_loss': 100,
                'hop_avg_rtt': None
            })
            continue

        # Pérdida estimada según probes (default 3)
        loss = round((timeouts / probes_per_hop) * 100, 2)
        if loss > 100:
            loss = 100.0

        # Calculamos el RTT promedio:
        avg_rtt = None
        if rtts:
            avg_rtt = (sum(rtts) / len(rtts))
            avg_rtt = round(avg_rtt, 2)

        hops.append({
            'hop_number': hop_number,
            'hop_ips': ips,
            'hop_result': 'ok',
            'hop_loss': loss,
            'hop_avg_rtt': avg_rtt
        })

    return hops


def execute_traceroute(host: str, max_hops: int = 30,
                       timeout_seconds: int = 60,
                       probes_per_hop: int = 3) -> dict:
    """
    Ejecuta traceroute/tracert al host indicado y extrae:
    - traceroute_result: ok/error (ejecución del comando)
    - trace_status: ok/no response/unknown (estado lógico según hops)
    - hops: lista de saltos (dicts)
    """

    # Validar sistema operativo
    os_name = get_os()
    if not os_name:
        return {
            'host': host,
            'traceroute_result': 'error',
            'trace_status': 'unknown',
            'hops': None,
            'output': None,
            'errors': 'Error al detectar el sistema operativo'
        }

    # Siempre sin DNS
    if os_name == 'windows':
        cmd = ['tracert', '-d', '-h', str(max_hops), host]
    else:
        cmd = ['traceroute', '-n', '-m', str(max_hops), host]

    # Ejecutar comando
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds
        )
    except Exception as e:
        return {
            'host': host,
            'traceroute_result': 'error',
            'trace_status': 'unknown',
            'hops': None,
            'output': None,
            'errors': str(e)
        }

    output = (proc.stdout or '').strip()
    stderr = (proc.stderr or '').strip()
    errors = stderr.replace('\n', ' || ') if stderr else ''

    hops = get_traceroute_hops(output, probes_per_hop=probes_per_hop)

    # Construir errors si stderr está vacío, igual que en ping
    if not errors:
        if not output:
            errors = 'No hubo salida del comando'
        elif not hops:
            errors = 'No se pudo extraer saltos del traceroute'
        elif all(h['hop_result'] == 'no answer' for h in hops):
            errors = 'Todos los saltos sin respuesta'

    # Estado lógico (similar a host_status en ping)
    if hops and any(h['hop_result'] == 'ok' for h in hops):
        trace_status = 'ok'
    elif hops and all(h['hop_result'] == 'no answer' for h in hops):
        trace_status = 'no response'
    else:
        trace_status = 'unknown'

    # Definimos el resultado del traceroute
    returncode = proc.returncode
    trace_result = 'error' if returncode != 0 else 'ok'
    if returncode != 0 and not errors:
        errors = f'traceroute returncode={returncode}'

    return {
        'host': host,
        'traceroute_result': trace_result,
        'trace_status': trace_status,
        'hops': hops,
        'output': output,
        'errors': errors
    }
