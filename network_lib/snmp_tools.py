import re
import time
import socket
import subprocess


SNMP_LINE_PATTERN = r"""
    ^(\.?\d+(?:\.\d+)*)   # OID
    (?:\s+(.*))?          # valor opcional
    $                     # fin de línea
"""
SNMP_LINE_RE = re.compile(SNMP_LINE_PATTERN, re.X)

NUMERIC_OID_RE = re.compile(r'^\d+(?:\.\d+)*$')


def is_numeric_oid(oid: str) -> bool:
    if oid is None:
        return False
    return bool(NUMERIC_OID_RE.fullmatch(oid.strip().strip('.')))


def snmp_get(
    host: str,
    oid: str,
    version: str = '2c',
    community: str = '',
    username: str = '',
    level: str = '',
    auth_proto: str = '',
    auth_pass: str = '',
    priv_proto: str = '',
    priv_pass: str = '',
    context: str = '',
    engine_id: str = '',
    context_engine_id: str = '',
    port: int = 161,
    timeout: int = 2,
    retries: int = 1
) -> dict:
    """
    Ejecuta snmpget usando net-snmp (snmpget CLI) y
    retorna un resultado estandarizado
    """

    # ---------------------------------------------------------------
    # Validación de argumentos de entrada
    # ---------------------------------------------------------------
    version = str(version).lower().strip() if version is not None else None
    level = str(level).strip() if level is not None else None
    errors = ''
    allowed_levels = ['noAuthNoPriv', 'authNoPriv', 'authPriv']

    # Validación de host y oid
    if not host or not oid:
        errors = 'Host u OID inválido'

    # Validación de OID numérico
    elif not is_numeric_oid(oid):
        errors = 'El OID debe ser numérico'

    # Validación de la versión SNMP
    elif version not in ['1', '2c', '3']:
        errors = 'Versión SNMP inválida (usa 1, 2c, 3)'

    # Validación SNMP v1/v2c
    elif version in ['1', '2c']:
        if not community:
            errors = 'Se requiere comunidad para SNMP v1/v2c'

    # Validación SNMP v3 según nivel
    elif version == '3':
        if not username or not level:
            errors = 'Falta usuario o nivel en SNMPv3'
        elif level not in allowed_levels:
            errors = (f'Nivel inválido en SNMPv3: {level}. '
                      f'Debes usar noAuthNoPriv, authNoPriv o '
                      f'authPriv')
        elif level == 'authNoPriv':
            if not auth_proto or not auth_pass:
                errors = ('SNMPv3 requiere auth_proto y '
                          'auth_pass para authNoPriv')
        elif level == 'authPriv':
            if not auth_proto or not auth_pass:
                errors = ('SNMPv3 requiere auth_proto y '
                          'auth_pass para authPriv')
            elif not priv_proto or not priv_pass:
                errors = ('SNMPv3 requiere priv_proto y '
                          'priv_pass para authPriv')
    if errors:
        return {
            'host': host,
            'oid': oid,
            'snmp_result': 'error',
            'snmp_status': 'invalid_args',
            'value': None,
            'stdout': None,
            'stderr': None,
            'time_ms': None,
            'errors': errors
        }

    # ---------------------------------------------------------------
    # Construcción del comando
    # ---------------------------------------------------------------
    cmd = ['snmpget', '-O', 'nq', '-v', version, '-t',
           str(timeout), '-r', str(retries)]

    if version in ['1', '2c']:
        cmd.extend(['-c', community])
    else:
        cmd.extend(['-u', username, '-l', level])

        if level in ['authNoPriv', 'authPriv']:
            cmd.extend(['-a', auth_proto, '-A', auth_pass])
        if level == 'authPriv':
            cmd.extend(['-x', priv_proto, '-X', priv_pass])
        if context:
            cmd.extend(['-n', context])
        if engine_id:
            cmd.extend(['-e', engine_id])
        if context_engine_id:
            cmd.extend(['-E', context_engine_id])

    # Host con puerto (net-snmp acepta host:port)
    cmd.extend([f'{host}:{port}', oid])

    # ---------------------------------------------------------------
    # Ejecución del comando
    # ---------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2
        )

        t1 = time.perf_counter()
        time_ms = round((t1 - t0) * 1000, 2)

        stdout = (proc.stdout or '').strip()
        stderr = (proc.stderr or '').strip()
        combined = f'{stdout}\n{stderr}'.strip().lower()
        # -----------------------------------------------------------
        # Clasificación de errores comunes (validación de returncode)
        # -----------------------------------------------------------
        if proc.returncode != 0:
            if 'timeout' in combined:
                snmp_status = 'timeout'
            elif re.search(r'unknown host|cannot find|'
                           'invalid address',
                           combined, re.I):
                snmp_status = 'dns_error'
            elif re.search(r'authentication failure|wrong digest',
                           combined, re.I):
                snmp_status = 'auth_failed'
            elif re.search(r'no such object available|'
                           'no such instance',
                           combined, re.I):
                snmp_status = 'no_such_object'
            elif re.search(r'unknown object identifier',
                           combined, re.I):
                snmp_status = 'bad_oid'
            elif re.search(r'connection refused|'
                           'network is unreachable',
                           combined, re.I):
                snmp_status = 'unreachable'
            else:
                snmp_status = 'snmp_error'

            errors = stderr or stdout or 'Error SNMP desconocido'
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': snmp_status,
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': errors
            }
        # -----------------------------------------------------------
        # Validación de la salida del comando snmpget
        # Formato típico: OID VALUE
        # -----------------------------------------------------------

        # Si la salida del comando está vacía:
        if not stdout:
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': 'empty_output',
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or 'Salida vacía'
            }

        # Validamos la primera línea de la salida
        lines = stdout.splitlines()
        first_line = lines[0]
        m = SNMP_LINE_RE.match(first_line.strip())

        # Retornamos un error si no se encuentra el patrón
        if not m:
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': 'parse_error',
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or stdout
            }

        # Validamos mensajes de OID sin respuesta
        no_such_messages = [
            'No Such Object available on this agent at this OID',
            'No Such Instance currently exists at this OID'
        ]

        value = m.group(2)
        if value is not None:
            value = value.strip()
        if value in no_such_messages:
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': 'no_such_object',
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or 'OID sin respuesta'
            }

        # Retornamos la salida completa
        extra_lines = lines[1:]
        if extra_lines:
            if value is None:
                value = '\n'.join(extra_lines)
            else:
                value = value + '\n' + '\n'.join(extra_lines)

        return {
            'host': host,
            'oid': oid,
            'snmp_result': 'ok',
            'snmp_status': 'success',
            'value': value,
            'stdout': stdout,
            'stderr': stderr,
            'time_ms': time_ms,
            'errors': ''
        }

    # ---------------------------------------------------------------
    # Validación de excepciones
    # ---------------------------------------------------------------
    except FileNotFoundError:
        snmp_status = 'missing_binary'
        errors = ('No existe el comando snmpget en el sistema'
                  ' (instale net-snmp)')
    except subprocess.TimeoutExpired:
        snmp_status = 'timeout'
        errors = 'Timeout ejecutando snmpget'
    except socket.gaierror:
        snmp_status = 'dns_error'
        errors = 'Fallo en la resolución DNS'
    except Exception as e:
        snmp_status = 'unknown'
        errors = str(e)

    return {
        'host': host,
        'oid': oid,
        'snmp_result': 'error',
        'snmp_status': snmp_status,
        'value': None,
        'stdout': None,
        'stderr': None,
        'time_ms': None,
        'errors': errors
    }


def snmp_walk(
    host: str,
    base_oid: str,
    version: str = '2c',
    community: str = '',
    username: str = '',
    level: str = '',
    auth_proto: str = '',
    auth_pass: str = '',
    priv_proto: str = '',
    priv_pass: str = '',
    context: str = '',
    engine_id: str = '',
    context_engine_id: str = '',
    port: int = 161,
    timeout: int = 2,
    retries: int = 1,
    bulk: bool = False,
    max_repetitions: int = 10
) -> dict:
    """
    Ejecuta SNMP WALK usando Net-SNMP y retorna un diccionario con:
    - snmp_result: ['ok', 'error']
    - snmp_status: [ 'success', 'timeout', 'dns_error', 'auth_failed',
                      'bad_oid', 'unreachable', 'snmp_error',
                       'missing_binary', 'empty_output',
                       'parse_error']
    - oids: lista de {oid, index, value}
            (soporta valores multilínea)
    - stdout, stderr, time_ms, errors

    Modos:
    - bulk=False: usa 'snmpwalk'
    - bulk=True: usa 'snmpbulkwalk' (SNMP v2c/v3) y aplica
                 -Cr<max_repetitions>
      donde max_repetitions controla cuántas repeticiones devuelve
      el GetBulk por petición.
    """

    # ---------------------------------------------------------------
    # Validación de argumentos de entrada (misma lógica que snmp_get)
    # ---------------------------------------------------------------
    version = str(version).lower().strip() if version is not None else None
    level = str(level).strip() if level is not None else None
    errors = ''
    allowed_levels = ['noAuthNoPriv', 'authNoPriv', 'authPriv']

    if not host or not base_oid:
        errors = 'Host u OID inválido'
    elif not is_numeric_oid(base_oid):
        errors = 'El OID base debe ser numérico'
    elif version not in ['1', '2c', '3']:
        errors = 'Versión SNMP inválida (usa 1, 2c, 3)'
    elif bulk and version == '1':
        errors = 'SNMP BULK no es soportado por v1'
    elif version in ['1', '2c'] and not community:
        errors = 'Se requiere comunidad para SNMP v1/v2c'
    elif version == '3' and (not username or not level):
        errors = 'Falta usuario o nivel en SNMPv3'
    elif version == '3' and level not in allowed_levels:
        errors = (f'Nivel inválido en SNMPv3: {level}. '
                  f'Debes usar noAuthNoPriv, authNoPriv o authPriv')
    elif version == '3' and level == 'authNoPriv' and (not auth_proto
                                                       or not auth_pass):
        errors = ('SNMPv3 requiere auth_proto y '
                  'auth_pass para authNoPriv')
    elif version == '3' and level == 'authPriv' and (not auth_proto
                                                     or not auth_pass):
        errors = ('SNMPv3 requiere auth_proto y '
                  'auth_pass para authPriv')
    elif version == '3' and level == 'authPriv' and (not priv_proto
                                                     or not priv_pass):
        errors = ('SNMPv3 requiere priv_proto y '
                  'priv_pass para authPriv')
    elif bulk and version in ['2c', '3']:
        try:
            if int(max_repetitions) <= 0:
                errors = 'max_repetitions debe ser un entero > 0'
        except (TypeError, ValueError):
            errors = 'max_repetitions debe ser un entero > 0'

    if errors:
        return {
            'host': host,
            'base_oid': base_oid,
            'snmp_result': 'error',
            'snmp_status': 'invalid_args',
            'oids': [],
            'stdout': None,
            'stderr': None,
            'time_ms': None,
            'errors': errors
        }

    # ---------------------------------------------------------------
    # Construcción del comando
    # ---------------------------------------------------------------
    cmd_bin = 'snmpbulkwalk' if bulk else 'snmpwalk'
    cmd = [cmd_bin, '-O', 'nq', '-v', version, '-t', str(timeout),
           '-r', str(retries)]

    if bulk:
        # Net-SNMP: -Cr<n> = max-repetitions (GetBulk)
        cmd.append(f'-Cr{int(max_repetitions)}')

    if version in ['1', '2c']:
        cmd.extend(['-c', community])
    else:
        cmd.extend(['-u', username, '-l', level])

        if level in ['authNoPriv', 'authPriv']:
            cmd.extend(['-a', auth_proto, '-A', auth_pass])
        if level == 'authPriv':
            cmd.extend(['-x', priv_proto, '-X', priv_pass])
        if context:
            cmd.extend(['-n', context])
        if engine_id:
            cmd.extend(['-e', engine_id])
        if context_engine_id:
            cmd.extend(['-E', context_engine_id])

    cmd.extend([f'{host}:{port}', base_oid])

    # ---------------------------------------------------------------
    # Ejecución del comando
    # ---------------------------------------------------------------
    t0 = time.perf_counter()

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 5
        )

        time_ms = round((time.perf_counter() - t0) * 1000, 2)
        stdout = (proc.stdout or '').strip()
        stderr = (proc.stderr or '').strip()
        combined = f'{stdout}\n{stderr}'.strip().lower()

        # -----------------------------------------------------------
        # Clasificación de errores comunes
        # -----------------------------------------------------------
        if proc.returncode != 0:
            if 'timeout' in combined:
                snmp_status = 'timeout'
            elif re.search(r'unknown host|cannot find|invalid address',
                           combined, re.I):
                snmp_status = 'dns_error'
            elif re.search(r'authentication failure|wrong digest',
                           combined, re.I):
                snmp_status = 'auth_failed'
            elif re.search(r'no such object available|'
                           'no such instance',
                           combined, re.I):
                snmp_status = 'no_such_object'
            elif re.search(r'unknown object identifier',
                           combined, re.I):
                snmp_status = 'bad_oid'
            elif re.search(r'connection refused|network is unreachable',
                           combined, re.I):
                snmp_status = 'unreachable'
            else:
                snmp_status = 'snmp_error'

            return {
                'host': host,
                'base_oid': base_oid,
                'snmp_result': 'error',
                'snmp_status': snmp_status,
                'oids': [],
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or stdout or 'Error SNMP desconocido'
            }

        # -----------------------------------------------------------
        # Validación de la salida del comando snmpwalk/bulkwalk
        # Formato típico (varias líneas):
        #    OID1 VALUE1
        #    OID2 VALUE2
        # -----------------------------------------------------------

        # Si la salida del comando está vacía:
        if not stdout:
            return {
                'host': host,
                'base_oid': base_oid,
                'snmp_result': 'error',
                'snmp_status': 'empty_output',
                'oids': [],
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or 'Salida vacía'
            }

        # Validamos la primera línea de la salida
        # para buscar el patrón
        lines = stdout.splitlines()
        first_line = lines[0]
        m = SNMP_LINE_RE.match(first_line.strip())

        # Retornamos un error si no se encuentra el patrón
        if not m:
            return {
                'host': host,
                'base_oid': base_oid,
                'snmp_result': 'error',
                'snmp_status': 'parse_error',
                'oids': [],
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or stdout
            }

        # Validamos mensajes de OID sin respuesta
        no_such_messages = [
            'No Such Object available on this agent at this OID',
            'No Such Instance currently exists at this OID'
        ]

        value = m.group(2)
        if value is not None:
            value = value.strip()
        if value in no_such_messages:
            return {
                'host': host,
                'base_oid': base_oid,
                'snmp_result': 'error',
                'snmp_status': 'no_such_object',
                'oids': [],
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or 'OID sin respuesta'
            }

        # Retornamos la salida completa
        oids = []
        current_oid = None  # Futuro diccionario
        base_oid_norm = base_oid.strip('.')

        for line in stdout.splitlines():
            # Línea principal: OID VALUE
            m = SNMP_LINE_RE.match(line)
            if m:
                oid = m.group(1).strip().strip('.')
                value = m.group(2)

                # Solo aceptar hijos del subárbol
                if oid != base_oid_norm and \
                        not oid.startswith(base_oid_norm + '.'):
                    current_oid = None
                    continue

                index = ''
                if len(oid) > len(base_oid_norm):
                    index = oid[len(base_oid_norm) + 1:]

                current_oid = {
                    'oid': oid,
                    'index': index,
                    'value': value
                }

                oids.append(current_oid)
                continue

            # Línea de continuación
            if current_oid is not None:
                if current_oid['value'] is None:
                    current_oid['value'] = line
                else:
                    current_oid['value'] += '\n' + line

        # Si no pudimos interpretar nada útil
        if not oids:
            return {
                'host': host,
                'base_oid': base_oid,
                'snmp_result': 'error',
                'snmp_status': 'parse_error',
                'oids': [],
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': (f'No se pudo interpretar la salida de '
                           f'{cmd_bin}')
            }

        # Resultado final
        return {
            'host': host,
            'base_oid': base_oid,
            'snmp_result': 'ok',
            'snmp_status': 'success',
            'oids': oids,
            'stdout': stdout,
            'stderr': stderr,
            'time_ms': time_ms,
            'errors': ''
        }

    # ---------------------------------------------------------------
    # Validación de excepciones
    # ---------------------------------------------------------------

    except FileNotFoundError:
        snmp_status = 'missing_binary'
        errors = (f'No existe el comando {cmd_bin} en el sistema '
                  f'(instale net-snmp)')
    except subprocess.TimeoutExpired:
        snmp_status = 'timeout'
        errors = f'Timeout ejecutando {cmd_bin}'
    except socket.gaierror:
        snmp_status = 'dns_error'
        errors = 'Fallo en la resolución DNS'
    except Exception as e:
        snmp_status = 'unknown'
        errors = str(e)

    return {
        'host': host,
        'base_oid': base_oid,
        'snmp_result': 'error',
        'snmp_status': snmp_status,
        'oids': [],
        'stdout': None,
        'stderr': None,
        'time_ms': None,
        'errors': errors
    }


def snmp_set(
    host: str,
    oid: str,
    set_type: str,
    set_value: str,
    version: str = '2c',
    community: str = '',
    username: str = '',
    level: str = '',
    auth_proto: str = '',
    auth_pass: str = '',
    priv_proto: str = '',
    priv_pass: str = '',
    context: str = '',
    engine_id: str = '',
    context_engine_id: str = '',
    port: int = 161,
    timeout: int = 2,
    retries: int = 1
) -> dict:
    """
    Ejecuta snmpset usando net-snmp (snmpset CLI) y
    retorna un resultado estandarizado (similar a snmp_get).

    Nota: snmpset requiere tipo net-snmp (ej: i, u, s, x, t, a, o, n)
    y valor.
    """

    # ---------------------------------------------------------------
    # Validación de argumentos de entrada
    # ---------------------------------------------------------------
    version = str(version).lower().strip() if version is not None else None
    level = str(level).strip() if level is not None else None
    set_type = str(set_type).strip() if set_type is not None else None
    errors = ''
    allowed_levels = ['noAuthNoPriv', 'authNoPriv', 'authPriv']

    if not host or not oid:
        errors = 'Host u OID inválido'
    elif not is_numeric_oid(oid):
        errors = 'El OID debe ser numérico'
    elif not set_type or set_value is None:
        errors = 'Falta set_type o set_value para snmpset'
    elif version not in ['1', '2c', '3']:
        errors = 'Versión SNMP inválida (usa 1, 2c, 3)'
    elif version in ['1', '2c']:
        if not community:
            errors = 'Se requiere comunidad para SNMP v1/v2c'
    elif version == '3':
        if not username or not level:
            errors = 'Falta usuario o nivel en SNMPv3'
        elif level not in allowed_levels:
            errors = (f'Nivel inválido en SNMPv3: {level}. '
                      f'Debes usar noAuthNoPriv, authNoPriv o '
                      f'authPriv')
        elif level == 'authNoPriv':
            if not auth_proto or not auth_pass:
                errors = ('SNMPv3 requiere auth_proto y '
                          'auth_pass para authNoPriv')
        elif level == 'authPriv':
            if not auth_proto or not auth_pass:
                errors = ('SNMPv3 requiere auth_proto y '
                          'auth_pass para authPriv')
            elif not priv_proto or not priv_pass:
                errors = ('SNMPv3 requiere priv_proto y '
                          'priv_pass para authPriv')

    if errors:
        return {
            'host': host,
            'oid': oid,
            'snmp_result': 'error',
            'snmp_status': 'invalid_args',
            'value': None,
            'stdout': None,
            'stderr': None,
            'time_ms': None,
            'errors': errors
        }

    # ---------------------------------------------------------------
    # Construcción del comando
    # ---------------------------------------------------------------
    cmd = ['snmpset', '-O', 'nq', '-v', version, '-t', str(timeout),
           '-r', str(retries)]

    if version in ['1', '2c']:
        cmd.extend(['-c', community])
    else:
        cmd.extend(['-u', username, '-l', level])

        if level in ['authNoPriv', 'authPriv']:
            cmd.extend(['-a', auth_proto, '-A', auth_pass])
        if level == 'authPriv':
            cmd.extend(['-x', priv_proto, '-X', priv_pass])
        if context:
            cmd.extend(['-n', context])
        if engine_id:
            cmd.extend(['-e', engine_id])
        if context_engine_id:
            cmd.extend(['-E', context_engine_id])

    cmd.extend([f'{host}:{port}', oid, set_type, str(set_value)])

    # ---------------------------------------------------------------
    # Ejecución del comando
    # ---------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2
        )

        time_ms = round((time.perf_counter() - t0) * 1000, 2)

        stdout = (proc.stdout or '').strip()
        stderr = (proc.stderr or '').strip()
        combined = f'{stdout}\n{stderr}'.strip().lower()

        # -----------------------------------------------------------
        # Errores por returncode
        # -----------------------------------------------------------
        if proc.returncode != 0:
            if 'timeout' in combined:
                snmp_status = 'timeout'
            elif re.search(r'unknown host|cannot find|invalid address',
                           combined, re.I):
                snmp_status = 'dns_error'
            elif re.search(r'authentication failure|wrong digest',
                           combined, re.I):
                snmp_status = 'auth_failed'
            elif re.search(r'not writable|read-only|no access',
                           combined, re.I):
                snmp_status = 'not_writable'
            elif re.search(r'no such object available|no such instance',
                           combined, re.I):
                snmp_status = 'no_such_object'
            elif re.search(r'unknown object identifier',
                           combined, re.I):
                snmp_status = 'bad_oid'
            elif re.search(r'bad value|wrong type|inconsistent value',
                           combined, re.I):
                snmp_status = 'bad_value'
            elif re.search(r'connection refused|network is unreachable',
                           combined, re.I):
                snmp_status = 'unreachable'
            else:
                snmp_status = 'snmp_error'

            errors = stderr or stdout or 'Error SNMP desconocido'
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': snmp_status,
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': errors
            }

        # -----------------------------------------------------------
        # Validación de la salida del comando snmpset
        # Formato típico: OID VALUE
        # -----------------------------------------------------------

        # Si la salida del comando está vacía:
        if not stdout:
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': 'empty_output',
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or 'Salida vacía'
            }

        # Validamos la primera línea de la salida
        lines = stdout.splitlines()
        first_line = lines[0]
        m = SNMP_LINE_RE.match(first_line.strip())

        # Retornamos un error si no se encuentra el patrón
        if not m:
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': 'parse_error',
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or stdout
            }

        # Validamos mensajes de OID sin respuesta
        no_such_messages = [
            'No Such Object available on this agent at this OID',
            'No Such Instance currently exists at this OID'
        ]

        value = m.group(2)
        if value is not None:
            value = value.strip()
        if value in no_such_messages:
            return {
                'host': host,
                'oid': oid,
                'snmp_result': 'error',
                'snmp_status': 'no_such_object',
                'value': None,
                'stdout': stdout,
                'stderr': stderr,
                'time_ms': time_ms,
                'errors': stderr or 'OID sin respuesta'
            }

        # Retornamos la salida completa
        extra_lines = lines[1:]
        if extra_lines:
            if value is None:
                value = '\n'.join(extra_lines)
            else:
                value = value + '\n' + '\n'.join(extra_lines)

        return {
            'host': host,
            'oid': oid,
            'snmp_result': 'ok',
            'snmp_status': 'success',
            'value': value,
            'stdout': stdout,
            'stderr': stderr,
            'time_ms': time_ms,
            'errors': ''
        }

    except FileNotFoundError:
        snmp_status = 'missing_binary'
        errors = ('No existe el comando snmpset en el sistema '
                  '(instale net-snmp)')
    except subprocess.TimeoutExpired:
        snmp_status = 'timeout'
        errors = 'Timeout ejecutando snmpset'
    except socket.gaierror:
        snmp_status = 'dns_error'
        errors = 'Fallo en la resolución DNS'
    except Exception as e:
        snmp_status = 'unknown'
        errors = str(e)

    return {
        'host': host,
        'oid': oid,
        'snmp_result': 'error',
        'snmp_status': snmp_status,
        'value': None,
        'stdout': None,
        'stderr': None,
        'time_ms': None,
        'errors': errors
    }
