import csv
import time
import re
import logging
from datetime import datetime
from pathlib import Path
from network_lib import snmp_walk, execute_with_threads


def get_snmp_tasks_from_csv(devices_path: Path) -> list[dict]:
    """
    Lee y valida un archivo CSV con la información de dispositivos.

    El archivo debe contener exactamente las siguientes columnas,
    en este orden:
        hostname, ip, version, community, user, level,
        auth_p, auth_pwd, priv_p, priv_pwd

    Cada fila es validada para asegurar que los campos obligatorios
    (hostname, ip, version) estén presentes.

    Parámetros:
        devices_path (Path): Ruta al archivo CSV.

    Retorna:
        list[dict]: Lista de dispositivos, donde cada dispositivo
                    es representado como un diccionario con las claves
                    del CSV.

    Excepciones:
        FileNotFoundError:
            Si el archivo no existe.

        ValueError:
            - Si el archivo está vacío.
            - Si la estructura de columnas es incorrecta.
            - Si faltan campos obligatorios en alguna fila.
    """

    # Definimos la estructura exacta esperada del CSV
    expected_columns = [
        'hostname', 'ip', 'version', 'community', 'user', 'level',
        'auth_p', 'auth_pwd', 'priv_p', 'priv_pwd'
    ]

    # Lista a retornar
    devices = []

    try:
        with open(devices_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            # Verificar que el archivo tenga encabezados
            if not reader.fieldnames:
                raise ValueError('El archivo CSV no tiene encabezado.')

            # Validar que las columnas coincidan exactamente
            if list(reader.fieldnames) != expected_columns:
                raise ValueError(
                    f'Estructura de columnas incorrecta.\n'
                    f' Esperado: {expected_columns}\n'
                    f' Encontrado: {list(reader.fieldnames)}'
                )

            # Procesar cada fila (start=2 para considerar
            # encabezado en la línea 0)
            for row_index, row in enumerate(reader, start=2):

                # Validar campos obligatorios
                if (not row['hostname']
                        or not row['ip']
                        or not row['version']):
                    raise ValueError(
                        f'Fila {row_index}: hostname, ip '
                        f'y version son obligatorios'
                    )

                devices.append(row)

    except FileNotFoundError:
        raise FileNotFoundError(f'Archivo '
                                f'no encontrado: {devices_path}')

    return devices


def snmp_walk_worker(task: dict) -> dict:
    """
    Ejecuta una operación SNMP WALK a partir de una tarea.

    Determina automáticamente si la operación corresponde a SNMPv1/v2c
    o SNMPv3 en función del campo 'version' dentro del diccionario task.

    Parámetros:
        task (dict): Diccionario con la información necesaria para ejecutar
        el SNMP WALK (ip, oid, version, credenciales, etc.).

    Retorna:
        dict: Resultado de la ejecución de snmp_walk.
    """

    # Parámetros comunes
    base_params = {
        'host': task['ip'],
        'base_oid': task['oid'],
        'version': task['version'],
        'timeout': task['timeout']
    }

    # SNMPv1 / SNMPv2c
    if task['version'] in ['1', '2c']:
        return snmp_walk(
            **base_params,
            community=task['community']
        )

    # SNMPv3
    return snmp_walk(
        **base_params,
        username=task['user'],
        level=task['level'],
        auth_proto=task.get('auth_p'),
        auth_pass=task.get('auth_pwd'),
        priv_proto=task.get('priv_p'),
        priv_pass=task.get('priv_pwd'),
        context=task.get('context'),
        engine_id=task.get('engine_id'),
        context_engine_id=task.get('context_engine_id')
    )


def process_snmp_queries(query: str,
                         snmp_tasks: list[dict],
                         ips_dict: dict,
                         logger: logging.Logger,
                         timeout: int = 60,
                         log: bool = True) -> list[dict]:
    """
    Ejecuta consultas SNMP y gestiona el logging de resultados.

    Lanza la consulta SNMP correspondiente, registra el inicio y fin
    de la ejecución, y reporta errores en caso de dispositivos sin respuesta.

    Parámetros:
        query (str): Nombre lógico de la consulta SNMP.
        tasks (list[dict]): Lista de tareas SNMP a ejecutar.
        ips_dict (dict): Diccionario que mapea IP -> hostname.
        logger: Objeto de logging utilizado para registrar eventos.
        log (bool): Indica si se debe registrar información en logs.

    Retorna:
        list[dict]: Lista de resultados de las consultas SNMP.
    """

    start_time = time.perf_counter()

    if log:
        logger.info(f'Inicio de consultas "{query}"')

    # Relación entre nombre lógico de consulta y OID real
    oid_map = {
        'sysDescr': '1.3.6.1.2.1.1.1',
        'entPhyDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
        'entPhyName': '.1.3.6.1.2.1.47.1.1.1.1.7',
        'entPhyModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
        'entSN': '.1.3.6.1.2.1.47.1.1.1.1.11'
    }

    # Obtener el OID correspondiente a la consulta
    oid = oid_map[query]

    # Agregar el OID y timeout a cada tarea SNMP
    for task in snmp_tasks:
        task['oid'] = oid
        task['timeout'] = timeout

    # Ejecutar la consulta de forma concurrente
    results = execute_with_threads(
        snmp_walk_worker,
        snmp_tasks,
        max_workers=10
    )

    # Procesar resultados
    for result in results:
        ip = result.get('host')
        hostname = ips_dict[ip]

        # Validar estado de la consulta (errores)
        if str(result.get('snmp_result', '')).lower() != 'ok' and log:
            logger.error(
                f'Sin respuesta de "{hostname}" al consultar '
                f'"{query}": {result.get("errors")}'
            )

    duration = time.perf_counter() - start_time

    if log:
        logger.info(
            f'Fin de consultas "{query}". Duración: {duration:.2f}s'
        )

    return results


def index_snmp_walk(responses: list[dict]) -> tuple[dict, dict]:
    """
    Convierte una lista de respuestas SNMP WALK en dos estructuras:

    • data:
        { host: { indice: valor } }

    • errors:
        { host: mensaje_error }

    Solo se procesan las respuestas con estado 'ok'. Las demás
    se registran en el diccionario de errores.

    Parámetros:
        responses (list[dict]): Lista de respuestas SNMP WALK.

    Retorna:
        tuple[dict, dict]:
            - datos: Información indexada por host e índice.
            - errores: Hosts con errores y su respectivo mensaje.
    """

    data = {}
    errors = {}

    for response in responses:
        host = response.get('host')

        # Validar estado de la respuesta
        result = str(response.get('snmp_result', '')).lower()
        if result != 'ok':
            errors[host] = response.get('errors', 'unknown_error')
            continue

        # Crear estructura del host
        if host not in data:
            data[host] = {}

        # Procesar resultados del walk
        for item in response.get('oids', []):
            index = item.get('index')
            value = item.get('value', '').strip('"')

            data[host][index] = value

    return data, errors


def get_vendor(sys_descr: str) -> str:
    """
    Determina el fabricante de un dispositivo a partir de sysDescr.

    Realiza una búsqueda de palabras clave dentro del texto utilizando
    expresiones regulares, ignorando mayúsculas/minúsculas.

    Parámetros:
        sys_descr (str): Valor de sysDescr obtenido por SNMP.

    Retorna:
        str: Nombre del fabricante identificado. Si no se encuentra
             coincidencia, retorna 'Unknown'.
    """

    vendor_map = {
        'Alcatel': ['alcatel'],
        'Cisco': ['cisco'],
        'Huawei': ['huawei'],
        'Nokia': ['nokia'],
        'Juniper': ['juniper', 'junos']
    }

    sys_descr = sys_descr.lower() if sys_descr else ''

    for vendor, keywords in vendor_map.items():
        for keyword in keywords:
            if re.search(fr'\b{keyword}\b', sys_descr):
                return vendor

    return 'Unknown'


def build_inventory(**kwargs) -> tuple[list[dict], dict]:
    """
    Procesa todos los resultados SNMP recolectados y construye
    dos estructuras:

    • results:
        Lista de dispositivos con información general e
        inventario físico.

    • errors:
        Diccionario por IP con los errores encontrados en
        cada consulta SNMP.

    Se espera recibir en kwargs los resultados ya procesados
    de las siguientes consultas:

        - sys_descr
        - ent_phy_descr
        - ent_phy_name
        - ent_phy_model_name
        - ent_sn

    Parámetros:
        **kwargs: Diccionario con los datos SNMP ya recolectados
                  y agrupados.

    Retorna:
        tuple[list[dict], dict]:
            - results: Lista de dispositivos con su inventario.
            - errors: Diccionario con errores por dispositivo.
    """

    ips_dict = kwargs['ips_dict']

    # Indexamos la información obtenida por SNMP
    sys_desc_data, sys_desc_err = index_snmp_walk(kwargs['sys_descr'])
    phy_desc_data, phy_desc_err = index_snmp_walk(kwargs['ent_phy_descr'])
    phy_name_data, phy_name_err = index_snmp_walk(kwargs['ent_phy_name'])
    model_data, model_err = index_snmp_walk(kwargs['ent_phy_model_name'])
    sn_data, sn_err = index_snmp_walk(kwargs['ent_sn'])

    results = []
    errors = {}

    for ip, hostname in ips_dict.items():
        # Como sysDescr es un único valor, en este caso el índice es 0:
        vendor = get_vendor(sys_desc_data.get(ip, {}).get('0', ''))

        device = {
            'hostname': hostname,
            'ip': ip,
            'vendor': vendor,
            'inventory': []
        }

        # Filtrar solo índices con número de serie no vacíos
        indexes = set(sn_data.get(ip, {}).keys())
        indexes = {index for index in indexes if index}

        for index in sorted(indexes,
                            key=lambda x: [int(p) for p in x.split('.')]):
            if not sn_data.get(ip, {}).get(index):
                continue

            # Obtener datos por separado
            phy_name = phy_name_data.get(ip, {}).get(index, '')
            phy_descr = phy_desc_data.get(ip, {}).get(index, '')
            model = model_data.get(ip, {}).get(index, '')
            serial = sn_data.get(ip, {}).get(index, '')

            # Limpiar valores (convertir a string y eliminar espacios)
            phy_name = str(phy_name).strip()
            phy_descr = str(phy_descr).strip()
            model = str(model).strip()
            serial = str(serial).strip()

            # Construir el item
            item = {
                'index': index,
                'entPhyName': phy_name,
                'entPhyDescr': phy_descr,
                'entPhyModelName': model,
                'entSN': serial
            }

            # No agregar filas completamente vacías
            if any(item.values()):
                device['inventory'].append(item)

        if device['inventory']:
            results.append(device)

        # Recolectar errores SNMP por dispositivo
        device_errors = {}

        error_sources = {
            'sysDescr': sys_desc_err,
            'entPhyDescr': phy_desc_err,
            'entPhyName': phy_name_err,
            'entPhyModelName': model_err,
            'entSN': sn_err,
        }

        for key, source in error_sources.items():
            error = source.get(ip)
            if error:
                device_errors[key] = error

        errors[ip] = device_errors

    return results, errors


def create_inventory_file(results: list[dict],
                          inventory_path: Path) -> Path:
    """
    Procesa los resultados de inventario y genera un archivo CSV.

    Se crea un archivo con timestamp en el directorio especificado,
    que contiene la información de los dispositivos y sus componentes.

    Parámetros:
        results (list[dict]): Lista de resultados de inventario por
                              dispositivo que retorna build_inventory().
        inventory_path (Path): Ruta donde se guardará el archivo
                              CSV.

    Retorna:
        Path: Ruta completa del archivo CSV generado.
    """

    # Asegurar que el directorio exista
    inventory_path.mkdir(parents=True, exist_ok=True)

    # Generar nombre de archivo con timestamp
    timestamp = datetime.now().strftime('%Y_%m_%d__%H_%M_%S')
    filename = f'inventory_{timestamp}.csv'
    full_path = inventory_path / filename

    # Definir encabezados del CSV
    headers = [
        'hostname', 'ip', 'vendor', 'entPhyName',
        'entPhyDescr', 'entPhyModelName', 'entSN'
    ]

    # Escribir archivo CSV usando csv.writer
    with open(full_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        # Escribir encabezados
        writer.writerow(headers)

        # Procesar cada dispositivo
        for result in results:

            # Iterar sobre inventario interno (si existe)
            for item in result.get('inventory', []):
                row = [
                    result.get('hostname', ''),
                    result.get('ip', ''),
                    result.get('vendor', ''),
                    item.get('entPhyName', ''),
                    item.get('entPhyDescr', ''),
                    item.get('entPhyModelName', ''),
                    item.get('entSN', '')
                ]
                writer.writerow(row)

    return full_path
