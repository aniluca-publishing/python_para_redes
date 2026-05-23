import time
from pathlib import Path
from datetime import datetime
from network_lib import create_logger
from .inventory_tools import (
    get_snmp_tasks_from_csv,
    process_snmp_queries,
    build_inventory,
    create_inventory_file
)


def main():
    """
    Orquesta el proceso completo de inventario de equipos.

    Flujo general:
        1. Preparar directorios y logging.
        2. Definir tareas.
        3. Validar equipos que no responden a consultas SNMP.
        4. Obtener información por SNMP.
        5. Generar resultados y logs de errores.
    """

    # ----------------------------------------------------------------
    # Preparar directorios, archivos y logging
    # ----------------------------------------------------------------

    # Directorios base
    base_path = Path(__file__).resolve().parent
    inventory_path = base_path / 'inventory'
    logs_path = base_path / 'logs'

    # Crear directorios si no existen
    inventory_path.mkdir(parents=True, exist_ok=True)
    logs_path.mkdir(parents=True, exist_ok=True)

    # Configuración de logging
    timestamp = datetime.now().strftime('%Y_%B_%d')
    logfile_path = logs_path / f'inventory_{timestamp}.log'

    logger = create_logger(str(logfile_path), 'inventory')
    logger.setLevel('INFO')

    # Registrar el inicio del proceso
    logger.info('Inicio del proceso de inventario')

    # ----------------------------------------------------------------
    # Definir tareas
    # ----------------------------------------------------------------

    devices_path = base_path / 'data' / 'devices.csv'
    try:
        snmp_tasks = get_snmp_tasks_from_csv(devices_path)
    except Exception as e:
        logger.error(f'Error al procesar "{devices_path}": {e}')
        return

    # Diccionario con IP como clave y hostname como valor
    ip_to_hostname = {d['ip']: d['hostname'] for d in snmp_tasks}

    # ----------------------------------------------------------------
    # Validar equipos que no responden a consultas SNMP.
    # ----------------------------------------------------------------

    logger.info('Validando equipos sin respuesta SNMP')
    t0 = time.perf_counter()

    # Consultar sysDescr en todos los equipos
    res_sys_descr = process_snmp_queries(
        query='sysDescr',
        snmp_tasks=snmp_tasks,
        ips_dict=ip_to_hostname,
        logger=logger,
        timeout=2,
        log=False)
    duration = time.perf_counter() - t0

    # Lista de equipos sin respuesta SNMP
    hostnames_down = []

    # Identificar equipos sin respuesta SNMP
    for r in res_sys_descr:
        if str(r['snmp_result']) != 'ok':
            ip = r['host']
            hostname = ip_to_hostname[ip]
            hostnames_down.append(hostname)
    if hostnames_down:
        logger.warning(f"Equipos sin respuesta SNMP: "
                       f"{', '.join(hostnames_down)}")

    # Fin de validación de respuestas SNMP
    logger.info(f'Fin de validación de equipos sin respuesta SNMP. '
                f'Duración: {duration:.2f}s')

    # ----------------------------------------------------------------
    # Obtener información por SNMP
    # ----------------------------------------------------------------

    t0 = time.perf_counter()

    # Filtrar solo equipos con respuesta SNMP
    valid_snmp_tasks = [t for t in snmp_tasks
                        if t['hostname'] not in hostnames_down]

    if not valid_snmp_tasks:
        logger.warning(f'Ningún equipo respondió a '
                       f'las consultas SNMP.')
        logger.error(f'El archivo de inventario '
                     f'no pudo ser creado.\n')
        return
    logger.info('Iniciando consultas SNMP.')
    res_ent_phy_descr = process_snmp_queries(
        query='entPhyDescr',
        snmp_tasks=valid_snmp_tasks,
        ips_dict=ip_to_hostname,
        logger=logger)
    res_ent_phy_name = process_snmp_queries(
        query='entPhyName',
        snmp_tasks=valid_snmp_tasks,
        ips_dict=ip_to_hostname,
        logger=logger)
    res_ent_phy_model_name = process_snmp_queries(
        query='entPhyModelName',
        snmp_tasks=valid_snmp_tasks,
        ips_dict=ip_to_hostname,
        logger=logger)
    res_ent_sn = process_snmp_queries(
        query='entSN',
        snmp_tasks=valid_snmp_tasks,
        ips_dict=ip_to_hostname,
        logger=logger)

    duration = time.perf_counter() - t0
    logger.info(f'Consultas SNMP finalizadas. Duración: {duration:.2f}s')

    # ----------------------------------------------------------------
    # Generar resultados y logs de errores
    # ----------------------------------------------------------------

    ip_to_hostname = {k: v for k, v in ip_to_hostname.items()
                      if v not in hostnames_down}
    res, err = build_inventory(ips_dict=ip_to_hostname,
                               sys_descr=res_sys_descr,
                               ent_phy_descr=res_ent_phy_descr,
                               ent_phy_name=res_ent_phy_name,
                               ent_phy_model_name=
                               res_ent_phy_model_name,
                               ent_sn=res_ent_sn)

    # Registrar errores de SNMP.
    for ip, d in err.items():
        for base_oid, error in d.items():
            logger.error(f'Error SNMP en {ip_to_hostname[ip]}: '
                         f'al consultar "{base_oid}": "{error}"')

    # Generar archivo de inventario
    if res:
        inventory_file_path = create_inventory_file(res,
                                                    inventory_path)
        logger.info(f'Archivo de inventario creado: '
                    f'{inventory_file_path}\n')
    else:
        logger.error(f'El archivo de inventario no '
                     f'pudo ser creado.\n')


if __name__ == '__main__':
    main()
