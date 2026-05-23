import time
import os
from datetime import datetime
from pathlib import Path
from network_lib import execute_with_threads, create_logger
from .backups_tools import (get_today_paths,
                            ping_worker,
                            ssh_worker,
                            build_current_cfg_path,
                            find_latest_previous_backup,
                            generate_unified_diff,
                            build_current_diff_path,
                            count_changed_lines)


SSH_USER = os.getenv('SSH_USER')
SSH_PASS = os.getenv('SSH_PASS')


def main():
    """
    Orquesta el proceso completo de respaldo automático
    de configuraciones.

    Flujo general:
        1. Preparar directorios y logging.
        2. Validar credenciales SSH.
        3. Definición de tareas.
        4. Verificar conectividad con ping.
        5. Obtener respaldos por SSH.
        6. Generar archivos de configuraciones.
        7. Generar archivo de diferencias.
    """

    # ----------------------------------------------------------------
    # Preparar directorios y logging
    # ----------------------------------------------------------------

    # Directorios base
    base_path = Path(__file__).resolve().parent
    backups_path = base_path / 'backups'
    logs_path = base_path / 'logs'

    # Creación de los directorios
    backups_path.mkdir(parents=True, exist_ok=True)
    logs_path.mkdir(parents=True, exist_ok=True)

    # Configuración de logging
    timestamp = datetime.now().strftime('%Y_%B_%d')
    logfile_path = logs_path / f'backup_{timestamp}.log'
    logger = create_logger(str(logfile_path), 'backup')
    logger.setLevel('INFO')

    # Definición de directorios diarios
    today_cfg_path, today_diff_path = get_today_paths(backups_path)

    # Registrar el inicio del proceso
    logger.info('Backup process started')

    # ----------------------------------------------------------------
    # Validar credenciales SSH
    # ----------------------------------------------------------------

    if not SSH_USER or not SSH_PASS:
        error_message = ('Las variables de entorno SSH_USER '
                         'y SSH_PASS no han sido definidas!')
        logger.error(error_message)
        raise RuntimeError(error_message)

    # ----------------------------------------------------------------
    # Definición de tareas
    # ----------------------------------------------------------------
    tasks = [
        {
            'hostname': 'R1-GYE',
            'ip': '10.10.108.100',
            'usuario': SSH_USER,
            'clave': SSH_PASS,
            'comando': 'show running-config'
        },
        {
            'hostname': 'SW1-GYE',
            'ip': '10.10.108.194',
            'usuario': SSH_USER,
            'clave': SSH_PASS,
            'comando': 'show running-config'
        },
    ]

    ip_to_hostname = {d['ip']: d['hostname'] for d in tasks}

    # ----------------------------------------------------------------
    # Verificar conectividad con ping
    # ----------------------------------------------------------------

    # Registrar el inicio de ping
    logger.info('Validating connectivity (ping)')

    # Tareas de ping
    ping_tasks = [{'host': ip} for ip in ip_to_hostname.keys()]

    # Ejecutar con concurrencia
    t0 = time.perf_counter()
    ping_results = execute_with_threads(
        ping_worker,
        ping_tasks,
        max_workers=10
    )
    duration = time.perf_counter() - t0

    # Procesamiento de equipos sin conectividad
    down_devices = []
    for result in ping_results:
        if result['host_status'] != 'up':
            ip = result['host']
            hostname = ip_to_hostname[ip]
            down_devices.append(hostname)
            logger.warning(f"{hostname} UNREACHABLE")
    logger.info(f'Ping validation finished. Duration: {duration:.2f}s')

    # Retornamos si no hay equipos operativos
    if len(down_devices) == len(tasks):
        logger.warning('No operational devices available')
        logger.info('Backup process finished\n')
        return

    # ----------------------------------------------------------------
    # Obtener respaldos por SSH
    # ----------------------------------------------------------------

    # Registrar el inicio de SSH
    logger.info('Starting configuration backups')

    # Tareas de SSH
    ssh_tasks = [
        t for t in tasks
        if t['hostname'] not in down_devices
    ]

    # Ejecutar con concurrencia
    t0 = time.perf_counter()
    ssh_results = execute_with_threads(
        ssh_worker,
        ssh_tasks,
        max_workers=10
    )
    duration = time.perf_counter() - t0

    # ----------------------------------------------------------------
    # Generar archivos de configuraciones
    # ----------------------------------------------------------------
    for result in ssh_results:
        ip = result['host']
        hostname = ip_to_hostname[ip]

        # Validar errores SSH
        if result['ssh_result'] != 'ok':
            logger.error(f'{hostname} SSH connection failed '
                         f'({result["errors"]})')
            continue

        # Guardar configuraciones
        current_config = build_current_cfg_path(today_cfg_path,
                                                hostname)
        with open(current_config, 'w', encoding='utf-8') as f:
            f.write(result['stdout'])

    # ----------------------------------------------------------------
    # Generar archivo de diferencias
    # ----------------------------------------------------------------
        # Buscar archivo de configuración anterior
        previous_config = find_latest_previous_backup(
            backups_path,
            hostname,
            current_config
        )

        # Si existe archivo, buscar diferencias
        if previous_config:
            diff_text = generate_unified_diff(
                previous_config,
                current_config
            )
            # Si hay diferencias, generar archivo
            if diff_text:
                diff_path = build_current_diff_path(
                    today_diff_path,
                    hostname
                )
                with open(diff_path, 'w', encoding='utf-8') as f:
                    f.write(diff_text)
                changes = count_changed_lines(diff_text)
                logger.info(f'{hostname} changes detected: {changes}')

    # Registrar en logs
    logger.info(
        f'Backup process finished. Duration: {duration:.2f}s\n'
    )


if __name__ == '__main__':
    main()
