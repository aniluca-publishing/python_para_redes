
import re
import difflib
from pathlib import Path
from datetime import datetime
from network_lib import execute_ssh, execute_ping
from typing import Optional


def get_today_paths(base_path: Path) -> tuple[Path, Path]:
    """
    Genera y garantiza la existencia de la estructura de directorios
    correspondiente al día actual.

    Estructura creada:
        base_dir/
             └── YEAR/
                  └── MONTH/
                       └── DAY/
                             ├── configs/
                             └── diffs/

    Parámetros:
        base_path (str): Directorio base donde se almacenan los
                         respaldos.

    Retorna:
        tuple:
         - configs_path (Path): Ruta donde se guardarán los respaldos.
         - diffs_path (Path): Ruta donde se guardarán los archivos
                              diff.
    """
    now = datetime.now()
    year = now.strftime('%Y')
    month = now.strftime('%B')
    day = now.strftime('%d')

    today_path = base_path / year / month / day
    configs_path = today_path / 'configs'
    diffs_path = today_path / 'diffs'

    configs_path.mkdir(parents=True, exist_ok=True)
    diffs_path.mkdir(parents=True, exist_ok=True)

    return configs_path, diffs_path


def normalize_filename(filename: str) -> str:
    """
    Normaliza un nombre para que pueda usarse de forma segura
    como nombre de archivo.

    Reemplaza caracteres problemáticos por '_'.
    """

    filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
    filename = filename.replace(' ', '_')

    return filename


def build_current_cfg_path(config_path: Path, hostname: str) -> Path:
    """
    Construye la ruta completa para almacenar la configuración
    actual de un dispositivo.

    El nombre del archivo incluye:
        - Nombre del host normalizado
        - Timestamp con formato YYYY_MM_DD__HH_MM_SS
        - Extensión .cfg

    Parámetros:
        config_path (Path): Ruta donde se guardan las configuraciones
        hostname (str): Nombre del dispositivo

    Retorna:
        Path: Ruta completa del archivo de configuración
    """
    name = normalize_filename(hostname)
    timestamp = datetime.now().strftime('%Y_%m_%d__%H_%M_%S')
    filename = f'{name}__{timestamp}.cfg'
    return config_path / filename


def build_current_diff_path(diff_path: Path, hostname: str) -> Path:
    """
    Construye la ruta completa para almacenar el archivo diff
    correspondiente a un dispositivo.

    El nombre del archivo incluye:
        - Nombre del host normalizado
        - Timestamp con formato YYYY_MM_DD__HH_MM_SS
        - Extensión .diff

    Parámetros:
        diff_path (str): Directorio donde se guardan diffs
        hostname (str): Nombre del dispositivo

    Retorna:
        Path: Ruta completa del archivo diff
    """
    name = normalize_filename(hostname)
    timestamp = datetime.now().strftime('%Y_%m_%d__%H_%M_%S')
    filename = f'{name}__{timestamp}.diff'
    return diff_path / filename


def find_latest_previous_backup(base_path: Path,
                                hostname: str,
                                current_path: Path) -> Optional[Path]:
    """
    Busca el respaldo anterior más reciente (archivo .cfg) para un
    host, dentro de una estructura de backups por fecha.

    Importante:
    - Se excluye explícitamente el archivo indicado por current_path,
      para evitar compararlo consigo mismo.
    - La selección del “más reciente” se basa en la fecha de
      modificación (mtime) del archivo en el sistema.

    Parámetros:
        base_path (str): Directorio base donde se almacenan los
                         respaldos.
        hostname (str): Nombre del equipo.
        current_path (str): Ruta del respaldo actual que debe
                            excluirse.

    Retorna:
        Path | None:
            - Ruta del archivo .cfg anterior más reciente si existe.
            - None si no hay candidatos.
    """
    hostname = normalize_filename(hostname)

    # Buscar archivos con patrón
    candidates = list(
        base_path.glob(f'*/*/*/configs/{hostname}__*.cfg')
    )

    # Excluir el archivo actual
    candidates = [
        p for p in candidates
        if p.resolve() != current_path.resolve()
    ]

    if not candidates:
        return None

    # Ordenar por fecha de modificación (más reciente primero)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    return candidates[0]


def generate_unified_diff(previous_file: Path,
                          current_file: Path) -> str:
    """
    Genera un diff unificado (formato unified diff) entre dos
    archivos de texto.

    Notas:
    - Se leen los archivos con encoding UTF-8 y errors='ignore'
      para minimizar fallos por caracteres inválidos o mezclas
      de codificación.
    - El resultado es un string listo para guardarse en un .diff
      o mostrarse.

    Parámetros:
        previous_file (Path): Ruta del archivo “anterior”.
        current_file (Path): Ruta del archivo “actual”.

    Retorna:
        str: Diff unificado como texto. Si no hay diferencias,
             retorna ''.
    """
    with open(previous_file, 'r',
              encoding='utf-8',
              errors='ignore') as f1:
        previous_lines = f1.read().splitlines()

    with open(current_file, 'r',
              encoding='utf-8',
              errors='ignore') as f2:
        current_lines = f2.read().splitlines()

    diff_iter = difflib.unified_diff(
        previous_lines,
        current_lines,
        fromfile=str(previous_file),
        tofile=str(current_file),
        lineterm=''
    )

    return '\n'.join(diff_iter)


def count_changed_lines(diff_text: str) -> int:
    """
    Cuenta cuántas líneas cambiaron dentro de un diff unificado.

    Regla:
    - Cuenta líneas agregadas (+) y eliminadas (-),
      pero ignora los encabezados '+++ ...' y '--- ...'.

    Parámetros:
        diff_text (str): Texto completo del diff unificado.

    Retorna:
        int: Número total de líneas cambiadas (agregadas +
             eliminadas).
    """
    if not diff_text:
        return 0

    changes = 0
    for line in diff_text.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            changes += 1
        elif line.startswith('-') and not line.startswith('---'):
            changes += 1

    return changes


def ping_worker(task: dict) -> dict:
    """
    Ejecuta una prueba de conectividad (ping) para un host específico.

    Diseñada para ser utilizada como función worker dentro de
    estructuras concurrentes.

    El diccionario task debe contener:
        - 'host': Dirección IP u hostname del destino.

    Parámetros:
        task (dict): Diccionario con la información del host.

    Retorna:
        dict: Resultado retornado por la función execute_ping(),
              que normalmente incluye estado, latencia y posibles
              errores.
    """
    host = task['host']
    return execute_ping(host)


def ssh_worker(task: dict) -> dict:
    """
    Ejecuta una tarea SSH a partir de un diccionario de parámetros.

    Esta función está diseñada para usarse como worker en esquemas
    de concurrencia (por ejemplo, con ThreadPoolExecutor).

    El diccionario task debe contener al menos:
        - 'ip': Dirección IP u hostname del dispositivo.
        - 'usuario': Usuario SSH.
        - 'clave': Contraseña SSH.
        - 'comando': Comando a ejecutar.

    Opcionales:
        - 'timeout': Tiempo máximo de espera (default 10 segundos).
        - 'port': Puerto SSH (default 22).

    Parámetros:
        task (dict): Diccionario con los datos necesarios para la
                     conexión SSH.

    Retorna:
        dict:
            Resultado retornado por la función execute_ssh(),
            típicamente incluyendo estado, salida y posibles errores.
    """
    return execute_ssh(
        host=task['ip'],
        user=task['usuario'],
        password=task['clave'],
        command=task['comando'],
        timeout=task.get('timeout', 10),
        port=task.get('port', 22),
    )



