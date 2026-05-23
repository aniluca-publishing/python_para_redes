import time
import socket
import paramiko
import stat
import os
import logging
logging.getLogger('paramiko').setLevel(logging.CRITICAL)


def execute_ssh(
        host: str,
        user: str,
        password: str,
        command: str,
        timeout: int = 5,
        port: int = 22,
        retries: int = 3,
        retry_delay: int = 1) -> dict:
    """
    Ejecuta un comando remoto usando SSH (paramiko), incorporando
    mecanismo de reintentos ante errores transitorios.

    Parámetros:
    - host: str → Dirección IP o hostname.
    - user: str → Usuario SSH.
    - password: str → Password SSH.
    - command: str → Comando a ejecutar remotamente.
    - timeout: int → Tiempo máximo (segundos) para conexión
      y ejecución.
    - port: int → Puerto SSH (default 22).
    - retries: int → Número máximo de intentos ante fallos
      transitorios (default 3).
    - retry_delay: int  → Tiempo de espera (segundos)
      entre intentos.

    Comportamiento:
    - Reintenta ante errores transitorios como:
        * timeout
        * SSHException (por ejemplo, problemas de banner)
        * errores de red temporales
    - No reintenta ante errores definitivos como:
        * auth_failed
        * dns_error

    Retorna un diccionario con:
    - host
    - command
    - ssh_result: 'ok' | 'error'
    - ssh_status: 'success' | 'auth_failed' | 'timeout' |
                  'dns_error' | 'unreachable' |
                  'ssh_error' | 'unknown'
    - stdout: str
    - stderr: str
    - exit_code: int | None
    - time_ms: float | None
    - errors: str
    """
    ssh_status = 'unknown'
    errors = 'Host, usuario, password o comando inválido'
    if not host or not user or not password or not command:
        return {
            'host': host,
            'command': command,
            'ssh_result': 'error',
            'ssh_status': ssh_status,
            'stdout': '',
            'stderr': '',
            'exit_code': None,
            'time_ms': None,
            'errors': errors
        }

    attempt = 0

    while attempt < retries:
        attempt += 1
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        t0 = time.perf_counter()

        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=timeout,
                banner_timeout=timeout + 2,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )

            stdin, stdout, stderr = \
                client.exec_command(command, timeout=timeout)
            stdout.channel.settimeout(timeout)
            stderr.channel.settimeout(timeout)

            out = stdout.read().decode(errors='replace').strip()
            err = stderr.read().decode(errors='replace').strip()
            exit_code = stdout.channel.recv_exit_status()

            t1 = time.perf_counter()
            time_ms = round((t1 - t0) * 1000, 2)

            return {
                'host': host,
                'command': command,
                'ssh_result': 'ok',
                'ssh_status': 'success',
                'stdout': out,
                'stderr': err,
                'exit_code': exit_code,
                'time_ms': time_ms,
                'errors': ''
            }

        except socket.gaierror:
            ssh_status = 'dns_error'
            errors = 'Fallo en la resolución DNS'
            break  # no retry

        except (socket.timeout, TimeoutError):
            ssh_status = 'timeout'
            errors = 'Timeout en SSH (conexión o ejecución)'

        except paramiko.AuthenticationException:
            ssh_status = 'auth_failed'
            errors = 'Autenticación fallida'
            break  # no retry

        except paramiko.SSHException as e:
            ssh_status = 'ssh_error'
            errors = str(e)

        except OSError as e:
            ssh_status = 'unreachable'
            errors = str(e)

        except Exception as e:
            ssh_status = 'unknown'
            errors = str(e)

        finally:
            try:
                client.close()
            except Exception:
                pass

        # Si llegamos aquí, hubo un error
        # Tratamos de establecer nuevamente la conexión
        if attempt < retries:
            time.sleep(retry_delay)

    return {
        'host': host,
        'command': command,
        'ssh_result': 'error',
        'ssh_status': ssh_status,
        'stdout': '',
        'stderr': '',
        'exit_code': None,
        'time_ms': None,
        'errors': errors
    }


def execute_sftp(
    host: str,
    user: str,
    password: str,
    remote_dir: str,
    local_dir: str = '',
    timeout: int = 10,
    port: int = 22,
    explore_subdirs: bool = False,
    suffix: str = '',
    contains: str = '',
    list_files: bool = False,
    retries: int = 3,
    retry_delay: int = 1
) -> dict:
    """
    Recorre un directorio remoto por SFTP, filtrando archivos
    por nombre y opcionalmente descargándolos.

    Esta función establece una conexión SFTP sobre SSH y
    lista el contenido del directorio indicado. Si
    explore_subdirs=True, recorre subdirectorios de
    forma recursiva.
    También permite aplicar filtros por:

    - suffix
    - contains

    Si list_files=True, únicamente lista los archivos encontrados.
    Si list_files=False, descarga los archivos que cumplen
    los criterios al directorio local actual.

    Retorna:
    - host
    - sftp_result: 'ok' | 'error'
    - sftp_status: 'listed_only' | 'downloaded' | 'no_matches' | 'unknown'
    - found: list[str]
    - downloaded: list[str]
    - errors: str | ''
    """

    def name_matches_filters(name):
        """
        Evalúa si el nombre cumple los filtros configurados.
        Si no hay filtros: acepta todo.
        """
        # Sin filtros → aceptar todo
        if not contains and not suffix:
            return True

        # Solo suffix
        if suffix and not contains:
            return name.endswith(suffix)

        # Solo contains
        if contains and not suffix:
            return contains in name

        # Ambos filtros: AND
        return contains in name and name.endswith(suffix)

    def explore(path):
        """
        Recorre un directorio remoto vía SFTP.
        Si explore_subdirs=True, explora subdirectorios.

        - Si encuentra subdirectorios, continúa explorando.
        - Si encuentra archivos, aplica los filtros definidos.
        - Agrega las rutas remotas a files_found.
        - Si list_files=False, descarga los archivos al
          directorio local indicado (local_dir) y los agrega
          a files_downloaded.
          Si local_dir está vacío, se usa el directorio actual.
        """
        for item in sftp.listdir_attr(path):
            file_name = item.filename
            file_path = f'{path}/{file_name}'
            is_dir = stat.S_ISDIR(item.st_mode)

            if is_dir:
                if explore_subdirs:
                    explore(file_path)
                continue

            if not name_matches_filters(file_name):
                continue

            files_found.append(file_path)

            if not list_files:
                local_path = file_name
                if local_dir:
                    local_path = os.path.join(local_dir, file_name)
                sftp.get(file_path, local_path)
                files_downloaded.append(local_path)

    # Validación básica
    if not host or not user or not password or not remote_dir:
        return {
            'host': host,
            'sftp_result': 'error',
            'sftp_status': 'unknown',
            'found': [],
            'downloaded': [],
            'errors': 'Host, usuario, password o ruta inválida'
        }

    attempt = 0
    sftp_status = 'unknown'
    errors = 'Error desconocido'

    while attempt < retries:
        attempt += 1

        files_found = []
        files_downloaded = []

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=timeout,
                banner_timeout=timeout + 2,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )

            sftp = client.open_sftp()
            sftp.get_channel().settimeout(timeout)

            explore(remote_dir)

            if not files_found:
                sftp_status = 'no_matches'
            elif list_files:
                sftp_status = 'listed_only'
            else:
                sftp_status = 'downloaded'

            return {
                'host': host,
                'sftp_result': 'ok',
                'sftp_status': sftp_status,
                'found': files_found,
                'downloaded': files_downloaded,
                'errors': ''
            }

        except socket.gaierror:
            sftp_status = 'dns_error'
            errors = 'Fallo en la resolución DNS'
            break  # no retry

        except paramiko.AuthenticationException:
            sftp_status = 'auth_failed'
            errors = 'Autenticación fallida'
            break  # no retry

        except (socket.timeout, TimeoutError):
            sftp_status = 'timeout'
            errors = 'Timeout en SFTP (listado o descarga)'

        except paramiko.SSHException as e:
            sftp_status = 'sftp_error'
            errors = str(e)

        except OSError as e:
            sftp_status = 'unreachable'
            errors = str(e)

        except Exception as e:
            sftp_status = 'unknown'
            errors = str(e)

        finally:
            try:
                client.close()
            except Exception:
                pass

        if attempt < retries:
            time.sleep(retry_delay)

    return {
        'host': host,
        'sftp_result': 'error',
        'sftp_status': sftp_status,
        'found': [],
        'downloaded': [],
        'errors': errors
    }
