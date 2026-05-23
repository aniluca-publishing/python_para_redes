# --------------------------------------------------------------------
# Bloque import
# --------------------------------------------------------------------
from datetime import datetime
import os


# --------------------------------------------------------------------
# Funciones auxiliares
# --------------------------------------------------------------------
def register_log(msg, file='chapter_10_ssh_backup', folder='../data/logs'):
    """Registra un evento en un archivo de log."""
    os.makedirs(folder, exist_ok=True)
    filepath = f'{folder}/{file}.log'
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(f'{datetime.now()} - {msg}\n')


def ssh_connection(hostname, ip):
    """
    Simula una conexión SSH.
    Si el hostname es R2-UIO, fallará la conexión.
    Caso contrario, se retorna una "configuración básica"
    """
    if hostname == 'R2-UIO':
        raise ConnectionError(f'No se pudo conectar con {hostname} ({ip})')
    return (f'hostname {hostname}\n interface Lo\n '
            f'ip address {ip} 255.255.255.0')


def process_line(line):
    """Convierte una línea en un diccionario válido."""
    try:
        hostname, ip = line.strip().split(',')
    except ValueError:
        print(f'Línea inválida: {line.strip()} ❗')
        register_log(f'Línea inválida: {line.strip()} ❗')
        return None
    return {'hostname': hostname, 'ip': ip}


def save_config(hostname, config, folder='../data/configs'):
    """Guarda una configuración en un archivo con timestamp."""
    os.makedirs(folder, exist_ok=True)

    timestamp = datetime.now().strftime('%Y_%m_%d-%H_%M_%S')
    filepath = f'{folder}/{hostname}_{timestamp}.cfg'

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(config)

    register_log(f'Respaldo guardado correctamente: {filepath}')


# --------------------------------------------------------------------
# Función principal
# --------------------------------------------------------------------
def main():
    register_log('Iniciando proceso de respaldo!')
    print('Iniciando proceso de respaldo...\n')
    inventory_filepath = '../data/chapter_10_inventory.csv'

    # Intentar abrir inventario
    try:
        with open(inventory_filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        msg = f'No se encontró el archivo {inventory_filepath} ❗'
        print(msg)
        register_log(msg)
        return

    # Procesamos todo el inventario
    for line in lines:
        d = process_line(line)
        if not d:
            continue
        hostname, ip = d['hostname'], d['ip']
        try:
            config = ssh_connection(hostname, ip)
            save_config(hostname, config)
            print(f'Respaldo de {hostname} completado ✔')
        except Exception as e:
            register_log(f'Error: {e} ❗')
            print(f'Error con {hostname}: {e} ❗')

    print('\nProceso finalizado. Revisar logs y archivos en '
          'part_1/data/configs y part_1/data/logs.')
    register_log('Fin de proceso de respaldo!\n')


if __name__ == '__main__':
    main()
