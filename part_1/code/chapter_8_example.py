# --------------------------------------------------------------------
# Definición de clases
# --------------------------------------------------------------------
class InventoryFormatError(Exception):
    pass


# --------------------------------------------------------------------
# Funciones auxiliares
# --------------------------------------------------------------------
def process_inventory_line(line):
    """
    Convierte una línea del archivo en un diccionario.
    Maneja errores de formato de archivo y estado de
    equipo inválido.
    """
    try:
        hostname, ip, vendor, status = line.split(',')
    except ValueError:
        raise InventoryFormatError(f'Formato inválido: {line}')

    if status not in ('0', '1'):
        raise ValueError(f'Status inválido en {hostname}: {status}')

    return {
        'hostname': hostname,
        'ip': ip,
        'vendor': vendor,
        'status': int(status)
    }


def process_inventory(filepath):
    """
    Lee el archivo y procesa cada línea.
    Retorna una lista de dispositivos válidos.
    """
    devices = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f'Archivo no encontrado: {filepath}')
        return []

    for line in lines:
        try:
            devices.append(process_inventory_line(line.strip()))
        except (InventoryFormatError, ValueError) as e:
            print(f'❗ Error: {e}')

    return devices


# --------------------------------------------------------------------
# Función principal
# --------------------------------------------------------------------
def main():
    try:
        devices = process_inventory('../data/chapter_8_inventory.csv')
        print(f'Dispositivos válidos: {len(devices)}')
    except Exception as e:
        print(f'❗ Error: {e}')


# --------------------------------------------------------------------
# Ejecución principal
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
