#
# --------------------------------------------------------------------
# Funciones auxiliares
# --------------------------------------------------------------------
def process_inventory_line(line: str):
    """Convierte una línea CSV de inventario a diccionario"""
    hostname, ip, vendor, status = line.split(',')
    return {
        'hostname': hostname,
        'ip': ip,
        'vendor': vendor,
        'status': int(status)
    }


def process_inventory(inventory):
    """Convierte lista de líneas CSV en lista de diccionarios"""
    return [process_inventory_line(linea) for linea in inventory]


def get_vendors(devices):
    """Extrae fabricantes únicos de lista de dispositivos"""
    return sorted({d['vendor'] for d in devices})


def get_down_devices(devices):
    """Filtra dispositivos con estado de alarma (status=0)"""
    return [d for d in devices if d['status'] == 0]


# --------------------------------------------------------------------
# Función principal
# --------------------------------------------------------------------
def main():
    # Inventario en bruto, como si viniera de un archivo CSV
    inventory = [
        'R1-GYE,10.10.10.1,Cisco,1',
        'R1-UIO,10.10.20.1,Juniper,0',
        'R1-CUE,10.10.30.1,Cisco,1',
        'R2-GYE,10.10.40.1,Huawei,1',
        'R2-UIO,10.10.50.1,Huawei,1'
    ]

    devices = process_inventory(inventory)

    print(f'Marcas de equipos en la red: {get_vendors(devices)}')

    print('\nDispositivos alarmados:')
    for d in get_down_devices(devices):
        print(f"  {d['hostname']} ({d['ip']}) ❗")


# --------------------------------------------------------------------
# Ejecución principal
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
#
