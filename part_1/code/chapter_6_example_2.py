#
# --------------------------------------------------------------------
# Funciones auxiliares
# --------------------------------------------------------------------
def process_inventory_line(line):
    """Convierte una línea CSV de inventario a diccionario"""
    hostname, ip, vlans_raw = line.split(',')
    vlans = [int(v) for v in vlans_raw.split('|')]
    return {'hostname': hostname, 'ip': ip, 'vlans': vlans}


def process_vlans_inventory(inventory):
    """Convierte lista de líneas CSV en lista de diccionarios"""
    return [process_inventory_line(linea) for linea in inventory]


def get_vlans(devices):
    """Extrae vlans únicas de lista de dispositivos"""
    return sorted({v for d in devices for v in d["vlans"]})


def get_vlan_diagnosis(device, vlan):
    """Retorna un mensaje respecto al estado de la vlan"""
    if vlan in device['vlans']:
        return f"  {device['hostname']} → VLAN presente ✔️"
    return f"  {device['hostname']} → VLAN NO configurada ❗"


def get_missing_vlans(device, vlans_clients):
    """Calcula las VLANs faltantes usando sets."""
    return sorted(vlans_clients - set(device['vlans']))


# --------------------------------------------------------------------
# Función principal
# --------------------------------------------------------------------

def main(vlan_critical=99):
    # Inventario en bruto, simulado
    vlans_inventory = [
        'SW1-GYE,10.10.10.10,10|20|99|100|200',
        'SW1-UIO,10.10.20.10,10|20|30',
        'SW1-CUE,10.10.30.10,99|100|200|300',
        'SW2-GYE,10.10.40.10,20|30|40',
        'SW2-UIO,10.10.50.10,10|99|100|200'
    ]

    devices = process_vlans_inventory(vlans_inventory)

    print(f'VLANs presentes en la red: {get_vlans(devices)}')

    print(f"\nRevisando si la VLAN {vlan_critical} está configurada..")
    for d in devices:
        print(get_vlan_diagnosis(d, vlan_critical))

    vlans_clients = {10, 20, 30, 40, 100, 200}
    print("\nVLANs faltantes por dispositivo:")
    for d in devices:
        print(f"  {d['hostname']} → {get_missing_vlans(d, vlans_clients)}")


# --------------------------------------------------------------------
# Ejecución principal
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
