# --------------------------------------------------------------------
# Declaración del inventario
# --------------------------------------------------------------------
# Formato: hostname,ip,fabricante,estado
inventory = [
    'R1-GYE,10.10.10.1,Cisco,1',
    'R1-UIO,10.10.20.1,Juniper,0',
    'R1-CUE,10.10.30.1,Cisco,1',
    'R2-GYE,10.10.40.1,Huawei,1',
    'R2-UIO,10.10.50.1,Huawei,1'
]

# --------------------------------------------------------------------
# Extraer la información del inventario
# --------------------------------------------------------------------
# Creamos la lista de equipos
devices = []
# Leemos el inventario, línea por línea:
for line in inventory:
    # split() convierte un string en una lista.
    hostname, ip, vendor, status = line.split(',')
    device = {
        'hostname': hostname,
        'ip': ip,
        'vendor': vendor,
        'status': int(status)   # casting: convertir texto a número
    }
    devices.append(device)

# --------------------------------------------------------------------
# Listar los fabricantes
# --------------------------------------------------------------------
vendors = set()
for device in devices:
    vendors.add(device['vendor'])


# --------------------------------------------------------------------
# Listar los dispositivos alarmados
# --------------------------------------------------------------------
# Recuerda que status = 0 se usa para equipos alarmados.
devices_down = []
for device in devices:
    if device['status'] == 0:
        devices_down.append(device)

# --------------------------------------------------------------------
# Generar resultados
# --------------------------------------------------------------------
print(f'Marcas de equipos en la red: {sorted(vendors)}')
print('\nDispositivos alarmados: ')
for d in devices_down:
    print(f"  ❗{d['hostname']} ({d['ip']})")
