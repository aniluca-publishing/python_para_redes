# --------------------------------------------------------------------
# Declaración del inventario
# --------------------------------------------------------------------
# Formato: hostname,ip,lista_de_vlans_separadas_por_|
vlans_inventory = [
    'SW1-GYE,10.10.10.10,10|20|99|100|200',
    'SW1-UIO,10.10.20.10,10|20|30',
    'SW1-CUE,10.10.30.10,99|100|200|300',
    'SW2-GYE,10.10.40.10,20|30|40',
    'SW2-UIO,10.10.50.10,10|99|100|200'
]

# --------------------------------------------------------------------
# Extraer la información del inventario
# --------------------------------------------------------------------
# Creamos una lista de diccionarios
devices = []
for line in vlans_inventory:
    hostname, ip, vlans_raw = line.split(',')
    # Convertimos las vlans a int con list comprehension
    vlans = [int(v) for v in vlans_raw.split('|')]
    # Creamos un diccionario por cada dispositivo
    device = {
        'hostname': hostname,
        'ip': ip,
        'vlans': vlans
    }
    devices.append(device)


# --------------------------------------------------------------------
# Listar las vlans configuradas en la red
# --------------------------------------------------------------------
# Obtener las vlans únicas, utilizando set comprehension
vlans = {vlan for d in devices for vlan in d['vlans']}
print(f'VLANs presentes en la red: {sorted(vlans)}')

# --------------------------------------------------------------------
# Verificar si la VLAN crítica está configurada
# --------------------------------------------------------------------
vlan_critical = 99
print(f'\nRevisando si la VLAN {vlan_critical} está configurada...')
for d in devices:
    for vlan in d['vlans']:
        if vlan == vlan_critical:
            print(f'  {d["hostname"]} → VLAN presente ✔️')
            break
    else:
        # Este else SOLO se ejecuta si NO se ejecutó el break
        print(f'  {d["hostname"]} → VLAN NO configurada ❗')

# --------------------------------------------------------------------
# Obtener las vlans faltantes en cada equipo
# --------------------------------------------------------------------
# Declarar las vlans que queremos comparar:
vlans_clients = {10, 20, 30, 40, 100, 200}
print('\nVLANs faltantes por dispositivo:')
for d in devices:
    # Usamos operaciones de sets para validar las vlans faltantes
    vlans_configured = set(d['vlans'])
    vlans_missing = vlans_clients - vlans_configured
    vlans_sorted = sorted(vlans_missing)
    print(f"  {d['hostname']} → {vlans_sorted}")
