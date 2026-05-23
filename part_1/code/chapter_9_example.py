# --------------------------------------------------------------------
# Clase base e hijas
# --------------------------------------------------------------------
class Device:
    """
    Representa un dispositivo genérico de red.
    """
    def __init__(self, hostname, ip, vendor, status=1):
        self.hostname = hostname
        self.ip = ip
        self.vendor = vendor
        self.status = status  # 1 = UP, 0 = DOWN (sin comunicación/alarmado)

    def is_up(self):
        """Retorna True si el dispositivo está operativo."""
        return self.status == 1

    def mark_down(self):
        """Marca el dispositivo como DOWN."""
        self.status = 0

    def summary(self):
        """Retorna un mensaje con información básica."""
        estado = 'UP' if self.is_up() else 'DOWN'
        return f'{self.hostname} ({self.ip}) - {self.vendor} - {estado}'


class Router(Device):
    """
    Representa un router. Extiende Device
    agregando información de modelo y protocolos.
    """
    def __init__(self, hostname, ip, vendor, model, status=1):
        super().__init__(hostname, ip, vendor, status)
        self.model = model
        self.protocols = []  # por ejemplo: ['OSPF', 'BGP']

    def add_protocol(self, protocol):
        """Agrega un protocolo de enrutamiento si no está repetido"""
        if protocol not in self.protocols:
            self.protocols.append(protocol)

    def print_protocols(self):
        """Imprime un mensaje con los protocolos configurados"""
        if not self.protocols:
            print(f' {self.hostname}: sin protocolos configurados ❗')
        else:
            _ = ', '.join(self.protocols)
            print(f' {self.hostname}: protocolos: {_}')

    def summary(self):
        """Retorna un mensaje de resumen del Router"""
        base = super().summary()
        return f'{base} - Router {self.model}'


class Switch(Device):
    """
    Representa un switch. Extiende Device
    agregando el manejo básico de VLANs.
    """
    def __init__(self, hostname, ip, vendor, status=1):
        super().__init__(hostname, ip, vendor, status)
        self.vlans = set()

    def add_vlan(self, vlan):
        """Agrega una VLAN al switch"""
        if not isinstance(vlan, int) or not (1 <= vlan <= 4094):
            raise ValueError('La VLAN debe ser un entero entre 1 y 4094')
        self.vlans.add(vlan)

    def has_vlan(self, vlan):
        """Verifica si una VLAN está configurada"""
        return vlan in self.vlans

    def summary(self):
        """Retorna un mensaje con las VLANs configuradas"""
        base = super().summary()
        if self.vlans:
            vlans_str = ','.join(str(v) for v in sorted(self.vlans))
            return f'{base} - Switch (VLANs: {vlans_str})'
        return f'{base} - Switch (sin VLANs) ❗'


# --------------------------------------------------------------------
# Clase para gestionar el inventario completo
# --------------------------------------------------------------------
class NetInventory:
    """
    Administra una colección de dispositivos de red.
    """

    def __init__(self):
        self.devices = []
        self.routers = []
        self.switches = []

    def add_device(self, device):
        """Agrega un dispositivo al inventario."""
        self.devices.append(device)
        if isinstance(device, Router):
            self.routers.append(device)
        elif isinstance(device, Switch):
            self.switches.append(device)

    def up_devices(self):
        """Retorna la lista de dispositivos operativos."""
        return [d for d in self.devices if d.is_up()]

    def down_devices(self):
        """Retorna la lista de dispositivos caídos."""
        return [d for d in self.devices if not d.is_up()]

    def by_vendor(self):
        """
        Retorna un diccionario con el conteo de
        dispositivos agrupados por fabricante.
        """
        count = {}
        for d in self.devices:
            count[d.vendor] = count.get(d.vendor, 0) + 1
        return count

    def print_summary(self):
        """Imprime un resumen general del inventario."""
        print('--- Inventario de dispositivos ---')
        for d in self.devices:
            print(f' {d.summary()}')

        print('\n--- Resumen de estados ---')
        print(' Dispositivos UP:', len(self.up_devices()))
        print(' Dispositivos DOWN:', len(self.down_devices()))

        print('\n--- Dispositivos por fabricante ---')
        for vendor, cantidad in self.by_vendor().items():
            print(f'  {vendor}: {cantidad}')


# --------------------------------------------------------------------
# Función principal
# --------------------------------------------------------------------
def main():
    inventory = NetInventory()

    # Routers
    r1 = Router('R1-GYE', '10.10.10.1', 'Cisco', 'ASR-1001', status=1)
    r1.add_protocol('OSPF')
    r1.add_protocol('BGP')

    r2 = Router('R1-UIO', '10.10.20.1', 'Juniper', 'MX-204', status=0)
    r2.add_protocol('OSPF')

    r3 = Router('R1-CUE', '10.10.30.1', 'Huawei', 'NE40E', status=1)

    # Switches
    s1 = Switch('SW1-GYE', '10.10.11.1', 'Cisco', status=1)
    s1.add_vlan(10)
    s1.add_vlan(20)

    s2 = Switch('SW1-UIO', '10.10.21.1', 'Huawei', status=1)
    s2.add_vlan(100)

    s3 = Switch('SW1-CUE', '10.10.31.1', 'Juniper', status=1)

    # Agregar al inventario
    inventory.add_device(r1)
    inventory.add_device(r2)
    inventory.add_device(r3)
    inventory.add_device(s1)
    inventory.add_device(s2)
    inventory.add_device(s3)

    # Mostrar protocolos por router
    print('--- Protocolos por router ---')
    for r in inventory.routers:
        r.print_protocols()

    # Validar VLAN crítica
    critical_vlan = 100
    print(f'\n--- Validando VLAN crítica {critical_vlan} ---')
    for s in inventory.switches:
        if s.has_vlan(critical_vlan):
            print(f' {s.hostname}: VLAN {critical_vlan} presente ✔️')
        else:
            print(f' {s.hostname}: VLAN {critical_vlan} NO configurada ❗')

    # Mostrar resumen general
    print()
    inventory.print_summary()


# --------------------------------------------------------------------
# Ejecución principal
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
