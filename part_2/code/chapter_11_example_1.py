import re

output = """
SW1-GYE# show vlan
VLAN Name                             Status    Ports
1    default                          active    Gi0/1, Gi0/2
10   CLIENTES                         active    Gi0/3
20   SERVIDORES                       active    Gi0/4, Gi0/5
100  GESTION                          active    Gi0/24
"""

pattern = r'^\s*(\d+)\s+([A-Za-z0-9_-]+)\s+'

for m in re.finditer(pattern, output, flags=re.M):
    vlan_number, vlan_name = m.groups()
    print(f'VLAN {vlan_number} - {vlan_name}')
