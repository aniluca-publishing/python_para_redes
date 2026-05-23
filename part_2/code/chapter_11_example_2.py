import re

text = '''
R1-GYE#show ip int br
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.1.1.1        YES NVRAM  up                    up
GigabitEthernet0/1     unassigned      YES unset  administratively down down
Loopback0              172.16.0.1      YES NVRAM  up                    up
'''

# Primera columna
interface = r'^(\S+)'
# Segunda columna
ip = r'(\S+)'
# Tercera columna
ok = r'\S+'
# Cuarta columna
method = r'\S+'
# Quinta columna
interface_status = r'(administratively down|up|down)'
# Sexta columna
protocol_status = r'(up|down)'
# Espacios en blanco
blanks = r'\s+'

pattern = (interface +
           blanks +
           ip +
           blanks +
           ok +
           blanks +
           method +
           blanks +
           interface_status +
           blanks +
           protocol_status)

for m in re.finditer(pattern, text, flags=re.M):
    print('Interfaz :', m.group(1))
    print('IP       :', m.group(2))
    print('Estado   :', m.group(3))
    print('Protocolo:', m.group(4))
    print()

