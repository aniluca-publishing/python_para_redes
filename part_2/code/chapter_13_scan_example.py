# main_scan.py
from security_tools import scan_ports, common_tcp_ports


def main():
    hosts = ['example.com',
             'example1.com',
             'mail.google.com',
             '127.0.0.1',
             'example111.com']
    ports = common_tcp_ports

    for host in hosts:
        print(f'----- Escaneo de puertos en <{host}> -----')
        scan = scan_ports(host, ports, timeout=1)

        print(f'  Resultado del escaneo: {scan["scan_result"]}')
        print(f'  Estado del escaneo: {scan["scan_status"]}')
        if scan['errors']:
            print(f'  Errores: "{scan["errors"]}"')

        results = scan['results']

        opened = sorted(
            int(r['port']) for r in results
            if r['port_result'] == 'ok' and r['port_status'] == 'open'
        )
        opened = [str(x) for x in opened]

        filtered = sorted(
            int(r['port']) for r in results
            if r['port_result'] == 'ok' and r['port_status'] == 'filtered'
        )
        filtered = [str(x) for x in filtered]

        closed = sorted(
            int(r['port']) for r in results
            if r['port_result'] == 'ok' and r['port_status'] == 'closed'
        )
        closed = [str(x) for x in closed]

        print(f'  Abiertos: {", ".join(opened)}')
        print(f'  Filtrados: {", ".join(filtered)}')
        print(f'  Cerrados: {", ".join(closed)}')
        print()


if __name__ == '__main__':
    main()
