from connectivity_tools import execute_traceroute


def main():
    hosts = [
        'example.com',
        'example111.com',
        '10.0.0.0',
        '127.0.0.1'
    ]

    for host in hosts:
        print(f'--- Resultados de traceroute para <{host}> ---')

        tr = execute_traceroute(host)
        print(f' Ejecución del Comando: {tr["traceroute_result"]}')
        print(f' Estado de la Traza: {tr["trace_status"]}')
        if tr['errors']:
            print(f' Errores: "{tr["errors"]}"')

        if tr['trace_status'] == 'ok':
            print(' Saltos:')
            for hop in tr['hops']:
                ips_str, rtt = 'N/A', 'N/A'
                if hop['hop_ips']:
                    ips_str = ', '.join(hop['hop_ips'])
                if hop['hop_avg_rtt'] is not None:
                    rtt = str(hop['hop_avg_rtt']) + ' ms'
                print(
                    f'  -Salto {hop["hop_number"]}: '
                    f'{hop["hop_result"]}, '
                    f'IPs: <{ips_str}>, '
                    f'RTT: {rtt}, '
                    f'Pérdidas: {hop["hop_loss"]} %'
                )
        print()


if __name__ == '__main__':
    main()
