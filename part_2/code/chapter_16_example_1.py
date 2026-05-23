from api_tools import get_ip_info, extract_host, resolve_host_ips


def main():
    urls = [
        'https://www.google.com',
        'https://www.cloudflare.com',
        'example.com',
        'example111.com'
    ]

    for url in urls:
        print(f'\n===== Analizando: {url} =====')
        host = extract_host(url)

        if not host:
            print('No se pudo extraer el host.')
            continue

        print(f'Host: {host}')

        ips = resolve_host_ips(host)
        if not ips:
            print('No se encontraron IPs para este host.')
            continue

        print(f"IPs asociadas: {', '.join(ips)}")

        print(f"\n{'IP':<16} {'Continente':<12} "
              f"{'País':<15} {'Ciudad':<15} "
              f"{'ASN':<10} {'Organización':<25}")

        for ip in ips:
            # Obtenemos datos de la IP con la API
            data = get_ip_info(ip)
            if not data:
                print(f"{ip:<16} {'N/A':<12} "
                      f"{'N/A':<15} {'N/A':<15} "
                      f"{'N/A':<10} {'Error API':<25}")
                continue

            continent = data.get('continent', 'N/A')
            country = data.get('countryName', 'N/A')
            city = data.get('cityName', 'N/A')
            asn = data.get('asn', 'N/A')
            org = data.get('asnOrganization', 'N/A')

            print(f'{ip:<16} {continent:<12} '
                  f'{country:<15} {city:<15} '
                  f'{asn:<10} {org:<25}')


if __name__ == '__main__':
    main()
