from snmp_tools import snmp_walk


def main():
    oid_base = '1.3.6.1.2.1.31.1.1.1.1'  # ifName
    hosts_v2 = ['SW1-GYE', 'example.com']
    hosts_v3 = ['R1-AMB', 'example111.com']

    for host in hosts_v2 + hosts_v3:
        version = '2c' if host in hosts_v2 else '3'
        if version == '2c':
            r = snmp_walk(host, oid_base, version=version,
                          community='public')
        else:
            r = snmp_walk(host, oid_base, version=version,
                          username='user',
                          level='authPriv', auth_proto='MD5',
                          auth_pass='auth_pass',
                          priv_proto='DES',
                          priv_pass='priv_pass')
        print(f'----- SNMP WALK v{version} <{host}> -----')
        print(f" Resultado : {r['snmp_result']}")
        print(f" Estado    : {r['snmp_status']}")
        print(f" OIDs leídos: {len(r.get('oids', []))}")
        if r['errors']:
            print(f" Errores   : {r['errors']}")
        if r['snmp_result'] == 'ok':
            for oid_dict in r['oids']:
                oid = oid_dict['oid']
                oid_value = oid_dict['value']
                print(f'  {oid} =>  {oid_value}')
        print()


if __name__ == '__main__':
    main()
