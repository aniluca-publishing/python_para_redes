from snmp_tools import snmp_get


def main():
    oid = '1.3.6.1.2.1.1.5.0'  # sysName
    hosts_v2 = ['SW1-GYE', 'example.com']
    hosts_v3 = ['R1-AMB', 'example111.com']

    for host in hosts_v2 + hosts_v3:
        version = '2c' if host in hosts_v2 else '3'
        if version == '2c':
            r = snmp_get(host, oid, version=version,
                         community='public')
        else:
            r = snmp_get(host, oid, version=version,
                         username='user',
                         level='authPriv', auth_proto='MD5',
                         auth_pass='pass1',
                         priv_proto='DES',
                         priv_pass='pass2')
        print(f'----- SNMP GET v{version} <{host}> -----')
        print(f" Resultado : {r['snmp_result']}")
        print(f" Estado    : {r['snmp_status']}")
        print(f" Valor     : {r['value']}")
        if r['errors']:
            print(f" Errores   : {r['errors']}")
        print()


if __name__ == '__main__':
    main()
