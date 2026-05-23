from snmp_tools import snmp_set, snmp_get


def main():
    oid = '1.3.6.1.2.1.1.4.0'  # sysContact
    new_syscontact = 'AniLuca Solutions'
    hosts_v2 = ['SRV1-GYE', 'example.com']
    hosts_v3 = ['SRV2-GYE', 'example111.com']

    for host in hosts_v2 + hosts_v3:
        version = '2c' if host in hosts_v2 else '3'

        # Validar el antiguo valor
        if version == '2c':
            v = snmp_get(host, oid, version=version,
                         community='private')['value']
        else:
            v = snmp_get(host, oid, version=version,
                         username='yser',
                         level='authPriv', auth_proto='SHA',
                         auth_pass='auth_pass',
                         priv_proto='AES',
                         priv_pass='priv_pass')['value']

        # Configurar el nuevo valor
        if version == '2c':
            r = snmp_set(host, oid, version=version,
                         set_type='s', set_value=new_syscontact,
                         community='private')
        else:
            r = snmp_set(host, oid, version=version,
                         set_type='s', set_value=new_syscontact,
                         username='myv3user',
                         level='authPriv', auth_proto='SHA',
                         auth_pass='auth_pass',
                         priv_proto='AES',
                         priv_pass='priv_pass')

        print(f"----- SNMP SETv{version} <{host}> -----")
        print(f"Estado            : {r['snmp_status']}")
        print(f"OID               : {r['oid']}")
        print(f"Antiguo valor     : {v}")
        print(f"Valor configurado : {r['value']}")
        print(f"Errores           : {r['errors']}")
        print()


if __name__ == '__main__':
    main()
