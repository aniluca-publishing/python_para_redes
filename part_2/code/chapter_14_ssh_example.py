from ssh_sftp_tools import execute_ssh


def print_vendor_header(vendor):
    """Imprime una cabecera con el fabricante"""
    line = '#' * 70
    print('\n' + line)
    print(f'FABRICANTE: {vendor.upper()}')
    print(line)


def print_device_header(host):
    """Imprime una cabecera con el nombre del host"""
    line = '-' * 60
    print('\n' + line)
    print(f'{host}')
    print(line)


def print_multiline(label, text):
    """Imprime texto multilínea con sangrías"""
    if text:
        print(f'{label}:')
        for line in text.strip().splitlines():
            print(f'    {line}')
        print()


def main():
    device_profiles = {
        'cisco': {
            'hosts': ['R1-UIO', 'SW1-GYE'],
            'username': 'user1',
            'password': 'pass1',
            'command': 'show clock'
        },
        'linux': {
            'hosts': ['SRV1-GYE'],
            'username': 'user2',
            'password': 'pass2',
            'command': 'timedatectl'
        },
        'juniper': {
            'hosts': ['R1-PVJ'],
            'username': 'user3',
            'password': 'pass3',
            'command': 'show system uptime | match time'
        },
        'huawei': {
            'hosts': ['R2-GYE'],
            'username': 'user4',
            'password': 'pass4',
            'command': 'display clock'
        },
        'mikrotik': {
            'hosts': ['R1-ESM'],
            'username': 'user5',
            'password': 'pass5',
            'command': '/system clock print'
        }
    }

    for vendor, profile in device_profiles.items():

        print_vendor_header(vendor)

        target_hosts = profile['hosts']
        username = profile['username']
        password = profile['password']
        command = profile['command']

        for host in target_hosts:

            print_device_header(host)

            res = execute_ssh(host, username, password, command)

            print(f"Command    : {command}")
            print(f"SSH Status : {res['ssh_status']}")
            print(f"Exit Code  : {res['exit_code']}")
            print()

            print_multiline("STDOUT", res['stdout'])
            print_multiline("STDERR", res['stderr'])
            print_multiline("ERRORS", res['errors'])


if __name__ == '__main__':
    main()
