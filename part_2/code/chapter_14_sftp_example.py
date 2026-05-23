import os
from ssh_sftp_tools import execute_sftp


def main():
    hosts = ['SRV1-GYE', 'example.com', 'example111.com']
    user = 'user'
    password = 'password'
    local_dir = '../data/'
    remote_dir = '/home/aniluca'

    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

    for host in hosts:
        res = execute_sftp(
            host=host,
            user=user,
            password=password,
            remote_dir=remote_dir,
            local_dir=local_dir,
            suffix='.log',
            list_files=True,
            port=22
        )

        print('=' * 60)
        print(host)
        print('=' * 60)
        print(f" SFTP Result: {res['sftp_result']}")
        print(f" SFTP Status: {res['sftp_status']}")
        if res['errors']:
            print(f"  Errors: {res['errors']}")
        print(" Found Files:")
        for f in res['found']:
            print(f"    - {f}")
        print(" Downloaded Files:")
        for f in res['downloaded']:
            print(f"    {f}")
        print()


if __name__ == '__main__':
    main()
