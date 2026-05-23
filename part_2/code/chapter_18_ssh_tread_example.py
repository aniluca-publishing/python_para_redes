import time
from ssh_sftp_tools import execute_ssh
from concurrency_tools import execute_with_threads


def sequential_ssh(tasks):
    results = []
    for task in tasks:
        r = execute_ssh(task['host'],
                        task['user'],
                        task['password'],
                        task['command'])
        results.append(r)
    return results


def ssh_worker(task):
    """
    Función para usar execute_ssh como worker.
    """
    return execute_ssh(task['host'],
                       task['user'],
                       task['password'],
                       task['command'])


def main():
    tasks = [
        {
            'host': 'R1-GYE', 'user': 'user',
            'password': 'password', 'command': 'show clock'
        },
        {
            'host': 'SW1-GYE', 'user': 'user',
            'password': 'password', 'command': 'show clock'
        },
        {
            'host': 'R1-UIO', 'user': 'user',
            'password': 'password', 'command': 'show clock'
        },
        {
            'host': 'R1-CUE', 'user': 'user',
            'password': 'password', 'command': 'show clock'
        },
        {
            'host': 'R1-AMB', 'user': 'user',
            'password': 'password', 'command': 'display clock'
        },
    ]

    # -----------------------------------------------------
    # SSH secuencial
    # -----------------------------------------------------
    print('===== SSH secuencial =====')
    t0 = time.perf_counter()
    results = sequential_ssh(tasks)
    t1 = time.perf_counter()

    print(f"{' Host':<15} {'Resultado SSH'}")
    for r in results:
        print(f' {r["host"]:<15} {r["ssh_result"]}')

    print(f'Tiempo secuencial: {t1 - t0:.2f} segundos')

    # Esperamos un tiempo prudencial para
    # repetir las conexiones SSH, para evitar
    # bloqueos o rechazos en los equipos remotos
    time.sleep(10)

    # -----------------------------------------------------
    # SSH concurrente
    # -----------------------------------------------------
    print('\n===== SSH concurrente con threads =====')
    t0 = time.perf_counter()
    results = execute_with_threads(ssh_worker,
                                 tasks)
    t1 = time.perf_counter()

    print(f"{' Host':<15} {'Resultado SSH'}")
    for r in results:
        print(f' {r["host"]:<15} {r["ssh_result"]}')

    print(f'Tiempo concurrente: {t1 - t0:.2f} segundos')


if __name__ == '__main__':
    main()
