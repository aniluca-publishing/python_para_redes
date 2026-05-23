import time
from connectivity_tools import execute_ping
from concurrency_tools import execute_with_threads


def sequential_ping(ips):
    results = []
    for ip in ips:
        r = execute_ping(ip)
        results.append(r)
    return results


def ping_worker(ip):
    """
    Función para usar execute_ping como worker.
    """
    return execute_ping(ip)


def main():
    tasks = ['example.com'] * 20

    # -----------------------------------------------------
    # PING secuencial
    # -----------------------------------------------------
    print('===== Ping secuencial =====')
    t0 = time.perf_counter()
    results = sequential_ping(tasks)
    t1 = time.perf_counter()

    print(f"{' Host':<15} {'Estado'}")
    for r in results:
        print(f' {r["host"]:<15} {r["host_status"]}')

    print(f'Tiempo secuencial: {t1 - t0:.2f} segundos')

    # -----------------------------------------------------
    # PING concurrente
    # -----------------------------------------------------
    print('\n===== Ping concurrente con threads =====')
    t0 = time.perf_counter()
    results = execute_with_threads(ping_worker,
                                   tasks,
                                   max_workers=20)
    t1 = time.perf_counter()

    print(f"{' Host':<15} {'Estado'}")
    for r in results:
        print(f' {r["host"]:<15} {r["host_status"]}')

    print(f'Tiempo concurrente: {t1 - t0:.2f} segundos')


if __name__ == '__main__':
    main()
