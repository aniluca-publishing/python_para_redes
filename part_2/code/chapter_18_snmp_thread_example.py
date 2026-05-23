import time
from snmp_tools import snmp_walk
from concurrency_tools import execute_with_threads


def sequential_snmp(tasks):
    results = []
    for t in tasks:
        r = snmp_walk(
            host=t['host'],
            base_oid=t['oid'],
            version=t['version'],
            community=t['community'],
            timeout=10,
            bulk=True
        )
        results.append(r)
    return results


def snmp_worker(task):
    """
    Función para usar snmp_walk como worker.
    """
    return snmp_walk(
        host=task['host'],
        base_oid=task['oid'],
        version=task['version'],
        community=task['community'],
        timeout=10,
        bulk=True
    )


def main():
    tasks = [
        {
            'host': 'R1-GYE', 'oid': 'ifTable',
            'version': '2c', 'community': 'public'
        },
        {
            'host': 'SW1-GYE', 'oid': 'ifTable',
            'version': '2c', 'community': 'public'
        },
        {
            'host': 'R2-AMB', 'oid': 'ifTable',
            'version': '2c', 'community': 'public'
        },
        {
            'host': 'R2-UIO', 'oid': 'ifTable',
            'version': '2c', 'community': 'public'
        },
        {
            'host': 'R2-PVJ', 'oid': 'ifTable',
            'version': '2c', 'community': 'public'
        },
        {
            'host': 'R2-CUE', 'oid': 'ifTable',
            'version': '2c', 'community': 'public'
        },
    ]

    # -----------------------------------------------------
    # SNMP secuencial
    # -----------------------------------------------------
    print('===== SNMP secuencial =====')
    t0 = time.perf_counter()
    results = sequential_snmp(tasks)
    t1 = time.perf_counter()

    print(f"{' Host':<15} {'Resultado SNMP'}")
    for r in results:
        print(f" {r['host']:<15} {r['snmp_result']}")

    print(f"Tiempo secuencial: {t1 - t0:.2f} segundos")

    # -----------------------------------------------------
    # SNMP concurrente
    # -----------------------------------------------------
    print('\n===== SNMP concurrente con threads =====')
    t0 = time.perf_counter()
    results = execute_with_threads(snmp_worker, tasks)
    t1 = time.perf_counter()

    print(f"{' Host':<15} {'Resultado SNMP'}")
    for r in results:
        print(f" {r['host']:<15} {r['snmp_result']}")

    print(f"Tiempo concurrente: {t1 - t0:.2f} segundos")


if __name__ == '__main__':
    main()
