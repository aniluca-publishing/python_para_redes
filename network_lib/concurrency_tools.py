from concurrent.futures import ThreadPoolExecutor, as_completed


def execute_with_threads(worker_function,
                         tasks: list,
                         max_workers: int = 20,
                         show_progress: bool = False) -> list:
    """
    Ejecuta worker_function(task) concurrentemente para cada tarea.
    Retorna una lista con los resultados no nulos.

    worker_function debe:
      - Recibir un solo parámetro (por ejemplo, una IP)
      - Devolver un resultado (por ejemplo, un dict o una tupla)
      - Devolver None si quieres ignorar el resultado
    """
    results = []

    if not tasks:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(worker_function,
                            task): task for task in tasks
        }

        for i, future in enumerate(as_completed(futures), start=1):
            task = futures[future]
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as e:
                print(f'[ERROR] Tarea falló para {task}: {e}')

            if show_progress:
                print(f'[DEBUG] Completadas {i}/{len(tasks)}')

    return results
