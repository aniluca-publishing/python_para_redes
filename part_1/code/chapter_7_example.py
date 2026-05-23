#
# --------------------------------------------------------------------
# Bloque import
# --------------------------------------------------------------------
import re


# --------------------------------------------------------------------
# Funciones auxiliares
# --------------------------------------------------------------------
def validate_if_name(if_name):
    """
    Valida que el nombre de la interfaz tenga el formato:
    FaX/Y, GiX/Y o TeX/Y.
    Ejemplos válidos: Fa0/0, Gi1/2, Te10/3.
    Retorna un valor booleano
    """
    if_pattern = r'^(Fa|Gi|Te)\d+/\d+$'
    return re.search(if_pattern, if_name) is not None


def process_inventory_line(line):
    """
    Convierte una línea del archivo en un diccionario.
    Maneja errores por nombre inválido o tráfico no numérico.
    """
    try:
        if_name, if_status, if_in_traffic = line.strip().split(',')
    except ValueError:
        print(f'❗ Error de formato en la línea: {line}')
        return None

    # Validar interfaz con regex
    if not validate_if_name(if_name):
        print(f'❗ Interfaz con nombre inválido: {if_name}')
        return None

    # Validar estado
    if if_status.lower() not in ['up', 'admin down', 'down']:
        print(f'❗ Interfaz con estado inválido: {if_name}: {if_status}')
        return None

    # Convertir tráfico entrante a float
    try:
        if_in_traffic = float(if_in_traffic)
    except ValueError:
        print(f'❗ Tráfico inválido en {if_name}: {if_in_traffic}')
        return None
    else:
        if if_in_traffic < 0:
            print(f'❗ Tráfico inválido en {if_name}: {if_in_traffic}')
            return None
    return {
        'if_name': if_name,
        'if_status': if_status.lower(),
        'if_in_traffic': if_in_traffic
    }


def process_inventory(file_path):
    """
    Lee el archivo y procesa cada línea.
    Retorna una lista de interfaces válidas.
    """
    try:
        # Abrimos el archivo en modo lectura
        with open(file_path, 'r', encoding='utf-8') as f:
            # Se carga el contenido del archivo en una lista
            lines = f.readlines()
    except FileNotFoundError:
        print(f'❗ Archivo no encontrado: {file_path}')
        return []

    interfaces = [process_inventory_line(l.strip()) for l in lines]
    return [i for i in interfaces if i]


# --------------------------------------------------------------------
# Función principal
# --------------------------------------------------------------------
def main():
    # Extraer la información del inventario
    file_path = '../data/chapter_7_inventory.csv'
    interfaces = process_inventory(file_path)
    if not interfaces:
        print('No se pudieron cargar interfaces.')
        return

    # Mostrar la lista de interfaces válidas
    print('\nInterfaces válidas:')

    for i, d in enumerate(interfaces):
        print(f' {i + 1}. {d["if_name"]}: {d["if_status"]}, '
              f'{d["if_in_traffic"]} Mbps')

    # Mostrar la interfaz con mayor tráfico
    max_traffic = max(interfaces, key=lambda x: x['if_in_traffic'])
    print(f'\nInterfaz con mayor tráfico:')
    print(f'  {max_traffic["if_name"]}: '
          f'{max_traffic["if_in_traffic"]} Mbps')

    # Generar un reporte del estado de las interfaces
    print('\nEstado de interfaces:')

    if all(i['if_status'] == 'up' for i in interfaces):
        print('  ✔ Todas están UP')
    else:
        down_if = [i['if_name'] for i in interfaces
                   if i['if_status'] == 'down']
        print(f'  ❗ Interfaces DOWN: {sorted(down_if)}')

    # Generar un reporte del tráfico
    print('\nInterfaces ordenadas por tráfico:')

    # Utilizamos key para ordenar por tráfico:
    for i in sorted(interfaces, key=lambda x: x['if_in_traffic']):
        print(f'  {i["if_name"]}: {i["if_in_traffic"]} Mbps')

    # Tráfico total y promedio
    total_traffic = sum(i['if_in_traffic'] for i in interfaces)
    avg_traffic = round(total_traffic / len(interfaces), 2)

    print('\nResumen de tráfico:')
    print(f'  Total: {round(total_traffic, 2)} Mbps')
    print(f'  Promedio: {avg_traffic} Mbps')


# --------------------------------------------------------------------
# Ejecución principal
# --------------------------------------------------------------------
if __name__ == '__main__':
    main()
