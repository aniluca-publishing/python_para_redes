from connectivity_tools import execute_ping


def main():
    hosts = ['127.0.0.1', 'example.com', 'example111.com']
    for host in hosts:
        # Ejecutamos el ping y guardamos en un diccionario
        ping = execute_ping(host, count=5)
        print(f'--- Resultados de ping para <{host}> ---')
        print(f'  Ejecución del Comando: {ping["ping_result"]}')
        if ping['ping_result'] != 'ok':
            print(f' Errores: "{ping["errors"]}"\n')
            continue

        # Imprimimos los resultados de ping
        print(f'  Estado: {ping["host_status"]}')

        # Agregamos un % a la pérdida si es diferente a None
        loss = ping['loss']
        if loss is not None:
            loss = str(loss) + '%'
        print(f'  Pérdida: {loss}')

        # Agregamos ms si rtt es diferente a None
        rtt = ping['rtt']
        if rtt is not None:
            rtt = str(rtt) + ' ms'
        print(f'  RTT: {rtt}')

        # Imprimimos los errores
        if ping["errors"]:
            print(f'  Errores: "{ping["errors"]}"')
        print()


if __name__ == '__main__':
    main()
