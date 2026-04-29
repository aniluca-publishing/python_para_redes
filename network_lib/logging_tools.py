import logging


def create_logger(log_path: str, log_name: str) -> logging.Logger:
    """
    Crea y configura un logger para el sistema de respaldos.

    El logger:
        - Registra mensajes en archivo.
        - Muestra mensajes en consola.
        - Evita duplicar handlers si ya fue inicializado.

    Parámetros:
        log_path (str): Ruta completa del archivo de log.
        log_name (str): El nombre del log.

    Retorna:
        logging.Logger: Instancia configurada del logger.
    """
    logger = logging.getLogger(log_name)

    if not logger.handlers:
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s %(message)s'
        )

        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger
