import platform


def get_os():
    """ Detecta el sistema operativo local """
    so = platform.system().lower()
    if 'windows' in so:
        return 'windows'
    elif 'linux' in so:
        return 'linux'
    elif 'darwin' in so:
        return 'macos'
    return None
