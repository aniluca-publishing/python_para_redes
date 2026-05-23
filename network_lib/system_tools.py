import platform
from typing import Optional


def get_os() -> Optional[str]:
    """ Detecta el sistema operativo local """
    so = platform.system().lower()
    if 'windows' in so:
        return 'windows'
    elif 'linux' in so:
        return 'linux'
    elif 'darwin' in so:
        return 'macos'
    return None
