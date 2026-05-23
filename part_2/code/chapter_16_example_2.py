import requests

# Reemplaza por tu clave de API de AbuseIPDB
API_KEY = 'TU_API_KEY'


def get_public_ip(timeout=5):
    """
    Consulta la IP pública actual usando ipify.

    Retorna:
    - IP pública como string.
    - None si la consulta falla.
    """
    url = 'https://api.ipify.org?format=json'

    try:
        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            return None

        data = response.json()
        return data.get('ip')

    except (requests.RequestException, ValueError):
        return None


def check_ip_reputation(ip, api_key, max_age_days=90,
                        timeout=10):
    """
    Consulta la reputación de una IP usando AbuseIPDB.

    Retorna:
    - data: respuesta JSON convertida a diccionario.
    - status_code: código HTTP.
    - error_text: detalle del error, si existe.
    """
    url = 'https://api.abuseipdb.com/api/v2/check'

    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }

    params = {
        'ipAddress': ip,
        'maxAgeInDays': max_age_days
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=timeout
        )

        if response.status_code != 200:
            return None, response.status_code, response.text

        return response.json(), response.status_code, response.text

    except (requests.RequestException, ValueError) as e:
        return None, None, str(e)


def classify_score(score):
    """
    Clasifica el puntaje de abuso de forma simple.
    """
    if score == 0:
        return 'Sin reportes recientes'
    elif score < 25:
        return 'Riesgo bajo'
    elif score < 75:
        return 'Riesgo medio'
    else:
        return 'Riesgo alto'


def print_reputation(ip=None):
    if not ip:
        ip = get_public_ip()

    if not ip:
        print('No se pudo obtener la IP pública.')
        return

    data, status_code, response_text = check_ip_reputation(ip, API_KEY)

    if status_code in [401, 403]:
        print('Error de autenticación o permisos.')
        print('Respuesta:', response_text)
        return

    if status_code == 429:
        print('Límite de consultas alcanzado.')
        return

    if not data:
        print('No se pudo obtener información.')
        print('Detalle:', response_text)
        return

    info = data.get('data', {})
    score = info.get('abuseConfidenceScore', 0)
    classification = classify_score(score)

    print(f'===== REPUTACIÓN DE {ip} =====')
    print('Tipo de uso         :', info.get('usageType'))
    print('ISP                 :', info.get('isp'))
    print('Dominio             :', info.get('domain'))
    print('País                :', info.get('countryCode'))
    print('Total de reportes   :', info.get('totalReports'))
    print('Último reporte      :', info.get('lastReportedAt'))
    print('Score de abuso      :', score)
    print('Clasificación       :', classification, '\n')


if __name__ == '__main__':
    print_reputation()
    print_reputation('8.8.8.8')
