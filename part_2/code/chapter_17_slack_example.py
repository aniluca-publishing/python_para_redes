from notification_tools import send_slack_notification
from datetime import datetime

WEBHOOK_URL = 'https://hooks.slack.com/services/xxxxx'


def main():
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    severity = 'CRITICAL'
    title = 'Equipo sin respuesta'
    details = (
        'Hostname: R1-GYE\n'
        'IP: 10.10.10.1\n'
        'Motivo: PING timeout'
    )

    text = (
        f'*{severity}* - {title}\n'
        f'{details}\n'
        f'_{now}_'
    )

    result = send_slack_notification(WEBHOOK_URL, text)

    if result['webhook_status'] == 'ok':
        print('Notificación enviada!')
    else:
        print(f'Error al enviar notificación: '
              f'{result["errors"]}')


if __name__ == '__main__':
    main()
