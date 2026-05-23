from notification_tools import send_email_smtp
from datetime import datetime
from time import sleep


SMTP_HOST = 'smtp.gmail.com'
SMTP_USER = 'aniluca@gmail.com'
# Si envías por Gmail, esta es la contraseña de aplicación:
SMTP_PASSWORD = 'anil ucaa nilu caan'


def main():
    receivers = ['aniluca@example.com',
                 'aniluca@example1.com']
    for receiver in receivers:
        email = send_email_smtp(
            to_email=receiver,
            subject='Pruebas Python',
            body=(f'Notificación de prueba, '
                  f'enviada el {datetime.now()}'),
            smtp_host=SMTP_HOST,
            username=SMTP_USER,
            password=SMTP_PASSWORD
        )
        if email['errors'] is None:
            print('Correo enviado!')
        else:
            print(f'Error al enviar el correo!: '
                  f'{email["errors"]}')
        sleep(1)


if __name__ == '__main__':
    main()