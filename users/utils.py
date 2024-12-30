import os
from twilio.rest import Client

def send_sms_with_token(phone_number, token):
    # Mes Informations Twilio à partir des variables d'environnement
    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
    auth_token = os.getenv('TWILIO_AUTH_TOKEN')
    from_phone_number = os.getenv('TWILIO_FROM_PHONE')

    if not all([account_sid, auth_token, from_phone_number]):
        raise ValueError("Les informations Twilio ne sont pas correctement configurées.")
    
    # Créer une instance Twilio client
    client = Client(account_sid, auth_token)

    # Message à envoyer
    message = f"Votre code de réinitialisation de mot de passe est : {token}. Il expire dans 1 heure."

    # Envoyer le SMS
    client.messages.create(
        body=message,
        from_=from_phone_number,
        to=phone_number
    )
