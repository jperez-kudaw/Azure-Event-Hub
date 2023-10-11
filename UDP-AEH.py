"""
Script de Conexión a AZURE EVENT HUB

Autor: Juan Alejandro Perez Chandia
Mail: jperez@kudaw.com
Fecha: Octubre 05 de 2023

Este script python se diseñó para establecer conexión con Azure Event Hub a través del puero 443 de comunicación
segura (SSL) utilizando certificados autofirmados. Su función principal consiste en enviar flujos de datos capturados
desde el puerto 514 UDP.

"""
import re
import socket
from azure.eventhub import EventHubProducerClient, EventData
from azure.eventhub.exceptions import AuthenticationError
import json
from datetime import datetime
from OpenSSL import crypto, SSL


eventhub_namespace = "azure-data-explore-testing"
eventhub_name = "aeh-adx"
certificate_path = "./certificate/certificate.pem"
private_key_path = "./certificate/private-key.pem"

udp_host = "0.0.0.0"
udp_port = 514

# SSL/TLS min TLS 1.2
ssl_context = SSL.Context(SSL.TLSv1_2_METHOD)
ssl_context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
ssl_context.set_verify(SSL.VERIFY_NONE, lambda *args, **kwargs: True)

# ---------------------------------------------- SELF-SIGNED CERTIFICATE ----------------------------------------------
private_key = crypto.PKey()
private_key.generate_key(crypto.TYPE_RSA, 2048)

cert = crypto.X509()
cert.get_subject().C = "CL"
cert.get_subject().ST = "Región Metropolitana"
cert.get_subject().L = "Providencia"
cert.get_subject().O = "Kudaw"
cert.get_subject().OU = "Desarrollo"
cert.get_subject().CN = "www.kudaw.com"
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
cert.set_pubkey(private_key)
cert.sign(private_key, "sha256")

with open(certificate_path, "rb") as cert_file:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
    ssl_context.use_certificate(cert)

with open(private_key_path, "rb") as key_file:
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    ssl_context.use_privatekey(private_key)

# ---------------------------------------------- SELF-SIGNED CERTIFICATE ----------------------------------------------

producer_client = EventHubProducerClient.from_connection_string(
    conn_str=f"Endpoint=sb://{eventhub_namespace}.servicebus.windows.net/;SharedAccessKeyName=raptorPolicy;SharedAccessKey=zH6BZYgXwz1bJh+1n5g9NbcfSJZMGnnx3+AEhCY9hM8=;EntityPath=aeh-adx",
    eventhub_name=eventhub_name,
    http_proxy=None,
    ssl_context=ssl_context
)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((udp_host, udp_port))

try:
    print(f"Listening for UDP messages on {udp_host}:{udp_port}")
    rex_data = re.compile(r'\w{3} \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\.\d+ [-+]\d+')
    while True:
        data, addr = udp_socket.recvfrom(1024)
        message = data.decode('utf-8')
        message = message.replace("\"ts\"", "\"timestamp\"")
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f-0300")
        message_new = rex_data.sub(current_date, message)

        print(f"message received: {message_new}")
        json_message = json.dumps(message_new, indent=2)
        event_data = EventData(message_new)
        producer_client.send_event(event_data)
        print(f"Sent message to Event Hub: {json_message}")

except AuthenticationError as auth_error:
    print(f"Error de autenticación: {auth_error}")
    print(f"Detalles adicionales: {auth_error.args}")

except KeyboardInterrupt:
    # Ctrl+C
    print("Sending operation interrupted by user")
finally:
    udp_socket.close()
    producer_client.close()
