#!/usr/bin/env python3

import argparse
import socket
import ssl
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Variables globales
HOST = "127.0.0.1"
PORT = 6666

DEBUG = False

def verify_cert(cert, expected_hostname):
    """Check whenether the certificate is valid for the expected hostname
        It DOES NOT check the validity of the certificate (expiration date, revocation, etc.), 
        it's expected to be done by the SSLContext
    """
    # Load the certificate
    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
    
    # Check the hostname
    if not x509_cert.subject.rfc4514_string() == f"CN={expected_hostname}":
        raise ValueError("The certificate is not valid for the expected hostname")

    if DEBUG:
        print("Human-Readable Certificate :")
        print(x509_cert)


def start_client():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('root-ca-lorne.pem')  # Use the ROOT CA to verify the server certificate
    expected_hostname = HOST  # The hostname we expect to be in the server certificate

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        with context.wrap_socket(client_socket, server_hostname=expected_hostname) as secure_socket:
            secure_socket.connect((HOST, PORT))

            # Check the certificate's hostname
            cert = secure_socket.getpeercert(binary_form=True)
            verify_cert(cert, expected_hostname)

            print("Type in, Ctrl+C to exit")
            while True:
                message = sys.stdin.read(1)
                secure_socket.send(message.encode())

if __name__ == "__main__":
    ArgumentParser = argparse.ArgumentParser()
    ArgumentParser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    args = ArgumentParser.parse_args()
    DEBUG = args.debug
    start_client()
