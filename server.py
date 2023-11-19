#!/usr/bin/env python3

import socket
import ssl
import argparse

HOST = "127.0.0.1"
PORT = 6666
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"


def start_server():
    # Create a SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Load the server certificate
    context.load_cert_chain(CERT_FILE, KEY_FILE)

    # Create a TCP/IP socket, AF_INET for IPv4, SOCK_STREAM for TCP (required by ssl)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)  # one connection at a time

        print("Waiting for connection...")
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            conn, addr = secure_socket.accept()  # accept the incoming connection
            with conn:
                print('Beginning of transmission', addr)
                while True:
                    # receive one caracter at a time (I find it fun)
                    data = conn.recv(1)
                    if not data:
                        break
                    print(data.decode(), end="")
                print("\nEnd of transmission")


if __name__ == "__main__":
    argparse = argparse.ArgumentParser()
    argparse.add_argument(
        "-s", "--host", help="Host to listen on", type=str, default=HOST)
    argparse.add_argument(
        "-p", "--port", help="Port to listen on", type=int, default=PORT)
    argparse.add_argument(
        "-c", "--cert", help="Certificate file", type=str, default=CERT_FILE)
    argparse.add_argument(
        "-k", "--key", help="Key file", type=str, default=KEY_FILE)
    args = argparse.parse_args()
    HOST = args.host
    PORT = args.port
    start_server()
