import socket

from logger import log_activity

HOST = ''


def handle_connection(port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind((HOST, port))
    soc.listen(10)

    while True:
        conn, addr = soc.accept()
        print(f'Received connection from {addr[0]}:{addr[1]} on server port {port}')
        log_activity(addr)

        # send a fake banner
        conn.sendall(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n')

        # receive data from the client and discard it
        while True:
            data = conn.recv(1024)

            if not data:
                break

            # check for failed login attempts and log them
            if b'Failed password' in data:
                log_activity(f'Failed login from {addr[0]}')

        # close the connection
        conn.close()
