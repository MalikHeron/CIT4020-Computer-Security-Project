import socket
import threading
from datetime import datetime
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

        # create a new thread to handle the connection
        threading.Thread(target=handle_client_connection,
                         args=(conn, addr),
                         daemon=True).start()


def handle_client_connection(conn, addr):
    # send a fake banner
    conn.sendall(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n')

    # give the client three attempts to enter a valid username and password
    for attempt in range(3):
        # prompt the user for a username
        conn.sendall(b'Username: ')
        username = conn.recv(1024).decode().strip()

        # prompt the user for a password
        conn.sendall(b'Password: ')
        password = conn.recv(1024).decode().strip()

        # check if the username and password are correct
        if username == 'admin' and password == 'password':
            conn.sendall(b'Access granted.\r\n')
            break
        else:
            conn.sendall(b'Access denied.\r\n')
            log_activity(f'Failed login from {addr[0]}')

    else:
        # log that the client failed to enter a valid username and password after three attempts
        log_activity(f'{addr[0]} failed to authenticate after 3 attempts')

    # get the current time and format it as a string
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # log that the client has disconnected along with the time
    log_activity(f'{now} - Client {addr[0]} disconnected')

    # close the connection
    conn.close()
