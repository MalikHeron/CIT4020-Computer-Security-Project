import socket
import sys
from logging import *
from packet_capture import *

'''Commands:
# To find tasks running on port: netstat -ano|findstr PORT
# To kill a task: taskkill /F /PID ID
# To connect: telnet localhost PORT
'''

# specify Host and Port
HOST = ''
PORT = 22

# create a socket object
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

soc2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

soc3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    # With the help of bind() function
    # binding host and port
    soc.bind((HOST, 22))
    soc2.bind((HOST, 80))
    soc3.bind((HOST, 443))

except socket.error as message:
    # if any error occurs then with the
    # help of sys.exit() exit from the program
    print('Bind failed. Error Code : '
          + str(message[0]) + ' Message '
          + message[1])
    sys.exit()

# print if Socket binding operation completed
print('Socket binding operation completed')

# listen for incoming connections up to 10 requests
soc.listen(1)
soc2.listen(1)
soc3.listen(1)

print(f'Honeypot listening on port {22, 80, 443}...')

# accept incoming connections
while True:
    conn, addr = soc.accept()
    conn2, addr2 = soc2.accept()
    conn3, addr3 = soc3.accept()

    print(f'Received connection from {addr[0]}:{addr[1]} on server port {22}')
    print(f'Received connection from {addr2[0]}:{addr2[1]} on server port {80}')
    print(f'Received connection from {addr3[0]}:{addr3[1]} on server port {443}')

    log_activity(addr)
    log_activity(addr2)
    log_activity(addr3)
    capture_packets(addr)
    capture_packets(addr2)
    capture_packets(addr3)

    # send a fake banner
    conn.sendall(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n')
    conn2.sendall(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n')
    conn3.sendall(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n')

    # receive data from the client and discard it
    while True:
        # msg can only be 1024 bytes long
        data = conn.recv(1024)
        data2 = conn.recv(1024)
        data3 = conn.recv(1024)

        if not data:
            break
        if not data2:
            break
        if not data3:
            break

    # close the connection
    conn.close()
    conn2.close()
    conn3.close()
