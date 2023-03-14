import socket
import sys

'''Commands:
# To find tasks running on port: netstat -ano|findstr PORT
# To kill a task: taskkill /F /PID ID
# To connect: telnet localhost PORT
'''

# specify Host and Port
HOST = ''
PORT = 5789

# create a socket object
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    # With the help of bind() function
    # binding host and port
    soc.bind((HOST, PORT))

except socket.error as message:

    # if any error occurs then with the
    # help of sys.exit() exit from the program
    print('Bind failed. Error Code : '
          + str(message[0]) + ' Message '
          + message[1])
    sys.exit()

# print if Socket binding operation completed
print('Socket binding operation completed')

# listen for incoming connections
soc.listen(9)

print(f'Honeypot listening on port {PORT}...')

# accept incoming connections
while True:
    conn, addr = soc.accept()
    print(f'Received connection from {addr[0]}:{addr[1]}')

    # send a fake banner
    conn.sendall(b'SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1\r\n')

    # receive data from the client and discard it
    while True:
        data = conn.recv(1024)
        if not data:
            break

    # close the connection
    conn.close()
