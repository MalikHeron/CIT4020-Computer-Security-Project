# This is a sample Python script.
from socket import *


# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

host = "127.0.0.2"
port = 80
print("[+] Honeypot start...")
try:
    get_socket_con = socket(AF_INET, SOCK_STREAM)
    get_socket_con.bind((host, port))
    get_socket_con.listen(10)
    while 1:
        client_con, client_addr = get_socket_con.accept()
        print("Visitor found! - [{}]".format(client_addr[0]))
        client_con.send(b"<h1>Got caught in our honeypot</h1>\r\n") # \r\n stops the stream of bytes so that the program
        # wont crash when the html page is closed
        data = client_con.recv(2048)
        print(data.decode('utf-8'))

        """
        def handle_client(sock):
            Respond to one client's commands
            # while True: ...

        def listen():
            Listen for incoming connections and call handle_client for each one
            # s = socket.socket(...)
            # while True: s.accept() ..."""

except error as identifier:
    print("[+] Unspecified error [{}]".format(identifier))
except KeyboardInterrupt as ky:
    print("[-] Process stopped!")
    get_socket_con.close()
finally:
    get_socket_con.close()
get_socket_con.close()

"""
HOST = ''

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.

def startSockets():
    soc22 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    soc80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc80.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc443.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc22:
    soc22.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc22.bind((HOST, 22))
    soc22.listen()
    conn, addr = soc22.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
"""

