import os
import socket
import sys
import threading
from datetime import datetime
from shutil import copyfile

from scapy.sendrecv import sniff
from src.detection import check_logs_for_intrusion
from handler import handle_connection
from packet import capture_packets

""" ------ Important commands ------
# Install ncap: https://npcap.com/#download
# Install telnet on windows: dism /online /Enable-Feature /FeatureName:TelnetClient
# Connect to a port: telnet localhost PORT
# View running processes on a port: netstat -ano|findstr PORT
# Kill a process on a port: taskkill /F /PID 19088
# Email for alerting: honeypotproject2023@gmail.com
# Email password: HoneyPot2023
"""


def main():
    # check if the log file already exists
    if os.path.exists('logs/honeypot.log'):
        # get the current date and time as a string with milliseconds
        now = datetime.now().strftime('%Y-%m-%d %f')

        # create a timestamped filename for the copy of the log file
        new_filename = f'logs/honeypot - {now}.log'

        # create a copy of the log file with the timestamped filename
        copyfile('logs/honeypot.log', new_filename)

        # overwrite the original log file
        with open('logs/honeypot.log', 'w') as f:
            f.write('')
    else:
        open('logs/honeypot.log', 'w')

    try:
        threading.Thread(target=handle_connection, args=(22,), daemon=True).start()
        threading.Thread(target=handle_connection, args=(80,), daemon=True).start()
        threading.Thread(target=handle_connection, args=(443,), daemon=True).start()

        # start the intrusion detection thread
        intrusion_detection_thread = threading.Thread(target=check_logs_for_intrusion)
        intrusion_detection_thread.start()

    except socket.error as message:
        print('Bind failed. Error Code : ' + str(message[0]) + ' Message ' + message[1])
        sys.exit()


print('Socket binding operation completed')
print(f'Honeypot listening on ports 22, 80 and 443...')

filter = "tcp port 22 or tcp port 80 or tcp port 443"

capture_thread = threading.Thread(target=sniff,
                                  kwargs={'filter': filter,
                                          'prn': capture_packets,
                                          'store': False})
capture_thread.start()

if __name__ == "__main__":
    main()
