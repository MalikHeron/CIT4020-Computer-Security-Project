import datetime
import os
import time
import platform
import smtplib


def send_alert(ip_address):
    sender = 'honeypotproject2023@gmail.com'
    receiver = 'honeypotproject2023@gmail.com'
    password = 'fkriuutxzsyskiaq'
    subject = f'Intrusion attempt detected from IP address {ip_address}'
    body = f'An intrusion attempt has been detected from IP address {ip_address}.'

    message = f"""From: {sender}
To: {receiver}
Subject: {subject}

{body}
"""

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, message)
        server.quit()
        print(f'Alert sent to {receiver}')
    except Exception as e:
        print(f'Error sending alert: {e}')


def block_ip(ip_address):
    # check the current operating system
    if platform.system() == 'Windows':
        # use the netsh command to block the IP address on Windows
        os.system(
            f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in interface=any action=block remoteip={ip_address}')
    else:
        # use the ufw command to block the IP address on Linux
        os.system(f'sudo ufw deny from {ip_address}')


def check_logs_for_intrusion():
    # create a set to store the IP addresses that have already been alerted
    alerted_ips = set()

    while True:
        with open('logs/honeypot.log', 'r') as log_file:
            logs = log_file.readlines()

        # create a report file
        if not os.path.exists('logs/report.txt'):
            with open('logs/report.txt', 'w') as report_file:
                report_file.write('Intrusion Attempts Report\n')
                report_file.write('=========================\n\n')

        # create a dictionary to store the number of failed login attempts for each IP address
        failed_attempts = {}

        for log in logs:
            # check if the log contains a failed login attempt
            if 'Failed login from' in log:
                # extract the IP address from the log
                ip_address = log.split()[-1]

                if ip_address in failed_attempts:
                    failed_attempts[ip_address] += 1
                else:
                    failed_attempts[ip_address] = 1

        # check if any IP address has more than 3 failed login attempts
        for ip_address, count in failed_attempts.items():
            if count >= 3 and ip_address not in alerted_ips:
                # print the intrusion detection message in red
                print(f'\033[91mPossible intrusion attempt detected from IP address {ip_address}\033[0m')
                # append to report file
                with open('logs/report.txt', 'a') as report_file:
                    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    report_file.write(f'{now}\n')
                    report_file.write(f'IP Address: {ip_address}\n')
                    report_file.write(f'Failed Login Attempts: {count}\n\n')

                # block the ip address
                block_ip(ip_address)
                # send an email alert
                send_alert(ip_address)
                # add the IP address to the set of alerted IPs
                alerted_ips.add(ip_address)

        # checks the log every 5 seconds
        time.sleep(5)
