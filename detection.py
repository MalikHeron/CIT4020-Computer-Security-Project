import time

from flask import Flask, request, app
import re

LOG_FILE = 'honeypot.log'


@app.route('/login', methods=['POST'])
def login():
    # capture information about the incoming request
    remote_ip = request.remote_addr
    request_method = request.method
    request_path = request.path
    request_data = request.data

    # log the request details to a file or database for analysis
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(
            f'remote_ip: {remote_ip}, method: {request_method}, path: {request_path}, data: {request_data}\n')
    # return a fake error message to the attacker
    return 'Invalid username or password'


def analyze_logs(LOG_FILE):
    with open(LOG_FILE, 'r') as f:
        logs = f.readlines()

    for log in logs:
        # look for suspicious activity in the logs
        if 'ssh' in log and 'Failed password' in log:
            # alert on failed SSH login attempts
            send_alert('Failed SSH login attempt: {}'.format(log))
        elif 'sudo' in log and 'COMMAND' in log and 'rm' in log:
            # alert on sudo commands that attempt to delete files
            send_alert('Sudo command to delete file: {}'.format(log))

    # define a function to send alerts


def send_alert(message):
    # send an email, text message, or other notification to the security team
    print(message)

    # run the log analysis function on a schedule
    while True:
        analyze_logs('honeypot.log')
        time.sleep(60)
