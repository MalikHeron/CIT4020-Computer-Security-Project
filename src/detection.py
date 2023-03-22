import time


def check_logs_for_intrusion():
    while True:
        with open('logs/honeypot.log', 'r') as log_file:
            logs = log_file.readlines()

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
            if count >= 3:
                print(f'Possible intrusion attempt detected from IP address {ip_address}')

        # checks the log every 5 seconds
        time.sleep(5)
