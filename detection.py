import re

LOG_FILE = 'honeypot.log'

# define a regular expression pattern for matching HTTP request data in the log file
REQUEST_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+"(?P<method>\w+) (?P<path>/.*) HTTP/1\.\d".+')

# read the log file and analyze the data
with open(LOG_FILE) as f:
    for line in f:
        match = REQUEST_PATTERN.match(line)
        if match:
            # extract the IP address, HTTP method, and path from the log data
            ip = match.group('ip')
            method = match.group('method')
            path = match.group('path')

            # check for suspicious activity
            if method.upper() != 'GET':
                print(f'Possible attack detected: {ip} used {method} method on {path}')

            if 'wp-admin' in path:
                print(f'Possible WordPress attack detected: {ip} accessed {path}')
