import datetime


# define a function for logging honeypot activity
def log_activity(activity):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('honeypot.log', 'a') as log_file:
        log_file.write(f'[{now}] {activity}\n')

# example usage: log an HTTP request received by the honeypot
# log_activity('HTTP request received - GET /admin.php HTTP/1.1')
