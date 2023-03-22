import datetime


# define a function for logging honeypot activity
def log_activity(activity):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('logs/honeypot.log', 'a') as log_file:
        if 'Failed login' in activity:
            ip_address = activity.split()[-1]
            log_file.write(f'[{now}] Failed login from {ip_address}\n')
        else:
            log_file.write(f'[{now}] {activity}\n')
