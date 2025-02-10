import sys
import os
from log_filter import filter_log_by_regex

def main():
    log_file = get_log_file_path_from_cmd_line()

    filter_log_by_regex(log_file, "sshd", True, True, True)
    filter_log_by_regex(log_file, "invalid user", True, True, True)
    filter_log_by_regex(log_file, "invalid user.*220.195.35.40", True, True, True)
    filter_log_by_regex(log_file, "error", True, True, True)

# Step 3
def get_log_file_path_from_cmd_line():
    if len(sys.argv) < 2:
        print("Error: Log file path must be provided as a command line argument.")
        sys.exit(1)

    log_file_path = sys.argv[1]

    if not os.path.isfile(log_file_path):
        print(f"Error: File '{log_file_path}' does not exist")
        sys.exit(1)

    return log_file_path

# TODO: Step 8
def tally_port_traffic(log_file):
    return

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
    main()