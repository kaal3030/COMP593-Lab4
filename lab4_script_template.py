import sys
import os
import csv
from log_filter import filter_log_by_regex

def main():
    if len(sys.argv) < 3:
        print("Error: Log file path and destination port number must be provided.")
        sys.exit(1)
        
    log_file = get_log_file_path_from_cmd_line()
    port_number = sys.argv[2]  

    try:
        port_number = int(port_number)
    except ValueError:
        print("Error: Destination port number must be a valid integer.")
        sys.exit(1)

    filter_log_by_regex(log_file, "sshd", True, True, True)
    filter_log_by_regex(log_file, "invalid user", True, True, True)
    filter_log_by_regex(log_file, "invalid user.*220.195.35.40", True, True, True)
    filter_log_by_regex(log_file, "error", True, True, True)

    _, extracted_source_ips = filter_log_by_regex(log_file, r"SRC=([\d.]+)", True, False, False)
    
    if extracted_source_ips:
        print("\nExtracted Source IPs:")
        for ip in extracted_source_ips:
            print(ip[0])

    port_counts = tally_port_traffic(log_file)

    print("\nPort Traffic Tally:")
    for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"Port {port}: {count} times")

    generate_port_traffic_report(log_file, port_number)


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
    port_counts = {}

    _, captured_ports = filter_log_by_regex(log_file, r"PROTO=(\w+)\s+SPT=(\d+)\s+DPT=(\d+)", True, False, False)

    print(f"Captured Ports: {captured_ports}")  

    for protocol, src_port, dest_port in captured_ports:
        port_counts[int(dest_port)] = port_counts.get(int(dest_port), 0) + 1
    
    return port_counts


# Step 9
def generate_port_traffic_report(log_file, port_number):
    regex = (r"(\d{2}-\w{3})\s+(\d{2}:\d{2}:\d{2}) .*? SRC=([\d.]+) DST=([\d.]+) "
             r".*? SPT=(\d+) DPT=(" + str(port_number) + r")")

    matching_records, captured_data = filter_log_by_regex(log_file, regex, True, False, False)

    if not captured_data:
        print(f"\nNo log entries found for Port {port_number}.")
        return

    csv_filename = f"destination_port_{port_number}_report.csv"

    with open(csv_filename, mode="w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Date", "Time", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port"])

        for row in captured_data:
            csv_writer.writerow(row)

    print(f"\nCSV report generated: {csv_filename}")
    return



# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    return

if __name__ == '__main__':
    main()