import re

def filter_log_by_regex(log_file, regex, ignore_case, print_summary, print_records):
    pattern_flags = re.IGNORECASE if ignore_case else 0
    pattern = re.compile(regex, pattern_flags)

    matching_records = []
    captured_data = []

    with open(log_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                matching_records.append(line.strip())
                if match.groups():
                    captured_data.append(match.groups())

    if print_records:
        print(f"\nTotal matching records: {len(matching_records)}")
        for record in matching_records:
            print(record)

    if print_summary:
        case_text = "case-insensitive" if ignore_case else "case-sensitive"
        print(f"\nThe log file contains {len(matching_records)} records that {case_text} match '{regex}'.")

    return matching_records , captured_data
