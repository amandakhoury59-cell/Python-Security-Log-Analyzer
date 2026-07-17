import csv


# ==========================
# Read Logs
# ==========================
def read_logs(file_name):
    """Reads all log entries from the log file."""
    with open(file_name, "r") as file:
        return file.readlines()


# ==========================
# Find Failed Logins
# ==========================
def count_failed_logins(logs):
    """Returns only failed login attempts."""
    failed_logs = []

    for log in logs:
        if "LOGIN_FAILED" in log:
            failed_logs.append(log)

    return failed_logs


# ==========================
# Count Failed Attempts Per IP
# ==========================
def count_ips(failed_logs):
    """Counts failed login attempts for each IP address."""
    ip_counts = {}

    for log in failed_logs:
        ip = log.split("IP: ")[1].strip()

        if ip in ip_counts:
            ip_counts[ip] += 1
        else:
            ip_counts[ip] = 1

    return ip_counts


# ==========================
# Display Security Report
# ==========================
def generate_report(ip_counts):
    """Displays the security report."""

    print("\n========== SECURITY REPORT ==========\n")

    print("Failed Attempts Per IP:\n")

    for ip, count in ip_counts.items():

        print(f"{ip} --> {count} failed attempts")

        if count >= 3:
            print("⚠️ ALERT: Possible Brute Force Attack!")

    print("\n========== END OF REPORT ==========\n")


# ==========================
# Save CSV Report
# ==========================
def save_report(ip_counts):
    """Exports the report to a CSV file."""

    with open("report.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["IP Address", "Failed Attempts", "Status"])

        for ip, count in ip_counts.items():

            if count >= 3:
                status = "Suspicious"
            else:
                status = "Normal"

            writer.writerow([ip, count, status])

    print("✅ CSV report saved as report.csv")


# ==========================
# Main Program
# ==========================
def main():

    logs = read_logs("sample_logs.txt")

    failed_logs = count_failed_logins(logs)

    ip_counts = count_ips(failed_logs)

    print("========== LOG SUMMARY ==========\n")

    print(f"Total Log Entries : {len(logs)}")
    print(f"Failed Logins     : {len(failed_logs)}")

    print("\nFailed Login Attempts:\n")

    for log in failed_logs:
        print(log.strip())

    generate_report(ip_counts)

    save_report(ip_counts)


# ==========================
# Run Program
# ==========================
if __name__ == "__main__":
    main()