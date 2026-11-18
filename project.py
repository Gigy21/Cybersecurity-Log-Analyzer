
import argparse
import csv
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime


def parse_log_line(line):
    """Parse and validate one authentication log entry."""

    parts = line.strip().split()

    if len(parts) != 4:
        return None

    date_text, time_text, status, ip = parts

    try:
        timestamp = datetime.strptime(
            f"{date_text} {time_text}",
            "%Y-%m-%d %H:%M:%S"
        )
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    status = status.upper()

    if status not in ("FAILED", "SUCCESS"):
        return None

    return {
        "timestamp": timestamp,
        "status": status,
        "ip": ip
    }


def load_logs(filename):
    """Read a log file and return valid records and invalid line count."""

    records = []
    invalid_lines = 0

    with open(filename, encoding="utf-8") as file:
        for line in file:
            record = parse_log_line(line)

            if record is None:
                invalid_lines += 1
            else:
                records.append(record)

    return records, invalid_lines


def detect_brute_force(records, threshold=5):
    """Detect IP addresses with repeated failed login attempts."""

    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise ValueError("Threshold must be an integer.")

    if threshold < 1:
        raise ValueError("Threshold must be positive.")

    failed_attempts = Counter(
        record["ip"]
        for record in records
        if record["status"] == "FAILED"
    )

    return {
        ip: count
        for ip, count in failed_attempts.items()
        if count >= threshold
    }


def analyze_activity(records):
    """Calculate login statistics for each IP address."""

    activity = defaultdict(
        lambda: {"FAILED": 0, "SUCCESS": 0}
    )

    for record in records:
        activity[record["ip"]][record["status"]] += 1

    return dict(activity)


def generate_report(records, invalid_lines=0, threshold=5):
    """Generate a detailed security analysis report."""

    if invalid_lines < 0:
        raise ValueError("Invalid line count cannot be negative.")

    failed = sum(
        1 for record in records
        if record["status"] == "FAILED"
    )

    successful = sum(
        1 for record in records
        if record["status"] == "SUCCESS"
    )

    suspicious_ips = detect_brute_force(records, threshold)
    activity = analyze_activity(records)

    report = [
        "=" * 50,
        "       CYBERSECURITY LOG ANALYZER",
        "             SECURITY REPORT",
        "=" * 50,
        "",
        f"Total valid entries: {len(records)}",
        f"Invalid entries: {invalid_lines}",
        f"Successful logins: {successful}",
        f"Failed logins: {failed}",
        f"Unique IP addresses: {len(activity)}",
        "",
        "-" * 50,
        "BRUTE FORCE DETECTION",
        "-" * 50,
        f"Detection threshold: {threshold}",
        ""
    ]

    if suspicious_ips:
        for ip, count in sorted(suspicious_ips.items()):
            report.append(
                f"[WARNING] {ip} - {count} failed attempts"
            )
    else:
        report.append("No suspicious IP addresses detected.")

    report.extend([
        "",
        "-" * 50,
        "IP ACTIVITY",
        "-" * 50
    ])

    for ip, stats in sorted(activity.items()):
        report.append(
            f"{ip} | FAILED: {stats['FAILED']} | "
            f"SUCCESS: {stats['SUCCESS']}"
        )

    report.append("")
    report.append("=" * 50)
    report.append("END OF REPORT")
    report.append("=" * 50)

    return "\n".join(report)


def export_report(records, filename, threshold=5):
    """Export IP activity and suspicious IP status to CSV."""

    suspicious_ips = detect_brute_force(records, threshold)
    activity = analyze_activity(records)

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP Address",
            "Failed Attempts",
            "Successful Logins",
            "Suspicious"
        ])

        for ip, stats in sorted(activity.items()):
            writer.writerow([
                ip,
                stats["FAILED"],
                stats["SUCCESS"],
                "YES" if ip in suspicious_ips else "NO"
            ])


def main():
    """Run the Cybersecurity Log Analyzer."""

    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )

    parser.add_argument(
        "logfile",
        help="Path to the authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login attempts needed to flag an IP"
    )

    parser.add_argument(
        "--output",
        default="security_report.csv",
        help="Name of the CSV report"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    try:
        records, invalid_lines = load_logs(args.logfile)

        report = generate_report(
            records,
            invalid_lines,
            args.threshold
        )

        print(report)

        export_report(
            records,
            args.output,
            args.threshold
        )

        with open(
            "security_report.txt",
            "w",
            encoding="utf-8"
        ) as file:
            file.write(report)

        print(f"\nCSV report saved to: {args.output}")
        print("Text report saved to: security_report.txt")

    except OSError as error:
        parser.error(f"File error: {error}")


if __name__ == "__main__":
    main()
