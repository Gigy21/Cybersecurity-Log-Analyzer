
from datetime import datetime

import pytest

from project import (
    parse_log_line,
    load_logs,
    detect_brute_force,
    analyze_activity,
    generate_report,
    export_report
)


def test_parse_log_line():
    line = "2026-11-18 10:00:00 FAILED 192.168.1.10"

    result = parse_log_line(line)

    assert result is not None
    assert result["status"] == "FAILED"
    assert result["ip"] == "192.168.1.10"
    assert result["timestamp"] == datetime(2026, 11, 18, 10, 0, 0)


def test_parse_invalid_line():
    assert parse_log_line("invalid log") is None

    assert parse_log_line(
        "2026-11-18 10:00:00 FAILED invalid-ip"
    ) is None

    assert parse_log_line(
        "2026-11-18 10:00:00 UNKNOWN 192.168.1.10"
    ) is None


def test_load_logs(tmp_path):
    log_file = tmp_path / "test_logs.txt"

    log_file.write_text(
        "2026-11-18 10:00:00 FAILED 192.168.1.10\n"
        "invalid line\n"
        "2026-11-18 10:02:00 SUCCESS 192.168.1.20\n",
        encoding="utf-8"
    )

    records, invalid = load_logs(log_file)

    assert len(records) == 2
    assert invalid == 1


def test_detect_brute_force():
    records = [
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "SUCCESS", "ip": "192.168.1.20"}
    ]

    result = detect_brute_force(records, 3)

    assert result == {"192.168.1.10": 3}


def test_detect_brute_force_invalid_threshold():
    with pytest.raises(ValueError):
        detect_brute_force([], 0)

    with pytest.raises(ValueError):
        detect_brute_force([], 2.5)


def test_analyze_activity():
    records = [
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "SUCCESS", "ip": "192.168.1.10"},
        {"status": "SUCCESS", "ip": "192.168.1.20"}
    ]

    result = analyze_activity(records)

    assert result["192.168.1.10"] == {
        "FAILED": 1,
        "SUCCESS": 1
    }

    assert result["192.168.1.20"] == {
        "FAILED": 0,
        "SUCCESS": 1
    }


def test_generate_report():
    records = [
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "SUCCESS", "ip": "192.168.1.20"}
    ]

    report = generate_report(records, 0, 5)

    assert "Total valid entries: 2" in report
    assert "Failed logins: 1" in report
    assert "Successful logins: 1" in report
    assert "No suspicious IP addresses detected." in report


def test_export_report(tmp_path):
    records = [
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "FAILED", "ip": "192.168.1.10"},
        {"status": "SUCCESS", "ip": "192.168.1.20"}
    ]

    output_file = tmp_path / "report.csv"

    export_report(records, output_file, 2)

    content = output_file.read_text(encoding="utf-8")

    assert "192.168.1.10" in content
    assert "YES" in content
    assert "192.168.1.20" in content
