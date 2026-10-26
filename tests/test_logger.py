import csv
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.logger import _COLUMNS, log_alert_to_csv
from ct_watcher.models import AlertInfo, DuoCheckResult


def _make_alert(**overrides):
    defaults = dict(
        domain="api-529aed63.evil.com",
        all_domains=["api-529aed63.evil.com", "evil.com"],
        not_before=1700000000.0,
        is_known_attacker=True,
        registrar="Namecheap",
        is_cloudflare=True,
        nameservers_list=["ns1.cloudflare.com", "ns2.cloudflare.com"],
        all_ips=["1.2.3.4", "5.6.7.8"],
        non_cdn_ips=["1.2.3.4"],
        confirmed_attacker_ip_matches=["1.2.3.4"],
        reg_date="2024-01-15",
        email_status_details="Email sent successfully",
        email_status_state="sent",
        target_info={"name": "Test University", "email": "security@test.edu"},
        api_ids=["529aed63"],
        certkit_url="https://www.certkit.io/tools/ct-logs/certificate?sha256=abcd1234",
        sha256="ab:cd:12:34:56:78",
        serial_number="04ABC123",
    )
    defaults.update(overrides)
    return AlertInfo(**defaults)


class TestCsvLogging:
    def test_row_writes_to_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert = _make_alert()
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                lines = f.readlines()
            assert len(lines) >= 2  # header + data row
            reader = csv.DictReader(lines)
            rows = list(reader)
            assert len(rows) == 1
            row = rows[0]
            assert row["domain"] == "api-529aed63.evil.com"
            assert row["registrar"] == "Namecheap"
            assert row["domain_count"] == "2"
            assert row["sha256"] == "ab:cd:12:34:56:78"
            assert row["serial_number"] == "04ABC123"
            assert row["certkit_url"] == (
                "https://www.certkit.io/tools/ct-logs/certificate?sha256=abcd1234"
            )
            assert row["target_name"] == "Test University"
            assert row["target_email"] == "security@test.edu"
            assert row["is_known_attacker"] == "True"
            assert row["alert_timestamp"] != ""
            assert row["duo_status"] == ""
            assert row["duo_a_records"] == ""
        finally:
            os.unlink(tmp)

    def test_duo_columns_are_serialized(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert = _make_alert(
                api_ids=["abcde", "fghij"],
                duo_checks={
                    "abcde": DuoCheckResult("invalid", ["1.2.3.4"]),
                    "fghij": DuoCheckResult("valid", ["5.6.7.8", "9.10.11.12"]),
                },
            )
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                reader = csv.DictReader(f)
                row = next(reader)
            assert row["duo_status"] == "abcde:invalid|fghij:valid"
            assert row["duo_a_records"] == "abcde:1.2.3.4|fghij:5.6.7.8+9.10.11.12"
        finally:
            os.unlink(tmp)

    def test_stale_header_is_refreshed_and_old_rows_stay_blank(self):
        # Mirrors the real alerts.csv: a 20-column header with 24-field rows.
        old_header = _COLUMNS[:20]
        old_row = [""] * 24
        old_row[0] = "2024-01-01T00:00:00+00:00"
        old_row[4] = "old.example.com"
        old_row[20] = "oldapi"
        old_row[21] = "oldkeyword"
        old_row[22] = "oldkeyworddomain"
        old_row[23] = "oldkeywordmatched"

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv", newline="") as f:
            tmp = f.name
            writer = csv.writer(f)
            writer.writerow(old_header)
            writer.writerow(old_row)

        try:
            alert = _make_alert(
                api_ids=["abcde"],
                duo_checks={"abcde": DuoCheckResult("invalid", ["54.241.191.167"])},
            )
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp, newline="") as f:
                reader = csv.DictReader(f, restval="")
                rows = list(reader)
                fieldnames = reader.fieldnames

            assert fieldnames == _COLUMNS
            assert rows[0]["domain"] == "old.example.com"
            assert rows[0]["api_ids"] == "oldapi"
            assert rows[0]["duo_status"] == ""
            assert rows[0]["duo_a_records"] == ""
            assert rows[1]["duo_status"] == "abcde:invalid"
            assert rows[1]["duo_a_records"] == "abcde:54.241.191.167"
        finally:
            os.unlink(tmp)

    def test_header_written_only_once(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert1 = _make_alert(domain="first.example.com")
            alert2 = _make_alert(domain="second.example.com")
            log_alert_to_csv(alert1, log_path=tmp)
            log_alert_to_csv(alert2, log_path=tmp)

            with open(tmp) as f:
                text = f.read()
            # Header should appear exactly once
            header_line = text.split("\n")[0]
            assert text.count(header_line) == 1
        finally:
            os.unlink(tmp)

    def test_list_fields_are_pipe_delimited(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert = _make_alert(matched_keywords=["calcentraltiw", "login"])
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                reader = csv.DictReader(f)
                row = next(reader)
            assert "|" in row["all_domains"]
            assert row["all_domains"] == "api-529aed63.evil.com|evil.com"
            assert row["nameservers_list"] == "ns1.cloudflare.com|ns2.cloudflare.com"
            assert row["all_ips"] == "1.2.3.4|5.6.7.8"
            assert row["non_cdn_ips"] == "1.2.3.4"
            assert row["confirmed_attacker_ip_matches"] == "1.2.3.4"
            assert row["matched_keywords"] == "calcentraltiw|login"
        finally:
            os.unlink(tmp)

    def test_empty_list_fields_produce_empty_string(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert = _make_alert(
                nameservers_list=None,
                all_ips=None,
                non_cdn_ips=None,
                confirmed_attacker_ip_matches=None,
                matched_keywords=None,
            )
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                reader = csv.DictReader(f)
                row = next(reader)
            assert row["nameservers_list"] == ""
            assert row["all_ips"] == ""
            assert row["non_cdn_ips"] == ""
            assert row["confirmed_attacker_ip_matches"] == ""
            assert row["matched_keywords"] == ""
        finally:
            os.unlink(tmp)

    def test_no_target_info(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert = _make_alert(target_info=None)
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                reader = csv.DictReader(f)
                row = next(reader)
            assert row["target_name"] == ""
            assert row["target_email"] == ""
        finally:
            os.unlink(tmp)

    def test_api_id_null(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            tmp = f.name
        try:
            alert = _make_alert(api_ids=[])
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                reader = csv.DictReader(f)
                row = next(reader)
            assert row["api_id"] == ""
        finally:
            os.unlink(tmp)
