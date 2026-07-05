import csv
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.logger import log_alert_to_csv
from ct_watcher.models import AlertInfo


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
            alert = _make_alert()
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
            )
            log_alert_to_csv(alert, log_path=tmp)

            with open(tmp) as f:
                reader = csv.DictReader(f)
                row = next(reader)
            assert row["nameservers_list"] == ""
            assert row["all_ips"] == ""
            assert row["non_cdn_ips"] == ""
            assert row["confirmed_attacker_ip_matches"] == ""
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
