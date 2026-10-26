import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.domain_checks import DUO_INVALID_HOSTNAME, check_duo_hostnames
from ct_watcher.models import DuoCheckResult
from ct_watcher.utils import format_duo_check_lines, format_duo_ids


class TestCheckDuoHostnames:
    @patch("ct_watcher.domain_checks.resolve_a")
    def test_invalid_when_a_records_match_baseline(self, mock_resolve):
        mock_resolve.side_effect = lambda host: {
            DUO_INVALID_HOSTNAME: ["54.241.191.167"],
            "api-abcde.duosecurity.com": ["54.241.191.167"],
        }[host]

        result = check_duo_hostnames(["abcde"])

        assert result["abcde"].status == "invalid"
        assert result["abcde"].a_records == ["54.241.191.167"]

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_valid_when_a_records_differ(self, mock_resolve):
        mock_resolve.side_effect = lambda host: {
            DUO_INVALID_HOSTNAME: ["54.241.191.167"],
            "api-fghij.duosecurity.com": ["3.145.240.61", "3.145.240.91"],
        }[host]

        result = check_duo_hostnames(["fghij"])

        assert result["fghij"].status == "valid"

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_set_comparison_ignores_record_order(self, mock_resolve):
        mock_resolve.side_effect = lambda host: {
            DUO_INVALID_HOSTNAME: ["5.6.7.8", "1.2.3.4"],
            "api-abcde.duosecurity.com": ["1.2.3.4", "5.6.7.8"],
        }[host]

        result = check_duo_hostnames(["abcde"])

        assert result["abcde"].status == "invalid"

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_unknown_when_target_has_no_a_records(self, mock_resolve):
        mock_resolve.side_effect = lambda host: {
            DUO_INVALID_HOSTNAME: ["54.241.191.167"],
            "api-abcde.duosecurity.com": [],
        }[host]

        result = check_duo_hostnames(["abcde"])

        assert result["abcde"].status == "unknown"
        assert result["abcde"].a_records == []

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_unknown_when_baseline_has_no_a_records(self, mock_resolve):
        mock_resolve.return_value = []

        result = check_duo_hostnames(["abcde", "fghij"])

        assert result["abcde"].status == "unknown"
        assert result["fghij"].status == "unknown"
        assert mock_resolve.call_count == 1

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_baseline_resolved_once_and_duplicate_ids_deduped(self, mock_resolve):
        def fake(host):
            if host == DUO_INVALID_HOSTNAME:
                return ["54.241.191.167"]
            return ["1.2.3.4"]

        mock_resolve.side_effect = fake

        result = check_duo_hostnames(["abcde", "abcde", "fghij"])

        assert set(result) == {"abcde", "fghij"}
        assert mock_resolve.call_count == 3

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_empty_api_ids_skips_dns(self, mock_resolve):
        assert check_duo_hostnames([]) == {}
        mock_resolve.assert_not_called()

    @patch("ct_watcher.domain_checks.resolve_a")
    def test_hostname_is_lowercased(self, mock_resolve):
        mock_resolve.side_effect = lambda host: {
            DUO_INVALID_HOSTNAME: ["54.241.191.167"],
            "api-abc123.duosecurity.com": ["1.2.3.4"],
        }[host]

        result = check_duo_hostnames(["ABC123"])

        assert result["ABC123"].status == "valid"


class TestFormatDuoIds:
    def test_appends_status_for_multiple_ids(self):
        checks = {
            "abcde": DuoCheckResult("invalid", ["54.241.191.167"]),
            "fghij": DuoCheckResult("valid", ["3.145.240.61"]),
        }

        duo_str, targets_str = format_duo_ids(
            ["abcde", "fghij"],
            {"fghij": {"name": "Example University", "email": "security@example.edu"}},
            checks,
        )

        assert "`abcde` — ❌ invalid Duo" in duo_str
        assert "`fghij` — ✅ valid Duo" in duo_str
        assert targets_str == "(unknown), Example University"

    def test_appends_status_for_single_id(self):
        checks = {"fghij": DuoCheckResult("valid", ["3.145.240.61"])}

        duo_str, targets_str = format_duo_ids(["fghij"], {}, checks)

        assert duo_str == "`fghij` — ✅ valid Duo"
        assert targets_str is None

    def test_without_checks_is_unchanged(self):
        duo_str, targets_str = format_duo_ids(["fghij"], {}, None)

        assert duo_str == "`fghij`"
        assert targets_str is None


class TestFormatDuoCheckLines:
    def test_invalid_and_unknown_details(self):
        checks = {
            "abcde": DuoCheckResult("invalid", ["54.241.191.167"]),
            "klmno": DuoCheckResult("unknown", []),
            "fghij": DuoCheckResult("valid", ["3.145.240.61"]),
        }

        lines = format_duo_check_lines(["abcde", "klmno", "fghij"], checks)

        assert lines is not None
        assert "❌ `api-abcde.duosecurity.com` → `54.241.191.167`" in lines
        assert "❔ `api-klmno.duosecurity.com` — DNS lookup failed" in lines
        assert "api-fghij.duosecurity.com" not in lines
        assert "known-invalid wildcard" in lines

    def test_valid_only_returns_none(self):
        checks = {"fghij": DuoCheckResult("valid", ["3.145.240.61"])}

        assert format_duo_check_lines(["fghij"], checks) is None

    def test_details_are_capped(self):
        api_ids = [f"id{i:03d}" for i in range(12)]
        checks = {aid: DuoCheckResult("invalid", ["54.241.191.167"]) for aid in api_ids}

        lines = format_duo_check_lines(api_ids, checks)

        assert lines is not None
        assert "api-id009.duosecurity.com" in lines
        assert "api-id010.duosecurity.com" not in lines
        assert "... and 2 more" in lines
