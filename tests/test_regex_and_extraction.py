import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.config import DOMAIN_REGEX
from ct_watcher.utils import extract_target_id, extract_all_target_ids, is_common_word_id


class TestDomainRegex:
    """Tests for DOMAIN_REGEX pattern matching."""

    @pytest.mark.parametrize(
        "domain",
        [
            "api-62a1edm3.ghg.example.com",
            "api-3dse1.example.com",
            "api-529aed63.example.com",
            "api-a540f86.example.com",
            "api-abcdef.example.com",
            "api-ABCDEFG.example.com",
            "api-12345.example.com",
            "api-a1b2c3d4.example.com",
        ],
    )
    def test_matches_valid_ids(self, domain):
        assert DOMAIN_REGEX.match(domain), f"Should match: {domain}"

    @pytest.mark.parametrize(
        "domain",
        [
            "api-xyz.example.com",
            "api-abcd.example.com",
            "api-abcdefghijk.example.com",
            "api-abcdefghijkl.example.com",
            "notapi-abcde.example.com",
            "xapi-abcde.example.com",
            "api-abcde",
        ],
    )
    def test_rejects_invalid_ids(self, domain):
        assert not DOMAIN_REGEX.match(domain), f"Should reject: {domain}"

    @pytest.mark.parametrize(
        "domain",
        [
            "api-test.ngrok.io",
            "api-test.ngrok-free.app",
            "api-test.workers.dev",
            "api-test.pages.dev",
            "api-20240909.pages.dev",
            "api-abc123.workers.dev",
            "api-test.amazonaws.com",
            "api-test.azure.something.com",
            "api-test.googleusercontent.com",
            "api-test.huaweiclouds.example.com",
            "api-test.multi.software",
            "api-test.upsolver.com",
            "api-test.ondigitalocean.com",
            "api-9b1fceb8.mongo.ondigitalocean.com",
        ],
    )
    def test_rejects_cloud_saas(self, domain):
        assert not DOMAIN_REGEX.match(domain), f"Should reject cloud/SaaS: {domain}"


class TestExtractTargetId:
    """Tests for extract_target_id function."""

    @pytest.mark.parametrize(
        "domain,expected",
        [
            ("api-62a1edm3.ghg.example.com", "62a1edm3"),
            ("api-3dse1.example.com", "3dse1"),
            ("api-529aed63.example.com", "529aed63"),
            ("api-a540f86.example.com", "a540f86"),
            ("api-abcde.sub.example.com", "abcde"),
            ("api-ABCDEF.example.com", "abcdef"),
            ("api-abcde.example.com", "abcde"),
            ("api-abcdef.example.com", "abcdef"),
            ("api-abcdefg.example.com", "abcdefg"),
            ("api-abcdefgh.example.com", "abcdefgh"),
        ],
    )
    def test_extracts_correctly(self, domain, expected):
        assert extract_target_id(domain) == expected

    @pytest.mark.parametrize(
        "domain",
        [
            "notapi-abcde.example.com",
            "api-xyz.example.com",
            "api-abcdefghijk.example.com",
            "api-abcde",
            "example.com",
        ],
    )
    def test_returns_none_for_invalid(self, domain):
        assert extract_target_id(domain) is None


class TestIsCommonWordId:
    """Tests for is_common_word_id false positive filtering."""

    @pytest.mark.parametrize(
        "api_id",
        [
            "cabal",
            "check",
            "email",
            "nexus",
            "quote",
            "relay",
            "teste",
            "testi",
            "tools",
        ],
    )
    def test_filters_5char_common_words(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is True

    @pytest.mark.parametrize(
        "api_id",
        [
            "agenda",
            "backup",
            "canary",
            "client",
            "global",
            "mobile",
            "origin",
            "portal",
            "public",
            "server",
        ],
    )
    def test_filters_6char_common_words(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is True

    @pytest.mark.parametrize(
        "api_id",
        [
            "backend",
            "gateway",
            "manager",
            "partner",
            "preprod",
            "preview",
            "private",
            "service",
            "staging",
            "storage",
            "testing",
            "toolbox",
        ],
    )
    def test_filters_7char_common_words(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is True

    @pytest.mark.parametrize(
        "api_id",
        [
            "constant",
            "decision",
            "identity",
            "partners",
            "training",
        ],
    )
    def test_filters_8char_common_words(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is True

    @pytest.mark.parametrize(
        "api_id",
        [
            "staging1",
            "staging2",
            "test1",
            "test22",
            "preprod2",
            "prod01",
            "dev01",
            "uat03",
        ],
    )
    def test_filters_explicit_digit_patterns(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is True

    @pytest.mark.parametrize(
        "api_id",
        [
            "3dse1",
            "admin1",
            "l0cal",
            "st0re",
            "62a1edm3",
            "529aed63",
            "a540f86",
            "stagingx",
        ],
    )
    def test_does_not_filter_ids_with_digits(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is False

    @pytest.mark.parametrize(
        "api_id",
        [
            "xyzqw",
            "abcdef",
            "qwerty",
            "foobar",
            "abcde",
            "abcdefgh",
        ],
    )
    def test_does_not_filter_unknown_words(self, api_id, noise_dictionary):
        assert is_common_word_id(api_id, noise_dictionary) is False

    def test_empty_string(self, noise_dictionary):
        assert is_common_word_id("", noise_dictionary) is False
        assert is_common_word_id(None, noise_dictionary) is False


class TestExtractAllTargetIds:
    """Tests for extract_all_target_ids multi-ID extraction."""

    def test_single_id(self, noise_dictionary):
        domains = ["api-3dse1.phish.example.com", "www.phish.example.com"]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert result == {"3dse1": "api-3dse1.phish.example.com"}

    def test_multiple_ids(self, noise_dictionary):
        domains = [
            "api-1d0c2651.mdj.example.com",
            "api-62a1edm3.mdj.example.com",
            "other.mdj.example.com",
        ]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert result == {
            "1d0c2651": "api-1d0c2651.mdj.example.com",
            "62a1edm3": "api-62a1edm3.mdj.example.com",
        }

    def test_duplicate_ids_use_first_domain(self, noise_dictionary):
        domains = [
            "api-3dse1.first.example.com",
            "api-3dse1.second.example.com",
        ]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert result == {"3dse1": "api-3dse1.first.example.com"}

    def test_filters_common_words(self, noise_dictionary):
        domains = ["api-staging.example.com", "api-3dse1.example.com"]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert result == {"3dse1": "api-3dse1.example.com"}

    def test_empty_domains(self, noise_dictionary):
        assert extract_all_target_ids([], noise_dictionary) == {}

    def test_no_matches(self, noise_dictionary):
        domains = ["www.example.com", "mail.example.com"]
        assert extract_all_target_ids(domains, noise_dictionary) == {}

    def test_ids_with_digits_not_filtered(self, noise_dictionary):
        domains = ["api-adm1n.example.com", "api-3dse1.example.com"]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert "adm1n" in result
        assert "3dse1" in result

    def test_case_insensitive(self, noise_dictionary):
        domains = ["API-3DSE1.example.com", "api-62a1edm3.EXAMPLE.com"]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert result == {
            "3dse1": "api-3dse1.example.com",
            "62a1edm3": "api-62a1edm3.example.com",
        }

    def test_known_attacker_domains_are_included(self, noise_dictionary):
        domains = [
            "known-bad-non-api.phish.com",
            "api-3dse1.phish.com",
            "api-62a1edm3.phish.com",
        ]
        result = extract_all_target_ids(domains, noise_dictionary)
        assert result == {
            "3dse1": "api-3dse1.phish.com",
            "62a1edm3": "api-62a1edm3.phish.com",
        }
