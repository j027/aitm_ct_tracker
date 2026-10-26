import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.utils import find_matching_keywords, match_keyword_targets


class TestMatchKeywordTargets:
    def test_single_keyword_match(self):
        domains = [
            "adfmorgan.evil.example.com",
            "www.example.com",
        ]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result
        assert "adfmorgan.evil.example.com" in result["morgan"]

    def test_multiple_keywords_same_target(self):
        domains = [
            "adfmorgan.evil.example.com",
            "mailladfmro.evil.example.com",
            "other.example.com",
        ]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["morgan", "mailladfmro"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result
        assert len(result["morgan"]) == 2

    def test_only_matching_keywords_are_returned(self):
        domains = ["adfmorgan.evil.example.com"]
        result = find_matching_keywords(domains, ["morgan", "mailladfmro"])
        assert result == ["morgan"]

    def test_matching_keywords_are_unique(self):
        domains = [
            "adfmorgan.evil.example.com",
            "mailladfmro.evil.example.com",
            "othermorgan.evil.example.com",
        ]
        result = find_matching_keywords(domains, ["morgan", "mailladfmro"])
        assert result == ["morgan", "mailladfmro"]

    def test_case_insensitive(self):
        domains = ["Adfmorgan.EVIL.example.COM"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["MORGAN"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result

    def test_no_match(self):
        domains = ["www.example.com", "mail.example.com"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert result == {}

    def test_keyword_falls_back_to_id(self):
        domains = ["adfmorgan.evil.example.com"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result

    def test_multiple_targets(self):
        domains = [
            "adfmorgan.evil.example.com",
            "csffdcale.evil.example.com",
        ]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["morgan"],
            },
            "csffd": {
                "type": "keyword",
                "name": "Other University",
                "email": "y@y.com",
                "keywords": ["csffd", "csffdcale"],
            },
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result
        assert "csffd" in result

    def test_empty_keyword_targets(self):
        result = match_keyword_targets(["example.com"], {})
        assert result == {}

    def test_empty_domains(self):
        result = match_keyword_targets([], {"morgan": {"keywords": ["morgan"]}})
        assert result == {}

    def test_keyword_matches_subdomain_part_not_full_domain(self):
        domains = ["notmorgan.example.com"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result

    def test_keyword_does_not_match_across_dot_boundary(self):
        domains = ["mor.gan.example.com"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Example University",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert result == {}


class TestKeywordExclusions:
    @staticmethod
    def _targets():
        return {
            "example": {
                "type": "keyword",
                "name": "Example Org",
                "email": "contact@example.edu",
                "keywords": ["acme"],
                "exclude_domains": ["example.edu"],
            }
        }

    def test_excludes_apex_and_subdomains(self):
        for domain in (
            "acme.example.edu",
            "acme-test.example.edu",
            "acme.it-prod-webhosting.aws.example.edu",
            "ACME.EXAMPLE.EDU",
            "acme.example.edu.",
        ):
            assert match_keyword_targets([domain], self._targets()) == {}, domain

    def test_does_not_exclude_lookalike_domains(self):
        for domain in (
            "acme.notexample.edu",
            "acme.example.edu.evil.com",
            "acme.evilexample.edu",
        ):
            result = match_keyword_targets([domain], self._targets())
            assert result["example"] == [domain], domain

    def test_excludes_only_matching_domain_in_mixed_certificate(self):
        result = match_keyword_targets(
            ["acme.example.edu", "acme.evil.com"],
            self._targets(),
        )
        assert result["example"] == ["acme.evil.com"]

    def test_exclusions_are_per_target(self):
        targets = {
            "example": self._targets()["example"],
            "other": {
                "type": "keyword",
                "name": "Other Org",
                "email": "x@example.com",
                "keywords": ["acme"],
            },
        }
        result = match_keyword_targets(["acme.example.edu"], targets)
        assert "example" not in result
        assert result["other"] == ["acme.example.edu"]

    def test_default_substring_matches_longer_variant(self):
        result = match_keyword_targets(["acmecorp.evil.com"], self._targets())
        assert result["example"] == ["acmecorp.evil.com"]

    def test_absent_exclusions_do_not_filter(self):
        targets = {
            "example": {
                "type": "keyword",
                "name": "Example Org",
                "email": "alerts@example.edu",
                "keywords": ["acme"],
            }
        }
        result = match_keyword_targets(["acme.example.edu"], targets)
        assert result["example"] == ["acme.example.edu"]
