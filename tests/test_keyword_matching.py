import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.utils import match_keyword_targets


class TestMatchKeywordTargets:
    def test_single_keyword_match(self):
        domains = [
            "adfmorgan.gobac.shadylakesranch.com",
            "www.example.com",
        ]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Morgan State",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result
        assert "adfmorgan.gobac.shadylakesranch.com" in result["morgan"]

    def test_multiple_keywords_same_target(self):
        domains = [
            "adfmorgan.gobac.shadylakesranch.com",
            "mailladfmro.gobac.shadylakesranch.com",
            "other.example.com",
        ]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Morgan State",
                "email": "x@x.com",
                "keywords": ["morgan", "mailladfmro"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result
        assert len(result["morgan"]) == 2

    def test_case_insensitive(self):
        domains = ["Adfmorgan.GOBAC.shadylakesranch.COM"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Morgan State",
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
                "name": "Morgan State",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert result == {}

    def test_keyword_falls_back_to_id(self):
        domains = ["adfmorgan.gobac.shadylakesranch.com"]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Morgan State",
                "email": "x@x.com",
            }
        }
        result = match_keyword_targets(domains, kt)
        assert "morgan" in result

    def test_multiple_targets(self):
        domains = [
            "adfmorgan.gobac.shadylakesranch.com",
            "csffdcale.gobac.shadylakesranch.com",
        ]
        kt = {
            "morgan": {
                "type": "keyword",
                "name": "Morgan State",
                "email": "x@x.com",
                "keywords": ["morgan"],
            },
            "csffd": {
                "type": "keyword",
                "name": "Cal State Fullerton",
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
                "name": "Morgan",
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
                "name": "Morgan",
                "email": "x@x.com",
                "keywords": ["morgan"],
            }
        }
        result = match_keyword_targets(domains, kt)
        assert result == {}
