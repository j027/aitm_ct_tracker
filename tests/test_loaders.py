import json
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.loaders import load_target_mapping


def _write_targets(tmp_path, mapping):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(mapping))
    return str(path)


class TestLoadTargetMappingExclusions:
    def test_duo_keyword_target_carries_normalized_exclusions(self, tmp_path):
        path = _write_targets(
            tmp_path,
            {
                "1234abcd": {
                    "name": "Example Org",
                    "email": "test@example.edu",
                    "keywords": ["acme", "sample"],
                    "exclude_domains": ["EXAMPLE.EDU."],
                }
            },
        )

        duo_targets, keyword_targets = load_target_mapping(path)

        assert duo_targets["1234abcd"]["name"] == "Example Org"
        assert keyword_targets["acme"]["exclude_domains"] == ["example.edu"]
        assert keyword_targets["acme"]["keywords"] == ["acme", "sample"]

    def test_explicit_keyword_target_carries_exclusions(self, tmp_path):
        path = _write_targets(
            tmp_path,
            {
                "example": {
                    "type": "keyword",
                    "name": "Example Org",
                    "email": "test@example.edu",
                    "keywords": [" acme "],
                    "exclude_domains": ["example.edu", "example.org"],
                }
            },
        )

        _, keyword_targets = load_target_mapping(path)

        assert keyword_targets["example"]["keywords"] == ["acme"]
        assert keyword_targets["example"]["exclude_domains"] == [
            "example.edu",
            "example.org",
        ]

    def test_explicit_keyword_target_without_keywords_allows_exclusions(self, tmp_path):
        path = _write_targets(
            tmp_path,
            {
                "example": {
                    "type": "keyword",
                    "name": "Example Org",
                    "email": "test@example.edu",
                    "exclude_domains": ["example.edu"],
                }
            },
        )

        _, keyword_targets = load_target_mapping(path)

        assert keyword_targets["example"]["exclude_domains"] == ["example.edu"]
        assert "keywords" not in keyword_targets["example"]

    @pytest.mark.parametrize(
        "entry",
        [
            {
                "type": "keyword",
                "name": "Bad",
                "email": "x@example.com",
                "keywords": ["acme"],
                "exclude_domains": "example.edu",
            },
            {
                "type": "keyword",
                "name": "Bad",
                "email": "x@example.com",
                "keywords": ["acme"],
                "exclude_domains": [123],
            },
            {
                "type": "keyword",
                "name": "Bad",
                "email": "x@example.com",
                "keywords": ["acme"],
                "exclude_domains": [""],
            },
            {
                "type": "keyword",
                "name": "Bad",
                "email": "x@example.com",
                "keywords": ["acme"],
                "exclude_domains": ["*.example.edu"],
            },
            {
                "type": "keyword",
                "name": "Bad",
                "email": "x@example.com",
                "keywords": ["acme"],
                "exclude_domains": ["https://example.edu"],
            },
            {
                "name": "Bad",
                "email": "x@example.com",
                "exclude_domains": ["example.edu"],
            },
            {
                "type": "keyword",
                "name": "Bad",
                "email": "x@example.com",
                "keywords": [],
                "exclude_domains": ["example.edu"],
            },
        ],
    )
    def test_invalid_exclusion_config_raises(self, tmp_path, entry):
        path = _write_targets(tmp_path, {"bad": entry})

        with pytest.raises(ValueError):
            load_target_mapping(path)
