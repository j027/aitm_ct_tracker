import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.loaders import load_noise_words
from ct_watcher.models import NoiseDictionary
from ct_watcher.utils import is_common_word_id


def _write_dictionary(tmp_path, text):
    path = tmp_path / "noise_words.txt"
    path.write_text(text)
    return str(path)


class TestLoadNoiseWords:
    def test_loads_exact_words_and_patterns(self, tmp_path):
        path = _write_dictionary(
            tmp_path,
            """
            # comment
            staging
            GATEWAY
            test#
            """,
        )

        noise = load_noise_words(path)

        assert noise.words == frozenset({"staging", "gateway"})
        assert is_common_word_id("gateway", noise) is True
        assert is_common_word_id("test1", noise) is True
        assert is_common_word_id("test22", noise) is True
        assert is_common_word_id("test", noise) is False

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_noise_words(str(tmp_path / "missing.txt"))

    def test_empty_file_raises(self, tmp_path):
        path = _write_dictionary(tmp_path, "# only comments\n\n")

        with pytest.raises(ValueError, match="empty"):
            load_noise_words(path)

    @pytest.mark.parametrize(
        "entry",
        [
            "abcd",
            "abcdefghi",
            "bad!",
            "staging##",
        ],
    )
    def test_invalid_entry_raises(self, tmp_path, entry):
        path = _write_dictionary(tmp_path, f"{entry}\n")

        with pytest.raises(ValueError):
            load_noise_words(path)

    def test_duplicate_entry_raises(self, tmp_path):
        path = _write_dictionary(tmp_path, "staging\nSTAGING\n")

        with pytest.raises(ValueError, match="duplicate"):
            load_noise_words(path)

    def test_exact_digit_entry_is_supported(self, tmp_path):
        path = _write_dictionary(tmp_path, "test1\n")

        noise = load_noise_words(path)

        assert is_common_word_id("test1", noise) is True


class TestShippedNoiseDictionary:
    def test_words_are_valid(self, noise_dictionary):
        assert noise_dictionary.words

        for word in noise_dictionary.words:
            assert word == word.lower()
            assert 5 <= len(word) <= 8
            assert word.isalnum()

    def test_patterns_are_anchored(self, noise_dictionary):
        assert noise_dictionary.patterns
        for pattern in noise_dictionary.patterns:
            assert pattern.pattern.startswith("^")
            assert pattern.pattern.endswith("$")

    def test_no_word_collides_with_a_duo_target(self, noise_dictionary, target_mapping):
        assert noise_dictionary.words.isdisjoint(target_mapping)


class TestMangledIdRegressions:
    def test_explicit_digit_pattern_does_not_catch_mangled_ids(self):
        noise = NoiseDictionary(
            frozenset({"admin"}),
            (re.compile(r"^test\d+$"),),
        )

        assert is_common_word_id("admin", noise) is True
        assert is_common_word_id("admin1", noise) is False
        assert is_common_word_id("a1b2c", noise) is False
        assert is_common_word_id("t3st1", noise) is False
        assert is_common_word_id("test1", noise) is True

    @pytest.mark.parametrize(
        "api_id",
        [
            "a1b2c",
            "a1b2c1",
            "stagin1",
            "stagingx",
            "preprod9e",
        ],
    )
    def test_shipped_dictionary_keeps_mangled_ids(self, noise_dictionary, api_id):
        assert is_common_word_id(api_id, noise_dictionary) is False
