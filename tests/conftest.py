import os
import sys
import pytest

# Allow importing ct_watcher package
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ct_watcher.loaders import (
    load_target_mapping,
    load_known_attacker_domains,
    load_known_attacker_ips,
)


@pytest.fixture(scope="session")
def target_mapping():
    """Load Duo target mapping from targets.json. Returns empty dict if file missing."""
    duo_targets, _ = load_target_mapping()
    return duo_targets


@pytest.fixture(scope="session")
def keyword_targets():
    """Load keyword targets from targets.json. Returns empty dict if file missing."""
    _, kw_targets = load_target_mapping()
    return kw_targets


@pytest.fixture(scope="session")
def known_attacker_domains():
    """Load known attacker domains. Returns empty set if file missing."""
    return load_known_attacker_domains()


@pytest.fixture(scope="session")
def known_attacker_ips():
    """Load known attacker IPs. Returns empty set if file missing."""
    return load_known_attacker_ips()
