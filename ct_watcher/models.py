"""Shared data models for CT Watcher."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Tuple


@dataclass(frozen=True)
class NoiseDictionary:
    """Common api-<id> words and explicit digit-suffix patterns to ignore."""

    words: FrozenSet[str]
    patterns: Tuple[re.Pattern, ...]


@dataclass(frozen=True)
class DuoCheckResult:
    """Result of checking a Duo API hostname against the invalid baseline."""

    status: str
    a_records: List[str]


@dataclass
class AlertInfo:
    """All data gathered for a single alert, passed to notification channels."""

    domain: str
    all_domains: List[str]
    not_before: float | None
    is_known_attacker: bool
    registrar: str | None
    is_cloudflare: bool
    nameservers_list: List[str] | None
    all_ips: List[str] | None
    non_cdn_ips: List[str] | None
    confirmed_attacker_ip_matches: List[str] | None
    reg_date: str | None
    email_status_details: str
    email_status_state: str
    target_info: Dict[str, str] | None
    api_ids: List[str] = field(default_factory=list)
    certkit_url: str | None = None
    sha256: str | None = None
    serial_number: str | None = None
    keyword: str | None = None
    keyword_match_domains: List[str] | None = None
    matched_keywords: List[str] | None = None
    duo_checks: Dict[str, DuoCheckResult] = field(default_factory=dict)
