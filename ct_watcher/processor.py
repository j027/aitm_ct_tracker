"""Certificate message processing for CT Watcher."""

import json
import time
import traceback
from typing import Dict, List

from .config import (
    DOMAIN_REGEX,
    SEEN_DOMAINS_LIMIT,
    ALERTED_DOMAINS_LIMIT,
    ALERTED_CERTIFICATES_LIMIT,
    MAX_CERT_AGE_SECONDS,
    DISCORD_WEBHOOK,
    DISCORD_WEBHOOK_WATCHED,
    APPRISE_URLS,
    APPRISE_URLS_WATCHED,
)
from .state import state
from .domain_checks import is_known_attacker_domain, get_nameservers, get_domain_info
from .ip_tracking import (
    get_attacker_ips_for_domain,
    resolve_and_classify,
    track_resolved_ips,
)
from .discord import send_discord_alert
from .apprise import send_apprise_alert
from .email_sender import send_automated_target_email
from .logger import log_alert_to_csv
from .models import AlertInfo
from .utils import (
    extract_target_id,
    is_common_word_id,
    ids_for_target,
    match_keyword_targets,
)


# The IPng Networks 'Gouda2026h2' CT log serves empty cert data for
# PrecertLogEntry entries. certstream-server-go faithfully computes the
# hash of the empty byte sequence, resulting in SHA256("") =
# E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
# certkit cannot look up this bogus hash, but it can look up the
# serial number (after its ~4-5 minute indexing delay). Detect and
# skip the bogus value, falling through to the serial-based URL.
_EMPTY_SHA256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"


def _build_certkit_url(sha256: str | None, serial_number: str | None) -> str | None:
    """Build a CertKit certificate details URL.

    Uses the SHA-256 fingerprint as the preferred lookup key.  Falls back to
    the serial number when the SHA-256 is missing or is the known-bogus
    empty-string hash returned for IPng Networks precertificates.
    """
    if sha256:
        clean = sha256.replace(":", "")
        if clean.upper() != _EMPTY_SHA256:
            return f"https://www.certkit.io/tools/ct-logs/certificate?sha256={clean}"
    if serial_number:
        return f"https://www.certkit.io/tools/ct-logs/certificate?serial={serial_number}"
    return None


def _print_stats() -> None:
    """Print processing stats every minute."""
    current_time = time.time()
    if current_time - state.last_stats_time >= 60:
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(
            f"[{timestamp_str}] Processed {state.cert_count} certificates"
            f" in the last minute | Total alerts: {state.total_alerts_count}"
        )
        state.reset_stats()


def _dispatch_alert(alert: AlertInfo) -> None:
    """Send alert to all configured notification channels (Discord and/or Apprise)."""
    log_alert_to_csv(alert)

    # Determine watched org channels
    primary_id = alert.api_ids[0] if alert.api_ids else None
    if primary_id is None and alert.keyword:
        primary_id = alert.keyword
    is_watched = primary_id is not None and primary_id in state.watched_org_ids
    watched_discord = DISCORD_WEBHOOK_WATCHED if is_watched else None
    watched_apprise = None
    if is_watched and APPRISE_URLS_WATCHED:
        watched_apprise = [u.strip() for u in APPRISE_URLS_WATCHED.split(",") if u.strip()]

    # Discord
    if DISCORD_WEBHOOK:
        send_discord_alert(alert, extra_webhook_url=watched_discord)

    # Apprise
    if APPRISE_URLS or watched_apprise:
        send_apprise_alert(alert, extra_urls=watched_apprise)


def _finalize_alert(
    domain: str,
    all_domains: List[str],
    not_before: float | None,
    is_known_attacker: bool,
    registrar: str | None,
    is_cloudflare: bool,
    nameservers_list: List[str] | None,
    all_ips: List[str] | None,
    non_cdn_ips: List[str] | None,
    confirmed_attacker_ip_matches: List[str] | None,
    reg_date: str | None,
    api_ids: List[str],
    api_id: str | None,
    certkit_url: str | None,
    sha256: str | None,
    serial_number: str | None,
    keyword: str | None = None,
    keyword_match_domains: List[str] | None = None,
) -> None:
    """Resolve targets, send per-target emails, build and dispatch alert.

    Called by ``_handle_known_attacker``, ``_handle_pattern_match``, and
    ``_handle_keyword_match`` after their handler-specific detection logic
    is complete.
    """
    # Resolve primary target: keyword targets use keyword_targets, Duo
    # targets use target_mapping.
    target_info = None
    if keyword:
        if keyword in state.keyword_targets:
            target_info = state.keyword_targets[keyword]
            if not api_id:
                api_id = keyword
    else:
        target_info = state.target_mapping.get(api_id) if api_id else None
        if not target_info and api_ids:
            for aid in api_ids:
                if aid in state.target_mapping:
                    api_id = aid
                    target_info = state.target_mapping[aid]
                    break

    # Send emails — one per distinct target
    email_results = []
    if keyword and target_info:
        primary_ids = [keyword]
        status = send_automated_target_email(
            target_info=target_info,
            domain=domain,
            all_domains=all_domains,
            non_cdn_ips=non_cdn_ips,
            target_api_ids=[],
            keyword=keyword,
        )
        email_results.append((target_info["name"], status))
    else:
        primary_ids = ids_for_target(
            api_ids,
            target_info.get("email") if target_info else None,
            state.target_mapping,
        )
        status = send_automated_target_email(
            target_info=target_info,
            domain=domain,
            all_domains=all_domains,
            non_cdn_ips=non_cdn_ips,
            target_api_ids=primary_ids,
        )
        email_results.append((target_info["name"] if target_info else "unknown", status))

        if len(api_ids) > 1:
            sent_emails = (
                {target_info["email"]} if (target_info and target_info.get("email")) else set()
            )
            for aid in api_ids:
                if aid == api_id:
                    continue
                ti = state.target_mapping.get(aid)
                if ti and ti.get("email") and ti["email"] not in sent_emails:
                    sent_emails.add(ti["email"])
                    ti_ids = ids_for_target(api_ids, ti["email"], state.target_mapping)
                    status = send_automated_target_email(
                        target_info=ti,
                        domain=domain,
                        all_domains=all_domains,
                        non_cdn_ips=non_cdn_ips,
                        target_api_ids=ti_ids,
                    )
                    email_results.append((ti["name"], status))

    # Build combined email status
    lines = []
    sent_count = 0
    for name, s in email_results:
        if s.state == "sent":
            sent_count += 1
            lines.append(f"✅ {name} — {s.details}")
        elif s.state == "failed":
            lines.append(f"❌ {name} — {s.details}")
        else:
            lines.append(f"⏭️ {name} — {s.details}")

    email_status_details = "\n".join(lines) if lines else "No emails sent"
    if sent_count > 0:
        email_status_state = "sent"
    elif any(s.state == "failed" for _, s in email_results):
        email_status_state = "failed"
    else:
        email_status_state = "skipped"

    alert = AlertInfo(
        domain=domain,
        all_domains=all_domains,
        not_before=not_before,
        is_known_attacker=is_known_attacker,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers_list=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
        reg_date=reg_date,
        email_status_details=email_status_details,
        email_status_state=email_status_state,
        target_info=target_info,
        api_ids=api_ids,
        certkit_url=certkit_url,
        sha256=sha256,
        serial_number=serial_number,
        keyword=keyword,
        keyword_match_domains=keyword_match_domains if keyword else None,
    )
    _dispatch_alert(alert)
    state.total_alerts_count += 1


def _handle_known_attacker(
    domain: str,
    all_domains: List[str],
    cert_id: int,
    not_before: float | None,
    certkit_url: str | None = None,
    sha256: str | None = None,
    serial_number: str | None = None,
    api_ids: List[str] | None = None,
    keyword: str | None = None,
    keyword_match_domains: List[str] | None = None,
) -> bool:
    """Handle known attacker domain detection. Returns True if alert was sent."""
    with state.lock:
        if domain in state.alerted_domains:
            return False
        if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
            state.clear_alerted_domains()
        state.alerted_domains.add(domain)
        if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
            state.clear_alerted_certificates()
        state.alerted_certificates.add(cert_id)

    # Get nameserver and registrar info
    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)

    # Resolve and track IP addresses
    all_ips, non_cdn_ips = get_attacker_ips_for_domain(domain)
    confirmed_attacker_ip_matches = sorted(ip for ip in all_ips if ip in state.known_attacker_ips)

    print(
        f"[!] KNOWN ATTACKER DOMAIN DETECTED: {domain}"
        f" (Registrar: {registrar}, IPs: {len(all_ips)},"
        f" Blockable: {len(non_cdn_ips)})"
    )

    # Known attacker domains are always high confidence
    if api_ids is None:
        api_ids = []
    if not api_ids:
        aid = extract_target_id(domain)
        if aid:
            api_ids = [aid]
        if not api_ids:
            for d in all_domains:
                candidate_id = extract_target_id(d.strip().lower())
                if candidate_id:
                    api_ids = [candidate_id]
                    break

    api_id = api_ids[0] if api_ids else None

    _finalize_alert(
        domain=domain,
        all_domains=all_domains,
        not_before=not_before,
        is_known_attacker=True,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers_list=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
        reg_date=reg_date,
        api_ids=api_ids,
        api_id=api_id,
        certkit_url=certkit_url,
        sha256=sha256,
        serial_number=serial_number,
        keyword=keyword,
        keyword_match_domains=keyword_match_domains,
    )
    return True


def _handle_pattern_match(
    domain: str,
    all_domains: List[str],
    cert_id: int,
    not_before: float | None,
    certkit_url: str | None = None,
    sha256: str | None = None,
    serial_number: str | None = None,
    api_ids: List[str] | None = None,
) -> bool:
    """Handle pattern match detection. Returns True if alert was sent."""
    with state.lock:
        if domain in state.alerted_domains:
            return False
        if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
            state.clear_alerted_domains()
        state.alerted_domains.add(domain)

    print(f"[+] Potential match: {domain}")

    # Only alert if multiple domains in certificate
    if len(all_domains) <= 1:
        print(f"[~] Skipping {domain} (only single domain in certificate)")
        return False

    # Get nameserver and registrar info
    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)

    # Resolve IPs for confidence check — tracking deferred until high confidence confirmed
    all_ips, non_cdn_ips = resolve_and_classify(domain)
    confirmed_attacker_ip_matches = sorted(ip for ip in all_ips if ip in state.known_attacker_ips)

    # Determine confidence level
    # High confidence if:
    # 1. The extracted ID matches a known target (in target_mapping), OR
    # 2. Cloudflare nameservers AND multiple domains AND 8-char hex ID, OR
    # 3. Confirmed attacker IP match
    #
    # Unknown 5-char alphanumeric IDs are always low confidence to avoid
    # alert fatigue
    api_id = extract_target_id(domain)
    if api_ids is None:
        api_ids = [api_id] if api_id else []
    is_known_target = any(aid in state.target_mapping for aid in api_ids) if api_ids else False
    is_8char_hex = api_id and len(api_id) == 8 and all(c in "0123456789abcdef" for c in api_id)

    has_confirmed_attacker_ip_match = bool(confirmed_attacker_ip_matches)
    high_confidence = bool(
        is_known_target
        or (is_cloudflare and len(all_domains) > 1 and is_8char_hex)
        or has_confirmed_attacker_ip_match
    )

    if not high_confidence:
        print(f"[~] Skipping {domain} (low confidence - no alert)")
        return False

    # High confidence confirmed — now track IPs
    track_resolved_ips(all_ips, non_cdn_ips, domain)

    cf_status = "Cloudflare" if is_cloudflare else "Non-Cloudflare"
    print(
        f"[!] ALERT [HIGH]: Multiple domains ({len(all_domains)}),"
        f" {cf_status} NS: {domain} (Registrar: {registrar},"
        f" IPs: {len(all_ips)}, Blockable: {len(non_cdn_ips)})"
    )

    if len(api_ids) > 1:
        print(f"    -> Multi-Duo ({len(api_ids)} IDs): {', '.join(api_ids)}")
    if is_known_target and api_id:
        known_targets = [aid for aid in api_ids if aid in state.target_mapping]
        for kt in known_targets:
            print(f"    -> Known target: {state.target_mapping[kt]['name']}")
    elif has_confirmed_attacker_ip_match:
        print(
            f"    -> Escalated to HIGH via known attacker IP match:"
            f" {', '.join(confirmed_attacker_ip_matches)}"
        )
    elif is_cloudflare and is_8char_hex:
        print("    -> 8-char hex + Cloudflare nameservers")

    with state.lock:
        if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
            state.clear_alerted_certificates()
        state.alerted_certificates.add(cert_id)

    _finalize_alert(
        domain=domain,
        all_domains=all_domains,
        not_before=not_before,
        is_known_attacker=False,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers_list=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
        reg_date=reg_date,
        api_ids=api_ids,
        api_id=api_id,
        certkit_url=certkit_url,
        sha256=sha256,
        serial_number=serial_number,
    )
    return True


def _handle_keyword_match(
    domain: str,
    all_domains: List[str],
    cert_id: int,
    not_before: float | None,
    keyword: str,
    keyword_match_domains: List[str],
    certkit_url: str | None = None,
    sha256: str | None = None,
    serial_number: str | None = None,
) -> bool:
    """Handle keyword-only match (no known attacker, no Duo pattern).

    Only alerts when a confirmed attacker IP match is found, to keep
    false positives under control for targets that don't use Duo.
    """
    with state.lock:
        if domain in state.alerted_domains:
            return False
        if len(state.alerted_domains) > ALERTED_DOMAINS_LIMIT:
            state.clear_alerted_domains()
        state.alerted_domains.add(domain)

    target_info = state.keyword_targets.get(keyword)
    if not target_info:
        print(f"[~] Skipping keyword '{keyword}' (not in keyword_targets)")
        return False

    print(f"[+] Potential keyword match: {domain} ({keyword} -> {target_info['name']})")

    is_cloudflare, nameservers_list = get_nameservers(domain)
    registrar, reg_date = get_domain_info(domain)
    all_ips, non_cdn_ips = resolve_and_classify(domain)
    confirmed_attacker_ip_matches = sorted(ip for ip in all_ips if ip in state.known_attacker_ips)

    has_confirmed_attacker_ip = bool(confirmed_attacker_ip_matches)

    if not has_confirmed_attacker_ip:
        cf_tag = "CF" if is_cloudflare else "Non-CF"
        print(
            f"[~] Skipping {domain} ({keyword} -> {target_info['name']})"
            f" — low confidence ({cf_tag}, no attacker IP match,"
            f" {len(all_domains)} domain(s) in cert)"
        )
        return False

    track_resolved_ips(all_ips, non_cdn_ips, domain)
    print(
        f"[!] ALERT [KEYWORD]: {domain} ({keyword} -> {target_info['name']})"
        f" — escalated via attacker IP match:"
        f" {', '.join(confirmed_attacker_ip_matches)}"
    )

    with state.lock:
        if len(state.alerted_certificates) > ALERTED_CERTIFICATES_LIMIT:
            state.clear_alerted_certificates()
        state.alerted_certificates.add(cert_id)

    _finalize_alert(
        domain=domain,
        all_domains=all_domains,
        not_before=not_before,
        is_known_attacker=False,
        registrar=registrar,
        is_cloudflare=is_cloudflare,
        nameservers_list=nameservers_list,
        all_ips=all_ips,
        non_cdn_ips=non_cdn_ips,
        confirmed_attacker_ip_matches=confirmed_attacker_ip_matches,
        reg_date=reg_date,
        api_ids=[],
        api_id=None,
        certkit_url=certkit_url,
        sha256=sha256,
        serial_number=serial_number,
        keyword=keyword,
        keyword_match_domains=keyword_match_domains,
    )
    return True


def process_message(message_str: str) -> None:
    """Process incoming CT log message from certstream server."""
    try:
        try:
            message = json.loads(message_str)
        except json.JSONDecodeError as e:
            print(f"[!] JSON decode error: {e}")
            return

        msg_type = message.get("message_type")
        if msg_type != "certificate_update":
            return

        data = message.get("data", {})
        leaf_cert = data.get("leaf_cert", {})
        all_domains = leaf_cert.get("all_domains", []) or []

        if not all_domains:
            return

        # Create unique certificate identifier
        cert_id = hash(tuple(sorted(d.strip().lower() for d in all_domains)))

        sha256 = leaf_cert.get("sha256")
        serial_number = leaf_cert.get("serial_number")
        certkit_url = _build_certkit_url(sha256, serial_number)

        # Check if already processed
        with state.lock:
            if cert_id in state.alerted_certificates:
                return

        # Check certificate age
        not_before = leaf_cert.get("not_before")
        if not_before:
            try:
                cert_age_seconds = time.time() - not_before
                if cert_age_seconds > MAX_CERT_AGE_SECONDS:
                    return
            except (ValueError, TypeError):
                pass

        # Update stats
        state.cert_count += 1
        _print_stats()

        # First pass: collect Duo api-IDs, known attacker domains, and keyword matches
        known_attacker_domains = []
        matched_patterns = {}
        keyword_matches: Dict[str, list] = {}

        for d in all_domains:
            try:
                domain = d.strip().lower()

                with state.lock:
                    if domain in state.seen_domains:
                        continue
                    if len(state.seen_domains) > SEEN_DOMAINS_LIMIT:
                        state.clear_seen_domains()
                    state.seen_domains.add(domain)

                if is_known_attacker_domain(domain, state.known_attacker_domains):
                    known_attacker_domains.append(domain)
                    continue

                if DOMAIN_REGEX.match(domain):
                    aid = extract_target_id(domain)
                    if aid and not is_common_word_id(aid):
                        if aid not in matched_patterns:
                            matched_patterns[aid] = domain

            except Exception as e:
                print(f"[!] Error processing domain {d}: {e}")
                continue

        # Run keyword scan against all domains (including known attacker
        # ones — so we can enrich the known-attacker alert with the correct
        # target info even when no Duo ID is present).
        if state.keyword_targets:
            keyword_matches = match_keyword_targets(all_domains, state.keyword_targets)

        all_api_ids = sorted(matched_patterns.keys())

        if known_attacker_domains:
            # If any known-attacker domain also matched a keyword, enrich
            # the alert so target_info is populated correctly.
            first_domain = known_attacker_domains[0]
            ka_keyword = None
            ka_kw_domains = None
            for kw_id, kw_domains in keyword_matches.items():
                safe = [d.strip().lower() for d in known_attacker_domains]
                matching = [d for d in kw_domains if d in safe]
                if matching:
                    ka_keyword = kw_id
                    ka_kw_domains = matching
                    break
            _handle_known_attacker(
                first_domain,
                all_domains,
                cert_id,
                not_before,
                certkit_url,
                sha256,
                serial_number,
                api_ids=all_api_ids,
                keyword=ka_keyword,
                keyword_match_domains=ka_kw_domains,
            )
        elif matched_patterns:
            _handle_pattern_match(
                list(matched_patterns.values())[0],
                all_domains,
                cert_id,
                not_before,
                certkit_url,
                sha256,
                serial_number,
                api_ids=all_api_ids,
            )
        elif keyword_matches:
            # Keyword-only matches — each unique keyword fires its own
            # handler (high-confidence only if backed by attacker IP).
            seen_kw = set()
            for kw_id, kw_domains in keyword_matches.items():
                if kw_id in seen_kw:
                    continue
                if kw_id not in state.keyword_targets:
                    continue
                seen_kw.add(kw_id)
                _handle_keyword_match(
                    kw_domains[0],
                    all_domains,
                    cert_id,
                    not_before,
                    kw_id,
                    kw_domains,
                    certkit_url,
                    sha256,
                    serial_number,
                )

    except Exception as e:
        print(f"[!] Error in process_message: {e}")
        traceback.print_exc()
