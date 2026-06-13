"""Apprise alerting for CT Watcher."""

from typing import List, Optional

import apprise

from .config import APPRISE_URLS, EMAIL_ENABLED
from .models import AlertInfo
from .state import state
from .utils import defang_domain, extract_target_id, calculate_freshness


def build_apprise_alert(alert: AlertInfo) -> str:
    """Build a simplified markdown alert for Apprise."""
    domain = alert.domain
    all_domains = alert.all_domains
    cert_timestamp = alert.not_before
    is_known_attacker = alert.is_known_attacker
    registrar = alert.registrar
    is_cloudflare = alert.is_cloudflare
    nameservers = alert.nameservers_list
    all_ips = alert.all_ips
    non_cdn_ips = alert.non_cdn_ips
    confirmed_attacker_ip_matches = alert.confirmed_attacker_ip_matches
    reg_date = alert.reg_date
    email_status = alert.email_status_details
    target_info = alert.target_info
    certkit_url = alert.certkit_url

    # Extract hex ID and look up target info
    hex_id = extract_target_id(domain)
    if target_info is None and hex_id and hex_id in state.target_mapping:
        target_info = state.target_mapping[hex_id]

    lines = []

    # Header: title, matched domain, target info
    title = "🚨 KNOWN ATTACKER DOMAIN DETECTED" if is_known_attacker else "⚠️ Potential Target Match"
    lines.append(f"**{title}**")
    lines.append(f"**Matched Domain:** `{defang_domain(domain)}`")
    if target_info:
        lines.append(f"**Target Organization:** {target_info['name']} ({target_info['email']})")
    elif hex_id:
        lines.append(f"**Hex ID:** `{hex_id}` (Unknown Target)")

    lines.append("")

    # Certificate info
    freshness_str = calculate_freshness(cert_timestamp, fmt="plain")
    lines.append(f"**Certificate Freshness:** {freshness_str}")
    lines.append(f"**Domain Count:** {len(all_domains)}")
    lines.append(f"**Registrar:** {registrar or 'Unknown'}")
    lines.append(f"**Domain Registered:** {reg_date or 'Unknown'}")
    if certkit_url:
        lines.append(f"**CertKit:** {certkit_url}")

    # Nameserver info
    if nameservers is not None:
        cf_status = "Yes" if is_cloudflare else "No"
        lines.append(f"**Cloudflare Nameservers:** {cf_status}")
        if nameservers:
            ns_str = "\n".join(nameservers)
            lines.append(f"**Nameservers:**\n```\n{ns_str}\n```")

    lines.append("")

    # IP addresses
    if all_ips:
        ip_lines = []
        for ip in all_ips[:10]:
            tag = "non-cdn" if non_cdn_ips and ip in non_cdn_ips else "cdn"
            ip_lines.append(f"  {ip} ({tag})")
        if len(all_ips) > 10:
            ip_lines.append(f"  ... and {len(all_ips) - 10} more")
        lines.append("**IP Addresses:**")
        lines.append("\n".join(ip_lines))

    # Confirmed attacker IP matches
    if confirmed_attacker_ip_matches:
        matched = "\n".join(f"  {ip}" for ip in confirmed_attacker_ip_matches[:20])
        if len(confirmed_attacker_ip_matches) > 20:
            matched += f"\n  ... and {len(confirmed_attacker_ip_matches) - 20} more"
        lines.append("**Confirmed Attacker IP Match:**")
        lines.append(matched)

    lines.append("")

    # All domains
    defanged_domains = [defang_domain(d) for d in all_domains]
    domains_block = "\n".join(defanged_domains[:50])
    if len(all_domains) > 50:
        domains_block += f"\n... and {len(all_domains) - 50} more"
    lines.append("**All Domains in Certificate:**")
    lines.append(f"```\n{domains_block}\n```")

    # Email status
    if EMAIL_ENABLED and email_status:
        lines.append(f"**Email Status:** {email_status}")

    return "\n".join(lines)


def send_apprise_alert(
    alert: AlertInfo,
    extra_urls: Optional[List[str]] = None,
) -> None:
    """Send alert via Apprise to configured URLs."""

    urls = []
    if APPRISE_URLS:
        urls.extend(u.strip() for u in APPRISE_URLS.split(",") if u.strip())
    if extra_urls:
        urls.extend(extra_urls)

    if not urls:
        return

    body = build_apprise_alert(alert)

    title = (
        "🚨 CT Alert: Known Attacker"
        if alert.is_known_attacker
        else "⚠️ CT Alert: Potential Match"
    )

    apobj = apprise.Apprise()
    for url in urls:
        apobj.add(url)

    try:
        apobj.notify(title=title, body=body, body_format=apprise.NotifyFormat.MARKDOWN)
    except Exception as e:
        print(f"[!] Apprise notification failed for {alert.domain}: {e}")
