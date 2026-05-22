"""DNS resolver with optional DoH support."""

import os
from typing import List

import dns.message
import dns.query
import dns.resolver
import dns.exception
import dns.rdatatype
from dns.query import HTTPVersion

_resolver = None
_doh_enabled = None


def _is_doh_enabled() -> bool:
    global _doh_enabled
    if _doh_enabled is None:
        _doh_enabled = bool(os.environ.get("DOH_SERVER"))
    return _doh_enabled


def _get_resolver() -> dns.resolver.Resolver:
    global _resolver
    if _resolver is None:
        _resolver = dns.resolver.Resolver()
    return _resolver


def _query_doh(domain: str, rdtype: dns.rdatatype.RdataType):
    """Send a DNS query via DoH."""
    doh_server = os.environ.get("DOH_SERVER")
    assert doh_server is not None
    q = dns.message.make_query(domain, rdtype)
    resp = dns.query.https(q, doh_server, http_version=HTTPVersion.HTTP_2)
    return resp


def _resolve(domain: str, rdtype: dns.rdatatype.RdataType) -> List[str]:
    """Resolve a DNS record, using DoH if configured."""
    results = []
    try:
        if _is_doh_enabled():
            resp = _query_doh(domain, rdtype)
            for rrset in resp.answer:
                for rr in rrset:
                    results.append(str(rr))
        else:
            answers = _get_resolver().resolve(domain, rdtype)
            for rdata in answers:
                results.append(str(rdata))
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.Timeout:
        pass
    except Exception as e:
        print(f"[!] DNS error resolving {domain}: {e}")
    return results


def resolve_a(domain: str) -> List[str]:
    """Resolve domain to IPv4 addresses. Returns empty list on failure."""
    return _resolve(domain, dns.rdatatype.A)


def resolve_ns(domain: str) -> List[str]:
    """Resolve domain to nameserver hostnames. Returns empty list on failure."""
    nameservers = []
    for result in _resolve(domain, dns.rdatatype.NS):
        nameservers.append(result.rstrip('.'))
    return nameservers
