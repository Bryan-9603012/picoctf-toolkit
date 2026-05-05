# core/scope.py
from __future__ import annotations

import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urlparse


def _resolve_host_ips(host: str) -> List[str]:
    ips: List[str] = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                ips.append(sockaddr[0])
            elif fam == socket.AF_INET6:
                ips.append(sockaddr[0])
    except Exception:
        pass
    return sorted(set(ips))


def _is_private_or_local_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except Exception:
        return True


def in_scope(
    url: str,
    allow_hosts: List[str],
    allow_suffixes: List[str],
    *,
    deny_private: bool = False,
) -> Tuple[bool, str]:
    u = urlparse(url)
    host = u.hostname or ""
    if not host:
        return False, "no-host"

    if allow_hosts or allow_suffixes:
        if host in allow_hosts:
            pass
        else:
            ok = False
            for sfx in allow_suffixes:
                sfx = sfx if sfx.startswith(".") else "." + sfx
                if host.endswith(sfx):
                    ok = True
                    break
            if not ok:
                return False, f"host-not-allowed:{host}"

    if deny_private:
        ips = _resolve_host_ips(host)
        if not ips:
            return False, f"dns-unresolved:{host}"
        for ip in ips:
            if _is_private_or_local_ip(ip):
                return False, f"private-ip:{host}->{ip}"

    return True, "ok"