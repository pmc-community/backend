"""
------------------------------------------------------------
get_client_ip(c) — single entry point, single file.

Trusted proxies are loaded from the configured data provider.

For DATA_SOURCE=fs:
  - TRUSTED_PROXY_IPS comes from   ./data/general/trusted-proxy-ip.txt
  - TRUSTED_PROXY_CIDRS comes from ./data/general/trusted-proxy-cidrs.txt

These values support hot reload.

Connection-address detection uses the ASGI ``scope["client"]`` - the actual
TCP peer.  IMPORTANT: run uvicorn with ``proxy_headers=False`` (main.py does),
otherwise uvicorn rewrites the peer address from X-Forwarded-For and the trust
decisions below would be taken on a client-controlled value.

Where no socket information is available, get_client_ip() falls back to the
forwarding headers.
------------------------------------------------------------
"""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

from app.core.context import Context
from app.data_provider import data

# ============================================================
# IP / CIDR parsing
# ============================================================

_IPV4_RE = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", re.ASCII)
_IPV6_GROUP_RE = re.compile(r"[0-9a-fA-F]{1,4}")


def ipv4_to_int(ip: str) -> Optional[int]:
    match = _IPV4_RE.fullmatch(ip)

    if not match:
        return None

    parts = [int(p) for p in match.groups()]

    if any(part < 0 or part > 255 for part in parts):
        return None

    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def ipv6_to_bigint(ip: str) -> Optional[int]:
    if ":" not in ip:
        return None

    # An IPv6 address may contain at most one "::".
    first_double_colon = ip.find("::")

    if first_double_colon != -1 and first_double_colon != ip.rfind("::"):
        return None

    if first_double_colon != -1:
        head, tail = ip.split("::")

        head_parts = head.split(":") if head else []
        tail_parts = tail.split(":") if tail else []

        missing = 8 - len(head_parts) - len(tail_parts)

        # "::" must replace at least one group.
        if missing < 1:
            return None

        full = [*head_parts, *(["0"] * missing), *tail_parts]
    else:
        full = ip.split(":")

        if len(full) != 8:
            return None

    if len(full) != 8:
        return None

    result = 0

    for group in full:
        # Strict IPv6 hexadecimal group validation.
        if not _IPV6_GROUP_RE.fullmatch(group):
            return None

        result = (result << 16) | int(group, 16)

    return result


def is_valid_ip(ip: str) -> bool:
    normalized = ip.strip()
    return ipv4_to_int(normalized) is not None or ipv6_to_bigint(normalized) is not None


# ============================================================
# CIDR parsing
# ============================================================


@dataclass
class ParsedCIDR:
    base: int
    bits: int
    is_v4: bool


def parse_cidr(cidr: str) -> Optional[ParsedCIDR]:
    parts = cidr.strip().split("/")

    if len(parts) != 2:
        return None

    address, prefix_string = parts

    if not address or not re.fullmatch(r"[0-9]+", prefix_string):
        return None

    prefix = int(prefix_string)

    ipv4 = ipv4_to_int(address)

    if ipv4 is not None:
        if prefix < 0 or prefix > 32:
            return None

        return ParsedCIDR(base=ipv4, bits=prefix, is_v4=True)

    ipv6 = ipv6_to_bigint(address)

    if ipv6 is not None:
        if prefix < 0 or prefix > 128:
            return None

        return ParsedCIDR(base=ipv6, bits=prefix, is_v4=False)

    return None


def ip_in_cidr(ip: str, cidr: ParsedCIDR) -> bool:
    if cidr.is_v4:
        value = ipv4_to_int(ip)

        if value is None:
            return False

        mask = 0 if cidr.bits == 0 else (0xFFFFFFFF << (32 - cidr.bits)) & 0xFFFFFFFF

        return (value & mask) == (cidr.base & mask)

    value6 = ipv6_to_bigint(ip)

    if value6 is None:
        return False

    full = (1 << 128) - 1
    mask6 = 0 if cidr.bits == 0 else (full << (128 - cidr.bits)) & full

    return (value6 & mask6) == (cidr.base & mask6)


# ============================================================
# Trusted proxy matcher
# ============================================================


def build_trusted_proxy_matcher(ips_csv: str, cidrs_csv: str) -> Callable[[str], bool]:
    ips = {
        ip
        for ip in (p.strip() for p in ips_csv.split(","))
        if ip and is_valid_ip(ip)
    }

    cidrs = [
        parsed
        for parsed in (parse_cidr(c.strip()) for c in cidrs_csv.split(",") if c.strip())
        if parsed is not None
    ]

    def matcher(ip: str) -> bool:
        normalized = ip.strip()
        return normalized in ips or any(ip_in_cidr(normalized, cidr) for cidr in cidrs)

    return matcher


# ------------------------------------------------------------
# Cached trusted-proxy matcher.
#
# The matcher is rebuilt only when the hot-reloaded trusted
# proxy configuration changes.
# ------------------------------------------------------------

_trusted_proxy_matcher: Optional[Callable[[str], bool]] = None
_trusted_proxy_ips_snapshot = ""
_trusted_proxy_cidrs_snapshot = ""


def is_trusted_proxy(ip: str) -> bool:
    global _trusted_proxy_matcher, _trusted_proxy_ips_snapshot, _trusted_proxy_cidrs_snapshot

    ips = data.TRUSTED_PROXY_IPS
    cidrs = data.TRUSTED_PROXY_CIDRS

    if (
        _trusted_proxy_matcher is None
        or ips != _trusted_proxy_ips_snapshot
        or cidrs != _trusted_proxy_cidrs_snapshot
    ):
        _trusted_proxy_matcher = build_trusted_proxy_matcher(ips, cidrs)
        _trusted_proxy_ips_snapshot = ips
        _trusted_proxy_cidrs_snapshot = cidrs

    return _trusted_proxy_matcher(ip)


# ============================================================
# Public IP rule matcher
# ============================================================


def ip_matches_rule(ip: str, rule: str) -> bool:
    normalized_ip = ip.strip()
    normalized_rule = rule.strip()

    if not is_valid_ip(normalized_ip):
        return False

    # Exact IP.
    if "/" not in normalized_rule:
        return (
            normalized_ip == normalized_rule
            or normalized_ip.lower() == normalized_rule.lower()
        )

    # CIDR.
    parsed_cidr = parse_cidr(normalized_rule)

    if not parsed_cidr:
        return False

    return ip_in_cidr(normalized_ip, parsed_cidr)


# ============================================================
# Single-IP forwarding headers
#
# Loaded from data.provider and the list itself is mutated during hot reload,
# so keeping this reference is safe.
# ============================================================

SINGLE_IP_HEADERS = data.SINGLE_IP_HEADERS


# ============================================================
# Public API — get_client_ip
# ============================================================


def get_client_ip(c: Context) -> str:
    """
    Returns the client IP for the current request.

    Direct connection:
      The actual TCP connection address when it is not a trusted proxy.

    Trusted proxy:
      If the TCP peer is trusted, forwarding headers are evaluated.

    No socket information:
      Forwarding headers are used.
    """
    connection_address = c.remote_address

    conn_ip = (
        connection_address
        if connection_address and is_valid_ip(connection_address)
        else None
    )

    # --------------------------------------------------------
    # Direct client connection.
    #
    # If the actual TCP peer is not a trusted proxy, it is the client.
    # Do not trust forwarding headers from it.
    # --------------------------------------------------------

    if conn_ip and not is_trusted_proxy(conn_ip):
        return conn_ip

    # --------------------------------------------------------
    # Either the connection came from a trusted proxy, or the runtime does not
    # expose a TCP connection.  In both cases forwarding information can be
    # evaluated.
    # --------------------------------------------------------

    forwarded_for = c.req.header("x-forwarded-for")

    if forwarded_for:
        chain = [
            ip
            for ip in (part.strip() for part in forwarded_for.split(","))
            if is_valid_ip(ip)
        ]

        # Walk from the closest proxy toward the client.  The first untrusted
        # address encountered is treated as the client address.
        for ip in reversed(chain):
            if not is_trusted_proxy(ip):
                return ip

        # Every address in the chain was trusted.
        if chain:
            return chain[0]

    # --------------------------------------------------------
    # Other single-IP forwarding headers.
    # --------------------------------------------------------

    for name in SINGLE_IP_HEADERS:
        value = (c.req.header(name) or "").strip()

        if value and is_valid_ip(value):
            return value

    # --------------------------------------------------------
    # If the connection peer was a trusted proxy but no usable forwarding
    # information was available, return the proxy address rather than "unknown".
    # --------------------------------------------------------

    if conn_ip:
        return conn_ip

    return "unknown"


# ============================================================
# Portable server identity
# ============================================================

DEFAULT_SERVER_NAME = "unknown"


@dataclass
class ServerIdentity:
    #: Logical name assigned to this API instance (e.g. api-production).
    name: str
    #: Physical/runtime hostname (os hostname, None when not available).
    hostname: Optional[str]
    #: Non-internal local network-interface addresses.
    ips: list[str] = field(default_factory=list)
    #: True when hostname/IP information comes from real network interfaces.
    has_network_identity: bool = False


def _get_environment_variable(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value else None


def _non_internal_addresses() -> list[str]:
    import ipaddress

    addresses: list[str] = []

    def add(address: str) -> None:
        address = address.split("%", 1)[0]  # drop IPv6 zone id

        try:
            if ipaddress.ip_address(address).is_loopback:
                return  # ignore loopback/internal interfaces
        except ValueError:
            return

        if address not in addresses:  # avoid duplicates
            addresses.append(address)

    try:
        import psutil

        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family in (socket.AF_INET, socket.AF_INET6):
                    add(entry.address)

        return addresses
    except ImportError:
        pass

    # stdlib fallback (less complete than psutil)
    for info in socket.getaddrinfo(socket.gethostname(), None):
        add(info[4][0])

    return addresses


def _get_node_server_identity(name: str) -> ServerIdentity:
    return ServerIdentity(
        name=name,
        hostname=socket.gethostname(),
        ips=_non_internal_addresses(),
        has_network_identity=True,
    )


def _get_generic_server_identity(name: str) -> ServerIdentity:
    return ServerIdentity(name=name, hostname=None, ips=[], has_network_identity=False)


def get_server_identity_sync(
    name: Optional[str] = None,
    runtime: str = "auto",
) -> ServerIdentity:
    """``runtime``: "auto" | "node" (a normal host) | "worker" (no network identity)."""
    resolved_name = name or _get_environment_variable("SERVER_NAME") or DEFAULT_SERVER_NAME

    if runtime == "worker":
        return _get_generic_server_identity(resolved_name)

    try:
        return _get_node_server_identity(resolved_name)
    except Exception:  # noqa: BLE001
        # Never allow server identity discovery to break the API itself.
        return _get_generic_server_identity(resolved_name)


async def get_server_identity(
    name: Optional[str] = None,
    runtime: str = "auto",
) -> ServerIdentity:
    return get_server_identity_sync(name, runtime)
