# ------------------------------------------------------------
# Host validation middleware
#
# Allowlist-based Host / Authority protection.
#
# Host sources:
#
#   Direct request:
#     1. HTTP/1.1 Host header
#     2. HTTP/2 / HTTP/3 :authority pseudo-header
#     3. Request URL host as fallback
#
#   Trusted proxy:
#     1. X-Forwarded-Host
#     2. Host
#     3. :authority
#     4. Request URL host
#
# X-Forwarded-Host is trusted ONLY when the immediate network peer is present
# in TRUSTED_PROXY_IPS or TRUSTED_PROXY_CIDRS.
#
# This is important because clients can freely send:
#
#     X-Forwarded-Host: anything.example
#
# Therefore the header must never be trusted merely because it exists.
#
# The middleware:
#
#   - identifies the immediate network peer
#   - determines whether that peer is a trusted proxy
#   - extracts the effective host
#   - validates its syntax
#   - strips the optional port
#   - normalizes case
#   - checks the hostname against data.ALLOWED_HOSTS
# ------------------------------------------------------------

from __future__ import annotations

import ipaddress
import json
import re
from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.data_provider import data
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int
from app.helpers.utilities import get_client_ip

MAX_HOST_LENGTH = env_int("MAX_HOST_LENGTH", "255")

# A parsed host is {"valid": False} or {"valid": True, "hostname": str, "source": str}
ParsedHost = dict

_INVALID: ParsedHost = {"valid": False}


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower()


def is_valid_port(port: str) -> bool:
    if not re.fullmatch(r"[0-9]+", port):
        return False

    value = int(port)
    return 0 <= value <= 65535


def is_valid_hostname(hostname: str) -> bool:
    if not hostname:
        return False

    if len(hostname) > MAX_HOST_LENGTH:
        return False

    if hostname.startswith(".") or hostname.endswith(".") or ".." in hostname:
        return False

    if not re.fullmatch(r"[A-Za-z0-9.\-]+", hostname):
        return False

    for label in hostname.split("."):
        if not label:
            return False

        if len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def parse_ipv6_host(host: str, source: str) -> ParsedHost:
    closing_bracket = host.find("]")

    if closing_bracket == -1:
        return dict(_INVALID)

    address = host[1:closing_bracket]

    if not address:
        return dict(_INVALID)

    if not re.fullmatch(r"[0-9a-fA-F:]+", address):
        return dict(_INVALID)

    remainder = host[closing_bracket + 1:]

    if remainder == "":
        return {
            "valid": True,
            "hostname": normalize_hostname(host[:closing_bracket + 1]),
            "source": source,
        }

    if not remainder.startswith(":"):
        return dict(_INVALID)

    if not is_valid_port(remainder[1:]):
        return dict(_INVALID)

    return {
        "valid": True,
        "hostname": normalize_hostname(host[:closing_bracket + 1]),
        "source": source,
    }


def parse_host_value(value: str, source: str) -> ParsedHost:
    host = value.strip()

    if not host:
        return dict(_INVALID)

    if re.search(r"[\s\x00-\x1f\x7f]", host):
        return dict(_INVALID)

    if len(host) > MAX_HOST_LENGTH + 6:
        return dict(_INVALID)

    # IPv6 literal
    if host.startswith("["):
        return parse_ipv6_host(host, source)

    # Normal hostname / IPv4
    first_colon = host.find(":")
    last_colon = host.rfind(":")

    if first_colon != -1:
        if first_colon != last_colon:
            return dict(_INVALID)

        hostname = host[:first_colon]
        port = host[first_colon + 1:]

        if not is_valid_port(port):
            return dict(_INVALID)

        if not is_valid_hostname(hostname):
            return dict(_INVALID)

        return {"valid": True, "hostname": normalize_hostname(hostname), "source": source}

    if not is_valid_hostname(host):
        return dict(_INVALID)

    return {"valid": True, "hostname": normalize_hostname(host), "source": source}


# ------------------------------------------------------------
# IPv4 / IPv6 CIDR matching (used for the trusted-proxy check)
# ------------------------------------------------------------


def ipv4_to_number(ip: str) -> Optional[int]:
    parts = ip.split(".")

    if len(parts) != 4:
        return None

    result = 0

    for part in parts:
        if not re.fullmatch(r"[0-9]+", part):
            return None

        value = int(part)

        if value < 0 or value > 255:
            return None

        result = result * 256 + value

    return result


def is_ipv4_in_cidr(ip: str, cidr: str) -> bool:
    network, sep, prefix_string = cidr.partition("/")

    if not sep:
        return False

    ip_number = ipv4_to_number(ip)
    network_number = ipv4_to_number(network)

    if ip_number is None or network_number is None:
        return False

    if not re.fullmatch(r"[0-9]+", prefix_string):
        return False

    prefix = int(prefix_string)

    if prefix < 0 or prefix > 32:
        return False

    if prefix == 0:
        return True

    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

    return (ip_number & mask) == (network_number & mask)


def _ipv6_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv6Address(ip))
    except ValueError:
        return None


def is_ipv6_in_cidr(ip: str, cidr: str) -> bool:
    slash = cidr.rfind("/")

    if slash == -1:
        return False

    network = cidr[:slash]
    prefix_string = cidr[slash + 1:]

    if not re.fullmatch(r"[0-9]+", prefix_string):
        return False

    prefix = int(prefix_string)

    if prefix < 0 or prefix > 128:
        return False

    ip_number = _ipv6_to_int(ip)
    network_number = _ipv6_to_int(network)

    if ip_number is None or network_number is None:
        return False

    if prefix == 0:
        return True

    shift = 128 - prefix

    return (ip_number >> shift) == (network_number >> shift)


def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    if ":" in ip or ":" in cidr:
        return is_ipv6_in_cidr(ip, cidr)

    return is_ipv4_in_cidr(ip, cidr)


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def is_trusted_proxy(c: Context) -> bool:
    """
    Checks the peer address against TRUSTED_PROXY_IPS / TRUSTED_PROXY_CIDRS.

    The two settings are comma-separated strings that are re-assigned on hot
    reload, so they are read (and split) on every call.
    """
    try:
        remote_ip = get_client_ip(c) or None
    except Exception:  # noqa: BLE001
        return False

    if not remote_ip:
        return False

    normalized_ip = remote_ip.strip().lower()

    # Exact trusted IPs
    for trusted_ip in _csv(data.TRUSTED_PROXY_IPS):
        if trusted_ip.lower() == normalized_ip:
            return True

    # Trusted CIDRs
    for trusted_cidr in _csv(data.TRUSTED_PROXY_CIDRS):
        if is_ip_in_cidr(normalized_ip, trusted_cidr.lower()):
            return True

    return False


# ------------------------------------------------------------
# Determines the effective request authority.
#
# Trusted proxy:  X-Forwarded-Host, Host, :authority, URL.host
# Direct request: Host, :authority, URL.host
#
# X-Forwarded-Host is NEVER trusted from an untrusted peer.
# ------------------------------------------------------------


def get_host_from_request(c: Context, trusted_proxy: bool) -> ParsedHost:
    if trusted_proxy:
        forwarded_host = c.req.header("X-Forwarded-Host")

        if forwarded_host is not None:
            # X-Forwarded-Host can theoretically contain a comma-separated
            # chain.  The first value is the original client-facing host in the
            # conventional proxy chain model.
            first_forwarded_host = forwarded_host.split(",")[0].strip()

            if first_forwarded_host:
                parsed = parse_host_value(first_forwarded_host, "forwarded-host")

                if parsed["valid"]:
                    return parsed

                # Explicitly supplied but malformed forwarded host must not
                # silently fall through to a potentially attacker-controlled
                # backend Host.
                return dict(_INVALID)

            return dict(_INVALID)

    host_header = c.req.header("Host")

    if host_header is not None:
        return parse_host_value(host_header, "host")

    # HTTP/2 / HTTP/3 :authority
    authority_header = c.req.header(":authority")

    if authority_header is not None:
        return parse_host_value(authority_header, "authority")

    # URL fallback
    url = c.req.url
    start = url.index("//") + 2
    end = url.index("/", start)
    host = url[start:end]

    if host:
        return parse_host_value(host, "url")

    return dict(_INVALID)


def normalize_allowlist(values) -> set[str]:
    allowlist: set[str] = set()

    for value in values:
        parsed = parse_host_value(value, "host")

        if not parsed["valid"]:
            continue

        allowlist.add(parsed["hostname"])

    return allowlist


# ------------------------------------------------------------
# A request is accepted only when its normalized hostname exists in
# data.ALLOWED_HOSTS.  X-Forwarded-Host is accepted only from a trusted proxy.
# ------------------------------------------------------------


def host_validation() -> Middleware:
    async def middleware(c: Context, next):
        # Determine whether the immediate peer is trusted.
        trusted_proxy = is_trusted_proxy(c)

        # Extract effective Host.
        parsed = get_host_from_request(c, trusted_proxy)

        # No usable authority.
        if not parsed["valid"]:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Invalid host {json.dumps(parsed, separators=(',', ':'))}",
                    "code": "HOST_VALIDATION_ERR",
                    "status": 400,
                },
            )

            return c.json({"error": "Invalid request"}, 400)

        # Normalize configured allowlist.
        allowed_hosts = normalize_allowlist(data.ALLOWED_HOSTS)

        # Host must be explicitly allowed.
        if parsed["hostname"] not in allowed_hosts:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Invalid host {json.dumps(parsed, separators=(',', ':'))}",
                    "code": "HOST_VALIDATION_ERR",
                    "status": 403,
                },
            )

            return c.json({"error": "Invalid request"}, 403)

        return await next()

    return middleware
