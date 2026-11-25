"""IP allow / deny middleware (hono/ip-restriction)."""

from __future__ import annotations

import ipaddress
import inspect
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException

_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4_REGEX = re.compile(rf"^(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}\Z")
_IS_CIDR = re.compile(r"/[^/]*$")


class InvalidIPAddress(Exception):
    """Equivalent of hono's ERR_INVALID_IP_ADDRESS TypeError."""


def distinct_remote_addr(addr: str) -> Optional[str]:
    if _IPV4_REGEX.match(addr):
        return "IPv4"

    if ":" in addr:
        return "IPv6"

    return None


def _to_v4(addr: str) -> int:
    try:
        return int(ipaddress.IPv4Address(addr))
    except ValueError as error:
        raise InvalidIPAddress(f"Invalid IPv4 address: {addr}") from error


def _to_v6(addr: str) -> int:
    try:
        return int(ipaddress.IPv6Address(addr))
    except ValueError as error:
        raise InvalidIPAddress(f"Invalid IPv6 address: {addr}") from error


_MAPPED_PREFIX = 0xFFFF << 32


def _is_v4_mapped(v6: int) -> bool:
    return v6 >> 32 == 0xFFFF


@dataclass
class _Remote:
    addr: str
    type: Optional[str]
    is_ipv4: bool
    binary: Optional[int] = None


def _build_matcher(rules: Sequence[Any]) -> Callable[[_Remote], bool]:
    function_rules: list[Callable] = []
    static_rules: set[str] = set()
    static_v4: set[int] = set()
    static_v6: set[int] = set()
    cidr_rules: list[tuple[bool, int, int]] = []

    def register_static(rule: str) -> None:
        kind = distinct_remote_addr(rule)

        if kind is None:
            raise TypeError(f"Invalid rule: {rule}")

        if kind == "IPv4":
            binary = _to_v4(rule)
            static_rules.add(rule)
            static_rules.add(f"::ffff:{rule}")
            static_v4.add(binary)
            static_v6.add(_MAPPED_PREFIX | binary)
        else:
            binary = _to_v6(rule)
            static_rules.add(str(ipaddress.IPv6Address(binary)))
            static_v6.add(binary)

            if _is_v4_mapped(binary):
                static_v4.add(binary & 0xFFFFFFFF)

    for rule in rules:
        if rule == "*":
            return lambda remote: True

        if callable(rule):
            function_rules.append(rule)
            continue

        if _IS_CIDR.search(rule):
            addr_str, _, prefix_str = rule.partition("/")
            kind = distinct_remote_addr(addr_str)

            if kind is None:
                raise TypeError(f"Invalid rule: {rule}")

            is_v4 = kind == "IPv4"
            maximum = 32 if is_v4 else 128

            if not re.fullmatch(r"[0-9]{1,3}", prefix_str) or int(prefix_str) > maximum:
                raise TypeError(f"Invalid rule: {rule}")

            prefix = int(prefix_str)

            if prefix == maximum:
                register_static(addr_str)
                continue

            addr = _to_v4(addr_str) if is_v4 else _to_v6(addr_str)

            if kind == "IPv6" and _is_v4_mapped(addr) and prefix >= 96:
                is_v4 = True
                addr = addr & 0xFFFFFFFF
                prefix -= 96

            width = 32 if is_v4 else 128
            mask = ((1 << prefix) - 1) << (width - prefix)
            cidr_rules.append((is_v4, addr & mask, mask))
            continue

        register_static(rule)

    def matcher(remote: _Remote) -> bool:
        if remote.addr in static_rules:
            return True

        if remote.binary is None:
            remote.binary = _to_v4(remote.addr) if remote.is_ipv4 else _to_v6(remote.addr)

        binary = remote.binary

        if remote.is_ipv4:
            remote_v4: Optional[int] = binary
        elif _is_v4_mapped(binary):
            remote_v4 = binary & 0xFFFFFFFF
        else:
            remote_v4 = None

        if binary in (static_v4 if remote.is_ipv4 else static_v6):
            return True

        for is_v4, addr, mask in cidr_rules:
            if is_v4:
                if remote_v4 is None:
                    continue

                if (remote_v4 & mask) == addr:
                    return True

                continue

            if remote.is_ipv4:
                continue

            if (binary & mask) == addr:
                return True

        for rule_fn in function_rules:
            if rule_fn({"addr": remote.addr, "type": remote.type}):
                return True

        return False

    return matcher


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def ip_restriction(
    get_ip: Callable[[Context], str],
    deny_list: Sequence[Any] = (),
    allow_list: Sequence[Any] = (),
    on_error: Optional[Callable[[dict, Context], Any]] = None,
) -> Middleware:
    allow_length = len(allow_list)
    deny_matcher = _build_matcher(deny_list)
    allow_matcher = _build_matcher(allow_list)

    def block_error(c: Context) -> HTTPException:
        # hono: new HTTPException(403, { res: c.text('Forbidden', 403) })
        return HTTPException(403, res=c.text("Forbidden", 403))

    async def middleware(c: Context, next):
        addr = get_ip(c)

        if not addr:
            raise block_error(c)

        kind = distinct_remote_addr(addr)
        remote = _Remote(addr=addr, type=kind, is_ipv4=kind == "IPv4")

        try:
            denied = deny_matcher(remote)
            allowed = False if denied else allow_matcher(remote)
        except InvalidIPAddress:
            raise block_error(c)

        if denied:
            if on_error:
                return await _maybe_await(on_error({"addr": addr, "type": kind}, c))

            raise block_error(c)

        if allowed:
            return await next()

        if allow_length == 0:
            return await next()

        if on_error:
            return await _maybe_await(on_error({"addr": addr, "type": kind}, c))

        raise block_error(c)

    return middleware
