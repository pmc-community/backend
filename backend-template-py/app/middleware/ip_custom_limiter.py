from app.core.context import Context
from app.data_provider import data
from app.helpers.err_handler import ip_restriction_error
from app.helpers.utilities import get_client_ip, ip_matches_rule


async def ip_custom_limiter(c: Context, next):
    remote = get_client_ip(c)

    denied = any(ip_matches_rule(remote, rule) for rule in data.GLOBAL_IP_DENY)

    if denied:
        return ip_restriction_error({"addr": remote}, c)

    return await next()
