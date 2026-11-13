"""Push-notification URL guard (P1-07, F-04).

A2A clients can ask for results to be POSTed to a URL of their choosing. Those
results contain review output for PRs read with the server's GITHUB_TOKEN, so the
URL must be on the PUSH_URL_ALLOWED_HOSTS allowlist. As defence in depth against
SSRF, it must also be https and every address the host resolves to must be public
(no private, loopback, link-local, reserved, multicast or unspecified ranges).

Known limit: the check resolves the name, then httpx resolves it again when it
connects, so a DNS rebinding host could answer differently the second time. The
allowlist is the primary control; the check runs again right before each push to
narrow the window.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.config import settings
from app.core.errors import ClientInputError


class PushUrlRejected(ClientInputError):
    """The push URL is not allowed. The message is safe to show the caller."""


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) is judged by its IPv4 form
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def _resolve(host: str, port: int) -> list[str]:
    """All addresses for host. Kept separate so tests can avoid the network."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


async def validate_push_url(url: object) -> str:
    """Return the URL if it may receive a push, else raise PushUrlRejected."""
    if not isinstance(url, str) or not url:
        raise PushUrlRejected("pushNotificationConfig.url is required")

    allowed = settings.push_url_allowed_hosts
    if not allowed:
        raise PushUrlRejected("Push notifications are disabled on this server")

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port or 443
    except ValueError as e:
        raise PushUrlRejected("pushNotificationConfig.url is not a valid URL") from e

    if parts.scheme.lower() != "https":
        raise PushUrlRejected("pushNotificationConfig.url must use https")
    if not host or host not in allowed:
        raise PushUrlRejected("pushNotificationConfig.url host is not on the allowlist")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            addresses = await _resolve(host, port)
        except OSError as e:
            raise PushUrlRejected("pushNotificationConfig.url host does not resolve") from e

    if not addresses:
        raise PushUrlRejected("pushNotificationConfig.url host does not resolve")
    for address in addresses:
        # Strip an IPv6 zone id (fe80::1%eth0) before parsing
        if not _is_public(ipaddress.ip_address(address.split("%", 1)[0])):
            raise PushUrlRejected("pushNotificationConfig.url resolves to a non-public address")
    return url
