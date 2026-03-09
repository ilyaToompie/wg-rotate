import re
import secrets


def sanitize_client_name(name: str) -> str:
    """
    Ensures WireGuard peer names are safe.
    """
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return name[:15] if len(name) > 15 else name


def bracket_if_ipv6(ip: str) -> str:
    """
    Wrap IPv6 in [] when used in endpoints.
    """
    if ":" in ip and not (ip.startswith("[") and ip.endswith("]")):
        return f"[{ip}]"
    return ip


def next_client_ipv4(server_ipv4: str, used: set) -> str:
    """
    Allocates random IPv4 inside server /24 network.
    """
    base = ".".join(server_ipv4.split(".")[:3])

    for _ in range(1000):
        dot = secrets.randbelow(253) + 2
        candidate = f"{base}.{dot}"

        if candidate not in used:
            used.add(candidate)
            return candidate

    raise RuntimeError("Unable to allocate IPv4 client address")


def client_ipv6_from(server_ipv6: str, last_octet: int) -> str:
    """
    Derives client IPv6 from server subnet.
    """
    base = server_ipv6.split("::", 1)[0]
    return f"{base}::{last_octet}"