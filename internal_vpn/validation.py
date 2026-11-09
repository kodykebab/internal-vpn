import base64
import ipaddress


def public_key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("Expected a WireGuard public key")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
        raise ValueError("Invalid WireGuard public key")
    return value


def subnet(value):
    network = ipaddress.IPv4Network(value)
    if not network.subnet_of(ipaddress.IPv4Network("100.64.0.0/10")) or network.prefixlen > 29:
        raise ValueError("Choose a subnet inside 100.64.0.0/10 with room for peers")
    return network


def endpoint(value):
    if not isinstance(value, str):
        raise ValueError("Expected an IPv4 endpoint and UDP port")
    host, port = value.split(":")
    address = ipaddress.IPv4Address(host)
    if address.is_unspecified or address.is_multicast or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid endpoint")
    return f"{address}:{int(port)}"
