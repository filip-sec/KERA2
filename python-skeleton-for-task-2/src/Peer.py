import ipaddress
import re

"""
host
host_formated == host for hostname and ipv4,
              == bracket wrapped ipv6 addres
"""
class Peer:
    def __init__(self, host_str, port:int):
        self.port = port
        self.isBootstrap = False # indicates if this is one of your hardcoded bootstrap nodes
        try:
            ip = None
            ip = ipaddress.ip_address(host_str)

            self.host = ip.compressed

            # ipv4
            self.host_formated = self.host


        # not an ipv, dns name
        except ValueError:
            # Validate hostname
            if not self._is_valid_hostname(host_str):
                raise ValueError(f"Invalid hostname: {host_str}")
            self.host = host_str
            self.host_formated = host_str

        def _is_valid_hostname(self, hostname: str) -> bool:
            if len(hostname) > 255:
                return False
            if hostname[-1] == ".":
                hostname = hostname[:-1]  # strip exactly one dot from the right, if present
            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
            return all(allowed.match(x) for x in hostname.split("."))

    def tagBootstrap(self):
        self.isBootstrap = True

    def __str__(self) -> str:
        return f"{self.host_formated}:{self.port}"

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Peer) and self.host == o.host \
            and self.port == o.port

    def __hash__(self) -> int:
        return (self.port, self.host).__hash__()

    def __repr__(self) -> str:
        return f"Peer: {self}"
