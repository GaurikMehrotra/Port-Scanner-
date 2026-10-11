"""An original, small lab port preset; not an Nmap database."""

COMMON = (22, 53, 80, 81, 82, 6379, 8000)


def parse_ports(spec: str, max_ports: int) -> list[int]:
    if spec == "common":
        if len(COMMON) > max_ports:
            raise ValueError("Preset exceeds port cap")
        return list(COMMON)
    ports: set[int] = set()
    for token in spec.split(","):
        if not token or not token.isascii():
            raise ValueError("Invalid port token")
        bounds = token.split("-")
        if len(bounds) not in (1, 2) or not all(x.isdecimal() for x in bounds):
            raise ValueError("Ports must be decimal integers or ascending ranges")
        low, high = int(bounds[0]), int(bounds[-1])
        if low < 1 or high > 65535 or low > high or high - low + 1 > max_ports:
            raise ValueError("Invalid range or port cap exceeded")
        ports.update(range(low, high + 1))
        if len(ports) > max_ports:
            raise ValueError("Port count exceeds cap")
    return sorted(ports)
