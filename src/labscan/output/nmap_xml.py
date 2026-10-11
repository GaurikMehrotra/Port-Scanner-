"""Nmap-style subset; labscan metadata prevents masquerading as Nmap."""

from xml.etree.ElementTree import Element, SubElement, tostring

from labscan.models import Report


def render(report: Report) -> str:
    root = Element(
        "nmaprun", scanner="labscan", version=report.scanner_version, startstr=report.started
    )
    root.set("banners", str(report.banners))
    root.set("discovery", report.discovery)
    SubElement(
        root,
        "scaninfo",
        type=report.scan_type,
        protocol="udp" if report.scan_type == "udp" else "tcp",
    )
    hosts: dict[str, Element] = {}
    for result in report.results:
        if result.host not in hosts:
            host = SubElement(root, "host")
            SubElement(host, "address", addr=result.host, addrtype="ipv4")
            hosts[result.host] = SubElement(host, "ports")
        port = SubElement(
            hosts[result.host], "port", protocol=result.protocol, portid=str(result.port)
        )
        SubElement(port, "state", state=result.state, reason=result.reason)
        service = {
            k: str(v)
            for k, v in {
                "name": result.service,
                "product": result.product,
                "version": result.version,
            }.items()
            if v is not None
        }
        if service:
            SubElement(port, "service", service)
    SubElement(root, "labscan-settings").text = report.settings.model_dump_json()
    SubElement(root, "runstats", ended=report.ended, duration=str(report.duration))
    return tostring(root, encoding="unicode")
