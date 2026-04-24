"""libvirt nwfilter helpers for guest-proof network isolation.

Two filters are defined together:

  * ``winbox-isolate``      — ``chain='root'``, handles L2 (ARP allow, IPv6 drop,
                              default drop) and ``<filterref>`` delegates IPv4
                              to the sub-filter below.
  * ``winbox-isolate-ipv4`` — ``chain='ipv4'``, allows DHCPv4 + intra-192.168.122.0/24
                              and drops everything else.

The split is required because libvirt dispatches by EtherType out of the root
chain; ``<ip>`` / ``<udp>`` rules only fire from ``chain='ipv4'``.

The filter is attached to the VM's interface via ``virsh update-device``. With
``--live --persistent`` it's hot-applied; with ``--config`` alone it lands in
the persistent config only (used at setup time against a stopped VM).
"""

from __future__ import annotations

import importlib.resources
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from winbox.vm.lifecycle import _virsh


FILTER_NAME = "winbox-isolate"
FILTER_XML = "winbox-isolate.xml"
FILTER_IPV4_NAME = "winbox-isolate-ipv4"
FILTER_IPV4_XML = "winbox-isolate-ipv4.xml"


def _filter_path(filename: str) -> Path:
    return Path(str(importlib.resources.files("winbox.data").joinpath(filename)))


def _define_one(filename: str, name: str) -> None:
    path = _filter_path(filename)
    result = _virsh("nwfilter-define", str(path), check=False)
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip() or f"virsh exit {result.returncode}"
        raise RuntimeError(f"Failed to define nwfilter '{name}': {msg}")


def ensure_filter_defined() -> None:
    """Define both libvirt nwfilters. Idempotent (libvirt overwrites on re-define).

    Sub-filter is defined first so the root filter's ``<filterref>`` resolves.
    """
    _define_one(FILTER_IPV4_XML, FILTER_IPV4_NAME)
    _define_one(FILTER_XML, FILTER_NAME)


def _dumpxml(vm_name: str) -> ET.Element:
    result = _virsh("dumpxml", vm_name, check=False)
    if result.returncode != 0:
        msg = result.stderr.strip() or f"virsh exit {result.returncode}"
        raise RuntimeError(f"virsh dumpxml {vm_name} failed: {msg}")
    return ET.fromstring(result.stdout)


def _find_iface(domain: ET.Element) -> ET.Element:
    """Locate the VM's primary network interface element."""
    devices = domain.find("devices")
    if devices is None:
        raise RuntimeError("domain XML has no <devices> block")
    iface = devices.find("interface[@type='network']")
    if iface is None:
        iface = devices.find("interface")
    if iface is None:
        raise RuntimeError("domain has no <interface> to attach the filter to")
    return iface


def _matching_filterrefs(iface: ET.Element) -> list[ET.Element]:
    return [r for r in iface.findall("filterref") if r.get("filter") == FILTER_NAME]


def _insert_filterref(iface: ET.Element) -> None:
    """Add <filterref filter='winbox-isolate'/> before any <address> child.

    libvirt's RNG for <interface> expects <address> last. Appending the
    filterref after <address> trips several libvirt versions into silently
    dropping it on domain re-parse.
    """
    ref = ET.Element("filterref", {"filter": FILTER_NAME})
    children = list(iface)
    for idx, child in enumerate(children):
        if child.tag == "address":
            iface.insert(idx, ref)
            return
    iface.append(ref)


def _update_device(
    vm_name: str,
    iface: ET.Element,
    *,
    live: bool = True,
    config: bool = True,
) -> None:
    if not live and not config:
        raise ValueError("at least one of live/config must be True")

    flags: list[str] = []
    if live:
        flags.append("--live")
    if config:
        flags.append("--persistent")

    tmp_path: str | None = None
    try:
        xml_bytes = ET.tostring(iface, encoding="utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".xml", delete=False,
        ) as tmp:
            tmp.write(xml_bytes)
            tmp_path = tmp.name

        result = _virsh(
            "update-device", vm_name, tmp_path, *flags,
            check=False,
        )
        if result.returncode != 0:
            msg = result.stderr.strip() or result.stdout.strip() or f"virsh exit {result.returncode}"
            raise RuntimeError(f"virsh update-device failed: {msg}")
    finally:
        if tmp_path is not None:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass


def attach_filter(
    vm_name: str,
    *,
    live: bool = True,
    config: bool = True,
) -> bool:
    """Attach 'winbox-isolate' to the VM's interface.

    Returns True if state changed, False if already attached.

    ``live=False, config=True`` is the setup-time path (VM is stopped;
    libvirt rejects ``--live`` against a shut-off domain).
    """
    domain = _dumpxml(vm_name)
    iface = _find_iface(domain)
    if _matching_filterrefs(iface):
        return False
    _insert_filterref(iface)
    _update_device(vm_name, iface, live=live, config=config)
    return True


def detach_filter(
    vm_name: str,
    *,
    live: bool = True,
    config: bool = True,
) -> bool:
    """Remove ALL 'winbox-isolate' filterrefs from the VM's interface
    (other filterrefs, e.g. 'clean-traffic', are preserved).

    Returns True if state changed, False if no such filterref was present.
    """
    domain = _dumpxml(vm_name)
    iface = _find_iface(domain)
    refs = _matching_filterrefs(iface)
    if not refs:
        return False
    for ref in refs:
        iface.remove(ref)
    _update_device(vm_name, iface, live=live, config=config)
    return True


def has_filter(vm_name: str) -> bool:
    """Return True iff the VM's interface has 'winbox-isolate' attached.

    Swallows any XML-parse or virsh error as False so callers (status/UI)
    don't fault on a missing/unparseable domain.
    """
    try:
        domain = _dumpxml(vm_name)
        iface = _find_iface(domain)
    except (RuntimeError, ET.ParseError):
        return False
    return bool(_matching_filterrefs(iface))
