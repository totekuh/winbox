"""libvirt nwfilter helpers for guest-proof network isolation.

Two filters are defined together:

  * ``winbox-isolate``      — ``chain='root'``, handles L2 (ARP allow, IPv6 drop,
                              default drop), delegates DHCPv4 to libvirt's
                              built-in ``allow-dhcp`` filter, and ``<filterref>``
                              delegates the rest of IPv4 to the sub-filter below.
  * ``winbox-isolate-ipv4`` — ``chain='ipv4'``, allows intra-192.168.122.0/24
                              and drops everything else.

The split is required because libvirt dispatches by EtherType out of the root
chain; ``<ip>`` / ``<udp>`` rules only fire from ``chain='ipv4'``.

The filter is attached to the VM's interface via ``virsh update-device``. With
``--live --persistent`` it's hot-applied; with ``--config`` alone it lands in
the persistent config only (used at setup time against a stopped VM).
"""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from winbox import data as _data
from winbox.vm import virsh_run


FILTER_NAME = "winbox-isolate"
FILTER_XML = "winbox-isolate.xml"
FILTER_IPV4_NAME = "winbox-isolate-ipv4"
FILTER_IPV4_XML = "winbox-isolate-ipv4.xml"


def _filter_path(filename: str) -> Path:
    """Bundled-resource Path. Kept for tests that patch this name."""
    return _data.path(filename)


def _filter_signature(root: ET.Element) -> tuple:
    """Canonical, comparable form of an nwfilter's actual ruleset.

    A raw XML comparison is useless here: libvirt stores a ``<uuid>`` our
    templates don't carry, fills in a computed ``priority`` on the root
    element, and discards comments. So compare only what changes behavior —
    the chain, the referenced sub-filters, and the ordered rules.
    """
    def attrs(el: ET.Element) -> tuple:
        return tuple(sorted(el.attrib.items()))

    rules = []
    for rule in root.findall("rule"):
        children = tuple(
            (child.tag, attrs(child))
            for child in rule
            if isinstance(child.tag, str)  # skip comments
        )
        rules.append((attrs(rule), children))

    refs = tuple(sorted(r.get("filter", "") for r in root.findall("filterref")))
    return (root.get("name"), root.get("chain"), refs, tuple(rules))


def _defined_filter_matches(name: str, desired_xml: str) -> bool:
    """True if libvirt's current definition of ``name`` equals ``desired_xml``."""
    result = virsh_run("nwfilter-dumpxml", name, check=False)
    if result.returncode != 0:
        return False
    try:
        current = _filter_signature(ET.fromstring(result.stdout))
        desired = _filter_signature(ET.fromstring(desired_xml))
    except ET.ParseError:
        return False
    return current == desired


def _define_one(filename: str, name: str, render_kwargs: dict | None = None) -> None:
    """Run ``virsh nwfilter-define`` against a bundled XML.

    If ``render_kwargs`` is given, the XML is treated as a ``str.format``
    template, rendered to a tempfile, and defined from there. This is how
    the IPv4 sub-filter picks up the configured subnet without keeping a
    second copy of ``192.168.122.0`` in ``data/`` that can drift from
    ``Config.vm_subnet``.

    On a UUID conflict (some libvirt builds — notably recent Kali — refuse
    to redefine a same-named filter when the incoming XML has no ``<uuid>``,
    aborting with "filter '...' already exists with uuid ..."), the existing
    filter is undefined and the define retried. Without this, every caller
    on those builds silently keeps the stale ruleset on disk.
    """
    if render_kwargs:
        body = _data.render(filename, **render_kwargs)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8",
        ) as tmp:
            tmp.write(body)
            tmp_path = tmp.name
        cleanup_paths: list[str] = [tmp_path]
        define_arg = tmp_path
    else:
        cleanup_paths = []
        define_arg = str(_data.path(filename))
        body = _data.read(filename)

    try:
        result = virsh_run("nwfilter-define", define_arg, check=False)
        if result.returncode != 0 and "already exists with uuid" in (result.stderr or ""):
            undef = virsh_run("nwfilter-undefine", name, check=False)
            if undef.returncode != 0:
                # A filter attached to a running domain cannot be undefined.
                # That is the normal state whenever the VM is already
                # isolated — and re-isolating an isolated VM should be a
                # no-op, not an error. Only complain if the live ruleset
                # actually differs from what we want to install.
                if _defined_filter_matches(name, body):
                    return
                msg = undef.stderr.strip() or f"virsh exit {undef.returncode}"
                raise RuntimeError(
                    f"nwfilter '{name}' is defined with a different ruleset and "
                    f"cannot be replaced while in use: {msg}\n"
                    f"    Run `winbox net connect` to detach it, then retry."
                )
            result = virsh_run("nwfilter-define", define_arg, check=False)

        if result.returncode != 0:
            msg = result.stderr.strip() or result.stdout.strip() or f"virsh exit {result.returncode}"
            raise RuntimeError(f"Failed to define nwfilter '{name}': {msg}")
    finally:
        for p in cleanup_paths:
            try:
                Path(p).unlink()
            except OSError:
                pass


def ensure_filter_defined(cfg=None) -> None:
    """Define both libvirt nwfilters. Idempotent on every supported libvirt
    backend — ``_define_one`` undefines and retries on the UUID-conflict
    error that Kali's libvirt raises when re-defining a same-named filter
    whose XML lacks a ``<uuid>``.

    Sub-filter is defined first so the root filter's ``<filterref>`` resolves.
    The IPv4 sub-filter is rendered with ``cfg.vm_subnet`` / ``cfg.vm_subnet_mask``
    so the allowed range tracks the configured libvirt network. ``cfg`` is
    optional for backwards compatibility -- when omitted, the package
    defaults (192.168.122.0/24) are used.
    """
    if cfg is None:
        from winbox.config import Config
        cfg = Config()

    _validate_allow_subnet(cfg.vm_subnet, cfg.vm_subnet_mask)
    _define_one(
        FILTER_IPV4_XML, FILTER_IPV4_NAME,
        render_kwargs={"subnet": cfg.vm_subnet, "mask": cfg.vm_subnet_mask},
    )
    _define_one(FILTER_XML, FILTER_NAME)


def _validate_allow_subnet(subnet: str, mask) -> None:
    """Reject a subnet/mask that would make the 'allow intra-LAN' rule permit
    the whole internet.

    The IPv4 sub-filter's only accept rule is scoped to ``subnet/mask``; a
    misconfigured wide value (``0.0.0.0/0``, a public range, a tiny prefix)
    renders a *syntactically valid* filter that nwfilter-define accepts, so
    net_isolate would report "enforced" while actually allowing egress. This is
    the isolation control's whole job, so validate it rather than trust config.
    """
    import ipaddress

    try:
        prefix = int(mask)
        net = ipaddress.IPv4Network(f"{subnet}/{prefix}", strict=False)
    except (ValueError, TypeError) as e:
        raise RuntimeError(
            f"refusing to define nwfilter: invalid isolation subnet "
            f"{subnet!r}/{mask!r}: {e}"
        )
    # A /8 (16M hosts) is already generous for a libvirt NAT network; anything
    # wider, or a non-private range, is almost certainly a misconfiguration that
    # would punch the air-gap wide open.
    if prefix < 8:
        raise RuntimeError(
            f"refusing to define nwfilter: isolation subnet {net} is too wide "
            f"(/{prefix}) — the intra-LAN allow rule would permit ~the whole "
            "internet. Set VM_SUBNET/VM_SUBNET_MASK to the libvirt network."
        )
    if not net.is_private:
        raise RuntimeError(
            f"refusing to define nwfilter: isolation subnet {net} is not a "
            "private range — the allow rule would permit public egress."
        )


def _dumpxml(vm_name: str) -> ET.Element:
    result = virsh_run("dumpxml", vm_name, check=False)
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

        result = virsh_run(
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


def filters_enforcing(cfg=None) -> bool:
    """True iff BOTH winbox nwfilters are defined in libvirt with exactly the
    rulesets we ship.

    A ``<filterref>`` in the domain XML is only a *name*: libvirt drops egress
    only if the named filter is actually defined and carries the right rules. A
    partial ``ensure_filter_defined``, a manual ``nwfilter-undefine``, or a
    permissive redefinition all leave the reference dangling while the guest is
    wide open — so the detonation gate must confirm the definitions, not just
    the reference.
    """
    if cfg is None:
        from winbox.config import Config
        cfg = Config()
    ipv4_body = _data.render(
        FILTER_IPV4_XML, subnet=cfg.vm_subnet, mask=cfg.vm_subnet_mask
    )
    root_body = _data.read(FILTER_XML)
    return (
        _defined_filter_matches(FILTER_IPV4_NAME, ipv4_body)
        and _defined_filter_matches(FILTER_NAME, root_body)
    )


def has_filter(vm_name: str, cfg=None) -> bool:
    """Return True iff the VM is *actually* internet-isolated: the interface
    references 'winbox-isolate' AND both nwfilters are defined and enforcing the
    shipped rulesets.

    This is the safety gate ``winbox detonate`` relies on, so it is deliberately
    strict — a dangling reference to an undefined/permissive filter reads as
    NOT isolated (a false "yes" here runs malware on a live network; a false
    "no" only refuses to detonate). Swallows any XML-parse or virsh error as
    False so callers (status/UI) don't fault on a missing/unparseable domain.
    """
    try:
        domain = _dumpxml(vm_name)
        iface = _find_iface(domain)
    except (RuntimeError, ET.ParseError):
        return False
    if not _matching_filterrefs(iface):
        return False
    return filters_enforcing(cfg)
