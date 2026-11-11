"""Libvirt domain XML manipulation for CET shadow-stack control."""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from winbox.config import Config
from winbox.vm import virsh_run


class CetSafetyError(RuntimeError):
    pass


def _inactive_domain(cfg: Config) -> ET.Element:
    result = virsh_run("dumpxml", cfg.vm_name, "--inactive", check=False)
    if result.returncode != 0:
        msg = result.stderr.strip() or result.stdout.strip() or result.returncode
        raise CetSafetyError(f"cannot read inactive domain XML: {msg}")
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise CetSafetyError(f"inactive domain XML is invalid: {exc}") from exc


def _insert_cpu(domain: ET.Element, cpu: ET.Element) -> None:
    """Insert a CPU node before clock/devices to satisfy libvirt ordering."""
    children = list(domain)
    for index, child in enumerate(children):
        if child.tag in {"clock", "on_poweroff", "devices"}:
            domain.insert(index, cpu)
            return
    domain.append(cpu)


def _stage_cet_ss_disable(cfg: Config) -> tuple[str | None, str | None]:
    """Return original CPU XML and updated domain XML, without mutating it."""
    domain = _inactive_domain(cfg)
    cpu = domain.find("cpu")
    original = ET.tostring(cpu, encoding="unicode") if cpu is not None else None
    if cpu is None:
        cpu = ET.Element("cpu", {"mode": "host-passthrough", "check": "none"})
        _insert_cpu(domain, cpu)
    feature = cpu.find("feature[@name='cet-ss']")
    if feature is not None and feature.get("policy") == "disable":
        return original, None
    if feature is None:
        feature = ET.SubElement(cpu, "feature", {"name": "cet-ss"})
    feature.set("policy", "disable")
    return original, ET.tostring(domain, encoding="unicode")


def _define_domain(cfg: Config, domain_xml: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8",
        ) as handle:
            handle.write(domain_xml)
            temporary = handle.name
        result = virsh_run("define", temporary, check=False)
        if result.returncode != 0:
            msg = result.stderr.strip() or result.stdout.strip() or result.returncode
            raise CetSafetyError(f"cannot persist cet-ss CPU override: {msg}")
    finally:
        if temporary is not None:
            try:
                Path(temporary).unlink()
            except OSError:
                pass


def _restore_domain_cpu(cfg: Config, original_xml: str | None) -> None:
    domain = _inactive_domain(cfg)
    current = domain.find("cpu")
    if current is not None:
        index = list(domain).index(current)
        domain.remove(current)
    else:
        index = -1
    if original_xml is not None:
        try:
            original = ET.fromstring(original_xml)
        except ET.ParseError as exc:
            raise CetSafetyError(f"saved domain CPU XML is invalid: {exc}") from exc
        if original.tag != "cpu":
            raise CetSafetyError("saved domain CPU XML is not a <cpu> element")
        if index >= 0:
            domain.insert(index, original)
        else:
            _insert_cpu(domain, original)
    _define_domain(cfg, ET.tostring(domain, encoding="unicode"))
