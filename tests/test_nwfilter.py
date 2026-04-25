"""Tests for winbox.nwfilter — libvirt nwfilter attach/detach helpers."""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from unittest.mock import patch

import pytest

from winbox import nwfilter


def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


DOMXML_NO_FILTER = """\
<domain type='kvm'>
  <name>winbox</name>
  <devices>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source network='default'/>
      <model type='e1000'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
  </devices>
</domain>
"""

DOMXML_WITH_FILTER = """\
<domain type='kvm'>
  <name>winbox</name>
  <devices>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source network='default'/>
      <model type='e1000'/>
      <filterref filter='winbox-isolate'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
  </devices>
</domain>
"""

DOMXML_WITH_OTHER_FILTER = """\
<domain type='kvm'>
  <name>winbox</name>
  <devices>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source network='default'/>
      <model type='e1000'/>
      <filterref filter='clean-traffic'/>
    </interface>
  </devices>
</domain>
"""

DOMXML_WITH_DUPLICATE_FILTER = """\
<domain type='kvm'>
  <name>winbox</name>
  <devices>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:cc'/>
      <filterref filter='winbox-isolate'/>
      <filterref filter='winbox-isolate'/>
    </interface>
  </devices>
</domain>
"""

DOMXML_NO_IFACE = """\
<domain type='kvm'>
  <name>winbox</name>
  <devices>
  </devices>
</domain>
"""

DOMXML_FALLBACK_IFACE = """\
<domain type='kvm'>
  <name>winbox</name>
  <devices>
    <interface type='bridge'>
      <mac address='52:54:00:dd:ee:ff'/>
      <source bridge='br0'/>
    </interface>
  </devices>
</domain>
"""


# ─── ensure_filter_defined ────────────────────────────────────────────────────


class TestEnsureFilterDefined:
    def test_defines_both_filters_ipv4_first(self):
        """The root filter references the ipv4 sub-filter, so sub-filter must
        be defined first or libvirt could reject the reference. The ipv4
        filter is rendered from a template so the path is a tempfile."""
        calls = []
        rendered_xml = None

        def fake_virsh(*args, check=True):
            nonlocal rendered_xml
            calls.append(args)
            if args[0] == "nwfilter-define" and args[1].endswith(".xml") and "isolate-ipv4" not in args[1]:
                # First call's path is a tempfile holding the rendered ipv4 filter.
                # Second call's path is the bundled root filter.
                pass
            if rendered_xml is None and args[0] == "nwfilter-define":
                try:
                    rendered_xml = open(args[1]).read()
                except OSError:
                    pass
            return _proc(0)

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            nwfilter.ensure_filter_defined()

        assert len(calls) == 2
        assert calls[0][0] == "nwfilter-define"
        assert calls[1][0] == "nwfilter-define"
        # Second call must be the bundled root filter (no rendering).
        assert calls[1][1].endswith("winbox-isolate.xml")
        # First call must be a rendered tempfile with the ipv4 sub-filter
        # body containing the configured subnet.
        assert rendered_xml is not None
        assert "winbox-isolate-ipv4" in rendered_xml
        assert "192.168.122.0" in rendered_xml  # default Config.vm_subnet
        assert "srcipmask='24'" in rendered_xml

    def test_ipv4_filter_picks_up_custom_subnet(self):
        """If Config.vm_subnet/_mask change, the rendered filter changes too."""
        from winbox.config import Config

        cfg = Config(vm_subnet="10.0.5.0", vm_subnet_mask=22)
        rendered_xml = None

        def fake_virsh(*args, check=True):
            nonlocal rendered_xml
            if rendered_xml is None and args[0] == "nwfilter-define":
                try:
                    rendered_xml = open(args[1]).read()
                except OSError:
                    pass
            return _proc(0)

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            nwfilter.ensure_filter_defined(cfg)

        assert rendered_xml is not None
        assert "10.0.5.0" in rendered_xml
        assert "srcipmask='22'" in rendered_xml
        # Default subnet must NOT appear
        assert "192.168.122.0" not in rendered_xml

    def test_failure_raises_with_stderr(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(1, stderr="error: unexpected XML")
            with pytest.raises(RuntimeError, match="unexpected XML"):
                nwfilter.ensure_filter_defined()

    def test_both_filter_files_exist_and_parse(self):
        """Both data files must be present and parseable as XML."""
        root_path = nwfilter._filter_path(nwfilter.FILTER_XML)
        ipv4_path = nwfilter._filter_path(nwfilter.FILTER_IPV4_XML)
        assert root_path.exists()
        assert ipv4_path.exists()

        root = ET.parse(root_path).getroot()
        assert root.tag == "filter"
        assert root.get("name") == "winbox-isolate"
        assert root.get("chain") == "root"
        # Root filter must reference the ipv4 sub-filter.
        ref = root.find("filterref[@filter='winbox-isolate-ipv4']")
        assert ref is not None, "root filter must <filterref> the ipv4 sub-filter"

        ipv4 = ET.parse(ipv4_path).getroot()
        assert ipv4.tag == "filter"
        assert ipv4.get("name") == "winbox-isolate-ipv4"
        assert ipv4.get("chain") == "ipv4"


# ─── attach_filter ────────────────────────────────────────────────────────────


class TestAttachFilter:
    def test_attaches_when_absent(self):
        virsh_calls = []

        def fake_virsh(*args, check=True):
            virsh_calls.append(args)
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_NO_FILTER)
            if args[0] == "update-device":
                return _proc(0)
            raise AssertionError(f"unexpected virsh call: {args}")

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            changed = nwfilter.attach_filter("winbox")

        assert changed is True
        update = next(c for c in virsh_calls if c[0] == "update-device")
        assert "--live" in update
        assert "--persistent" in update
        assert update[1] == "winbox"

    def test_idempotent_when_already_attached(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_WITH_FILTER)
            changed = nwfilter.attach_filter("winbox")

        assert changed is False
        call_names = [c[0][0] for c in mock_virsh.call_args_list]
        assert call_names == ["dumpxml"]

    def test_filterref_inserted_before_address(self):
        """libvirt's RNG expects <address> last inside <interface>; inserting
        <filterref> after it trips several libvirt versions."""
        written_xml = None

        def fake_virsh(*args, check=True):
            nonlocal written_xml
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_NO_FILTER)
            if args[0] == "update-device":
                written_xml = open(args[2]).read()
                return _proc(0)
            raise AssertionError(f"unexpected: {args}")

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            nwfilter.attach_filter("winbox")

        assert written_xml is not None
        root = ET.fromstring(written_xml)
        children = list(root)
        tags = [c.tag for c in children]
        # filterref must appear BEFORE address
        assert "filterref" in tags
        assert "address" in tags
        assert tags.index("filterref") < tags.index("address")
        # MAC preserved
        assert root.find("mac").get("address") == "52:54:00:aa:bb:cc"

    def test_filterref_appended_when_no_address(self):
        """Interface without <address> (e.g. bridge mode) should still get the filterref."""
        written_xml = None

        def fake_virsh(*args, check=True):
            nonlocal written_xml
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_FALLBACK_IFACE)
            if args[0] == "update-device":
                written_xml = open(args[2]).read()
                return _proc(0)
            raise AssertionError(f"unexpected: {args}")

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            changed = nwfilter.attach_filter("winbox")

        assert changed is True
        root = ET.fromstring(written_xml)
        assert root.find("filterref[@filter='winbox-isolate']") is not None

    def test_update_device_failure_surfaces_stderr(self):
        def fake_virsh(*args, check=True):
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_NO_FILTER)
            return _proc(1, stderr="device busy")

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            with pytest.raises(RuntimeError, match="device busy"):
                nwfilter.attach_filter("winbox")

    def test_no_interface_raises(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_NO_IFACE)
            with pytest.raises(RuntimeError, match="no <interface>"):
                nwfilter.attach_filter("winbox")

    def test_live_false_config_true_for_stopped_vm(self):
        """Setup-time path: VM is stopped, libvirt rejects --live."""
        virsh_calls = []

        def fake_virsh(*args, check=True):
            virsh_calls.append(args)
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_NO_FILTER)
            return _proc(0)

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            nwfilter.attach_filter("winbox", live=False, config=True)

        update = next(c for c in virsh_calls if c[0] == "update-device")
        assert "--live" not in update
        assert "--persistent" in update

    def test_both_live_and_config_false_raises(self):
        with pytest.raises(ValueError):
            nwfilter._update_device("winbox", ET.Element("interface"), live=False, config=False)


# ─── detach_filter ────────────────────────────────────────────────────────────


class TestDetachFilter:
    def test_detaches_when_present(self):
        written_xml = None

        def fake_virsh(*args, check=True):
            nonlocal written_xml
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_WITH_FILTER)
            if args[0] == "update-device":
                written_xml = open(args[2]).read()
                return _proc(0)
            raise AssertionError(f"unexpected: {args}")

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            changed = nwfilter.detach_filter("winbox")

        assert changed is True
        root = ET.fromstring(written_xml)
        assert root.find("filterref[@filter='winbox-isolate']") is None

    def test_idempotent_when_absent(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_NO_FILTER)
            changed = nwfilter.detach_filter("winbox")

        assert changed is False
        call_names = [c[0][0] for c in mock_virsh.call_args_list]
        assert call_names == ["dumpxml"]

    def test_preserves_other_filterrefs(self):
        """Only 'winbox-isolate' is removed; other filterrefs stay in place."""
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_WITH_OTHER_FILTER)
            changed = nwfilter.detach_filter("winbox")

        assert changed is False
        call_names = [c[0][0] for c in mock_virsh.call_args_list]
        assert "update-device" not in call_names

    def test_removes_all_matching_when_duplicated(self):
        """If a buggy state left two winbox-isolate filterrefs, remove both."""
        written_xml = None

        def fake_virsh(*args, check=True):
            nonlocal written_xml
            if args[0] == "dumpxml":
                return _proc(0, stdout=DOMXML_WITH_DUPLICATE_FILTER)
            if args[0] == "update-device":
                written_xml = open(args[2]).read()
                return _proc(0)
            raise AssertionError(f"unexpected: {args}")

        with patch("winbox.nwfilter.virsh_run", side_effect=fake_virsh):
            changed = nwfilter.detach_filter("winbox")

        assert changed is True
        root = ET.fromstring(written_xml)
        assert root.findall("filterref[@filter='winbox-isolate']") == []


# ─── has_filter ───────────────────────────────────────────────────────────────


class TestHasFilter:
    def test_true_when_attached(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_WITH_FILTER)
            assert nwfilter.has_filter("winbox") is True

    def test_false_when_absent(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_NO_FILTER)
            assert nwfilter.has_filter("winbox") is False

    def test_false_when_other_filter_attached(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_WITH_OTHER_FILTER)
            assert nwfilter.has_filter("winbox") is False

    def test_false_on_dumpxml_failure(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(1, stderr="domain not found")
            assert nwfilter.has_filter("winbox") is False

    def test_false_when_no_interface(self):
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout=DOMXML_NO_IFACE)
            assert nwfilter.has_filter("winbox") is False

    def test_false_on_parse_error(self):
        """Garbage XML must not crash net_status with ET.ParseError."""
        with patch("winbox.nwfilter.virsh_run") as mock_virsh:
            mock_virsh.return_value = _proc(0, stdout="<not valid xml")
            assert nwfilter.has_filter("winbox") is False
