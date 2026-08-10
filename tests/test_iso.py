"""Tests for winbox.iso — URL resolution and pure helpers."""

import pytest

from winbox.osprofile import OS_PROFILES
from winbox.setup.iso import (
    EVAL_REDIRECT_URL,
    ISO_FILENAME,
    resolve_download_url,
)


class TestIsoConstants:
    def test_redirect_url_is_microsoft(self):
        assert "go.microsoft.com" in EVAL_REDIRECT_URL

    def test_redirect_url_has_locale(self):
        assert "en-us" in EVAL_REDIRECT_URL

    def test_iso_filename(self):
        assert ISO_FILENAME.endswith(".iso")
        assert "EVAL" in ISO_FILENAME

    def test_module_constants_mirror_server_profile(self):
        srv = OS_PROFILES["server2022"]
        assert EVAL_REDIRECT_URL == srv.iso_url
        assert ISO_FILENAME == srv.iso_filename


class TestOsProfileIsoValues:
    @pytest.mark.parametrize("key", ["server2022", "win11"])
    def test_profile_iso_url_and_filename(self, key):
        p = OS_PROFILES[key]
        assert "go.microsoft.com/fwlink" in p.iso_url
        assert p.iso_filename.endswith(".iso")
        assert p.iso_min_size >= 4_000_000_000

    def test_win11_distinct_from_server(self):
        srv, w11 = OS_PROFILES["server2022"], OS_PROFILES["win11"]
        assert w11.iso_url != srv.iso_url
        assert w11.iso_filename != srv.iso_filename


class TestResolveDownloadUrl:
    @pytest.mark.integration
    def test_resolves_to_microsoft_cdn(self):
        """Verify the redirect chain lands on Microsoft's CDN."""
        url = resolve_download_url()
        assert "microsoft.com" in url
        assert url.endswith(".iso")


# ─── download_iso ───────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal urlopen response for the download path."""

    def __init__(self, chunks, *, status=200, content_length=None):
        self._chunks = list(chunks)
        self.status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.fp = None

    def read(self, _n):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        pass


class _IsoHarness:
    """Wires download_iso up to controllable network + a tmp iso dir."""

    # Real floors are multi-GB; allocating buffers that size in a unit test
    # would be absurd, so shrink the floor and keep every other profile value.
    FLOOR = 4096

    def __init__(self, monkeypatch, tmp_path, os_key="server2022"):
        import dataclasses

        from winbox.config import Config
        from winbox.osprofile import OS_PROFILES
        from winbox.setup import iso as iso_mod

        monkeypatch.setitem(
            OS_PROFILES, os_key,
            dataclasses.replace(OS_PROFILES[os_key], iso_min_size=self.FLOOR),
        )

        self.mod = iso_mod
        self.cfg = Config(winbox_dir=tmp_path / ".winbox")
        self.cfg.vm_os = os_key
        self.monkeypatch = monkeypatch
        self.resolved_from: list[str] = []
        self.dest = self.cfg.iso_dir / self.cfg.profile.iso_filename

        monkeypatch.setattr(
            iso_mod, "resolve_download_url",
            lambda redirect_url=None: (
                self.resolved_from.append(redirect_url) or "https://cdn/eval.iso"
            ),
        )

    def set_remote_size(self, size):
        self.monkeypatch.setattr(self.mod, "get_remote_size", lambda url: size)

    def set_body(self, chunks, *, status=200, content_length=None):
        resp = _FakeResp(chunks, status=status, content_length=content_length)
        self.monkeypatch.setattr(
            self.mod.urllib.request, "urlopen", lambda req, timeout=None: resp
        )
        self.last_request_holder = resp
        return resp

    def write_local(self, nbytes):
        self.cfg.iso_dir.mkdir(parents=True, exist_ok=True)
        self.dest.write_bytes(b"\x00" * nbytes)


class TestDownloadIsoCacheDecisions:
    """The cached-ISO branch decides whether a local file is usable. Getting
    it wrong either re-downloads several GB or, worse, hands a truncated
    image to virt-install, which only fails much later inside WinPE."""

    def test_exact_size_match_is_reused(self, monkeypatch, tmp_path):
        h = _IsoHarness(monkeypatch, tmp_path)
        h.write_local(1000)
        h.set_remote_size(1000)

        assert h.mod.download_iso(h.cfg) == h.dest

    def test_local_larger_than_remote_is_refused(self, monkeypatch, tmp_path):
        h = _IsoHarness(monkeypatch, tmp_path)
        h.write_local(2000)
        h.set_remote_size(1000)

        with pytest.raises(RuntimeError, match="larger than remote"):
            h.mod.download_iso(h.cfg)

    def test_unverifiable_size_above_the_profile_floor_is_reused(
        self, monkeypatch, tmp_path
    ):
        h = _IsoHarness(monkeypatch, tmp_path)
        h.write_local(h.cfg.profile.iso_min_size)
        h.set_remote_size(None)

        assert h.mod.download_iso(h.cfg) == h.dest

    def test_unverifiable_size_below_the_profile_floor_is_not_reused(
        self, monkeypatch, tmp_path
    ):
        """A partial download parked above the old flat 1 GB leniency used to
        be accepted here."""
        h = _IsoHarness(monkeypatch, tmp_path)
        h.write_local(h.cfg.profile.iso_min_size - 1)
        h.set_remote_size(None)
        h.set_body([b"x" * 10])

        with pytest.raises(RuntimeError, match="truncated"):
            h.mod.download_iso(h.cfg)

    def test_force_skips_the_cache_check_entirely(self, monkeypatch, tmp_path):
        h = _IsoHarness(monkeypatch, tmp_path)
        h.write_local(h.cfg.profile.iso_min_size)
        h.set_remote_size(None)
        h.set_body([b"x" * 10])

        with pytest.raises(RuntimeError, match="truncated"):
            h.mod.download_iso(h.cfg, force=True)

    def test_force_restarts_instead_of_resuming_a_known_size_partial(
        self, monkeypatch, tmp_path
    ):
        """With a known remote size, force must overwrite the partial rather
        than sending a Range header and appending onto a corrupt prefix."""
        h = _IsoHarness(monkeypatch, tmp_path)
        floor = h.cfg.profile.iso_min_size
        h.write_local(100)
        h.set_remote_size(floor)

        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["range"] = req.get_header("Range")
            return _FakeResp([b"x" * floor], status=200, content_length=floor)

        monkeypatch.setattr(h.mod.urllib.request, "urlopen", fake_urlopen)

        h.mod.download_iso(h.cfg, force=True)

        assert seen["range"] is None
        assert h.dest.stat().st_size == floor


class TestDownloadIsoIsProfileDriven:
    @pytest.mark.parametrize("os_key", ["server2022", "win11"])
    def test_downloads_to_the_profile_filename(self, monkeypatch, tmp_path, os_key):
        h = _IsoHarness(monkeypatch, tmp_path, os_key=os_key)
        h.set_remote_size(None)
        floor = h.cfg.profile.iso_min_size
        h.set_body([b"x" * floor], content_length=floor)

        result = h.mod.download_iso(h.cfg)

        assert result.name == h.cfg.profile.iso_filename
        assert result.stat().st_size == floor

    @pytest.mark.parametrize("os_key", ["server2022", "win11"])
    def test_resolves_the_profile_url(self, monkeypatch, tmp_path, os_key):
        """A Win11 build must never fetch the Server ISO."""
        h = _IsoHarness(monkeypatch, tmp_path, os_key=os_key)
        h.set_remote_size(None)
        floor = h.cfg.profile.iso_min_size
        h.set_body([b"x" * floor], content_length=floor)

        h.mod.download_iso(h.cfg)

        assert h.resolved_from == [h.cfg.profile.iso_url]

    @pytest.mark.parametrize("os_key", ["server2022", "win11"])
    def test_truncation_floor_is_the_profiles(self, monkeypatch, tmp_path, os_key):
        h = _IsoHarness(monkeypatch, tmp_path, os_key=os_key)
        h.set_remote_size(None)
        short = h.cfg.profile.iso_min_size - 1
        h.set_body([b"x" * short], content_length=short)

        with pytest.raises(RuntimeError, match="truncated"):
            h.mod.download_iso(h.cfg)

    def test_the_two_profiles_use_different_files_and_urls(self):
        from winbox.osprofile import OS_PROFILES

        server, win11 = OS_PROFILES["server2022"], OS_PROFILES["win11"]
        assert server.iso_filename != win11.iso_filename
        assert server.iso_url != win11.iso_url
        assert server.iso_min_size != win11.iso_min_size


class TestDownloadIsoResume:
    def test_partial_download_sends_a_range_header(self, monkeypatch, tmp_path):
        h = _IsoHarness(monkeypatch, tmp_path)
        floor = h.cfg.profile.iso_min_size
        h.write_local(100)
        h.set_remote_size(floor)

        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["range"] = req.get_header("Range")
            return _FakeResp([b"x" * (floor - 100)], status=206,
                             content_length=floor - 100)

        monkeypatch.setattr(h.mod.urllib.request, "urlopen", fake_urlopen)

        h.mod.download_iso(h.cfg)

        assert seen["range"] == "bytes=100-"
        assert h.dest.stat().st_size == floor

    def test_server_ignoring_range_restarts_instead_of_doubling(
        self, monkeypatch, tmp_path
    ):
        """A 200 in reply to a Range request means the whole file is coming;
        appending it to the partial would produce a corrupt image."""
        h = _IsoHarness(monkeypatch, tmp_path)
        floor = h.cfg.profile.iso_min_size
        h.write_local(100)
        h.set_remote_size(floor)
        monkeypatch.setattr(
            h.mod.urllib.request, "urlopen",
            lambda req, timeout=None: _FakeResp(
                [b"x" * floor], status=200, content_length=floor
            ),
        )

        h.mod.download_iso(h.cfg)

        assert h.dest.stat().st_size == floor


class TestGetRemoteSize:
    def test_returns_content_length(self, monkeypatch):
        from winbox.setup import iso as iso_mod

        monkeypatch.setattr(
            iso_mod.urllib.request, "urlopen",
            lambda req, timeout=None: _FakeResp([], content_length=4321),
        )
        assert iso_mod.get_remote_size("https://x") == 4321

    def test_missing_header_returns_none(self, monkeypatch):
        from winbox.setup import iso as iso_mod

        monkeypatch.setattr(
            iso_mod.urllib.request, "urlopen",
            lambda req, timeout=None: _FakeResp([]),
        )
        assert iso_mod.get_remote_size("https://x") is None

    def test_network_error_returns_none(self, monkeypatch):
        import urllib.error

        from winbox.setup import iso as iso_mod

        def boom(req, timeout=None):
            raise urllib.error.URLError("down")

        monkeypatch.setattr(iso_mod.urllib.request, "urlopen", boom)
        assert iso_mod.get_remote_size("https://x") is None
