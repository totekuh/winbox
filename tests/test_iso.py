"""Tests for winbox.iso — URL resolution and pure helpers."""

import pytest

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


class TestResolveDownloadUrl:
    @pytest.mark.integration
    def test_resolves_to_microsoft_cdn(self):
        """Verify the redirect chain lands on Microsoft's CDN."""
        url = resolve_download_url()
        assert "microsoft.com" in url
        assert url.endswith(".iso")
