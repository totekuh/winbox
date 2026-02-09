"""Tests for winbox.utils — shared utility functions."""

from winbox.utils import human_size


class TestHumanSize:
    def test_zero(self):
        assert human_size(0) == "0.0 B"

    def test_bytes(self):
        assert human_size(1) == "1.0 B"
        assert human_size(512) == "512.0 B"
        assert human_size(1023) == "1023.0 B"

    def test_kilobytes(self):
        assert human_size(1024) == "1.0 KB"
        assert human_size(1536) == "1.5 KB"

    def test_megabytes(self):
        assert human_size(1024 * 1024) == "1.0 MB"
        assert human_size(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        assert human_size(1024 ** 3) == "1.0 GB"
        assert human_size(5 * 1024 ** 3) == "5.0 GB"

    def test_terabytes(self):
        assert human_size(1024 ** 4) == "1.0 TB"
        assert human_size(2 * 1024 ** 4) == "2.0 TB"

    def test_float_input(self):
        assert human_size(1024.0) == "1.0 KB"
