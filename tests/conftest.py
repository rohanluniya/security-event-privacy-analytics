"""Shared pytest fixtures providing isolated temporary PlatformConfig directories."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.secops_platform.config import PlatformConfig


@pytest.fixture()
def test_config(tmp_path: Path) -> PlatformConfig:
    cfg = PlatformConfig(
        runtime_mode="local_native",
        data_dir=tmp_path / "secops_data",
    )
    cfg.ensure_directories()
    return cfg
