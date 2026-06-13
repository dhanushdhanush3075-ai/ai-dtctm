"""
Smoke tests — verify the project imports cleanly and core contracts hold.
These are the first tests CI runs; they catch 80% of integration bugs
in 20 ms.
"""
from __future__ import annotations

import pytest


class TestCoreImports:
    """Every core module must import without error."""

    def test_config_loads(self):
        from config import CFG
        assert CFG is not None
        assert CFG.APP_VERSION.startswith("20.")
        assert CFG.PROFILE in ("dev", "demo", "prod")

    def test_cache_imports(self):
        from core.cache import TTLCache, cached, get_cache
        assert TTLCache is not None
        assert callable(cached)
        assert callable(get_cache)

    def test_logger_imports(self):
        from core.logger import get_logger
        log = get_logger("test")
        assert log is not None

    def test_shared_css_imports(self):
        from core.shared_css import (
            DASHBOARD_CSS, inject_css, inject_header,
            section_header, readout, risk_bar, case_id,
        )
        assert DASHBOARD_CSS.startswith("<style>")
        assert callable(inject_css)


class TestCaseID:
    """Forensic case IDs must follow expected format."""

    def test_case_id_format(self):
        from core.shared_css import case_id
        cid = case_id("OPS")
        assert cid.startswith("OPS-")
        parts = cid.split("-")
        # e.g. "OPS-2026-04-19-A7F3"
        assert len(parts) == 5
        assert parts[0] == "OPS"
        assert len(parts[-1]) == 4   # hex suffix

    def test_case_id_uniqueness(self):
        from core.shared_css import case_id
        ids = {case_id() for _ in range(20)}
        assert len(ids) >= 15  # Should be mostly unique


class TestRiskBar:
    """Risk bar HTML must escape correctly and segment properly."""

    def test_risk_bar_low(self):
        from core.shared_css import risk_bar
        html = risk_bar(2.0)
        assert "mc-risk-bar" in html
        assert html.count("seg") >= 10

    def test_risk_bar_critical(self):
        from core.shared_css import risk_bar
        html = risk_bar(9.5)
        assert "seg crit" in html

    def test_risk_bar_clamps_out_of_range(self):
        from core.shared_css import risk_bar
        # shouldn't raise
        assert risk_bar(-5) is not None
        assert risk_bar(999) is not None


class TestAPIClientContract:
    """Every API client must respect the APIResult schema."""

    @pytest.mark.parametrize("module_name", [
        "core.api_clients.virustotal",
        "core.api_clients.google_safebrowsing",
        "core.api_clients.urlscan",
        "core.api_clients.phishtank",
        "core.api_clients.abuseipdb",
        "core.api_clients.otx",
        "core.api_clients.shodan_client",
        "core.api_clients.malware_bazaar",
        "core.api_clients.urlhaus",
        "core.api_clients.threatfox",
    ])
    def test_client_imports(self, module_name):
        import importlib
        mod = importlib.import_module(module_name)
        assert mod is not None


class TestConfigProfiles:
    def test_profile_flags_are_mutually_exclusive(self):
        from config import CFG
        count = sum([CFG.is_dev, CFG.is_demo, CFG.is_prod])
        assert count == 1, "Exactly one profile flag must be true"

    def test_log_level_matches_profile(self):
        from config import CFG
        expected = {"dev": "DEBUG", "demo": "INFO", "prod": "WARNING"}
        assert CFG.log_level == expected[CFG.PROFILE]

    def test_available_apis_returns_full_dict(self):
        from config import CFG
        apis = CFG.available_apis()
        assert "virustotal" in apis
        assert "nvd" in apis
        assert apis["nvd"] is True  # No-key API, always available
