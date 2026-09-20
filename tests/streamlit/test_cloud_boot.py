from __future__ import annotations

import time
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).parents[2] / "streamlit_app.py"


def test_cloud_session_renders_without_network_initialization() -> None:
    started = time.monotonic()
    app = AppTest.from_file(str(APP), default_timeout=20).run()
    assert not app.exception
    assert len(app.tabs) == 6
    assert time.monotonic() - started < 10


def test_deep_network_checks_are_opt_in() -> None:
    app = AppTest.from_file(str(APP), default_timeout=20).run()
    checkboxes = {checkbox.label: checkbox for checkbox in app.checkbox}
    assert checkboxes["Enable Company/Organization + domain-age lookup (WHOIS)"].value is False
    assert checkboxes["Deep SMTP mailbox + catch-all checks"].value is False
