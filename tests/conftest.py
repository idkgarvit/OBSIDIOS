"""Shared test fixtures.

Two pieces of process-global state need isolation:

* The dashboard keeps rate-limit and login-lockout state in module globals.
  Without a reset, a suite that logs in more than 50 times inside one minute
  starts getting 429s, and tests fail depending on execution order.
* CHRONICLE used to write into the developer's real `chronicle/obsidios.db`
  (logins, audit rows, settings). Tests get a throwaway database instead.
"""
import os
import tempfile
from pathlib import Path

# This runs before any test module imports dashboard.app, so the background
# db.init() it starts uses the temporary database.
_TEST_DB = Path(tempfile.mkdtemp(prefix="obsidios-tests-")) / "obsidios.db"

from config import settings  # noqa: E402

settings.db.db_path = _TEST_DB
os.environ["OBSIDIOS_TEST_DB"] = str(_TEST_DB)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_auth_rate_limits():
    import dashboard.app as dash

    dash._rate_limit_store.clear()
    dash._LOGIN_FAILS.clear()
    yield
    dash._rate_limit_store.clear()
    dash._LOGIN_FAILS.clear()
