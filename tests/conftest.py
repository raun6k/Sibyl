"""Tests never start the scheduler's clock: no repository polls or feed refreshes against the dev database.

Queued jobs (a run someone started) still run.
"""

import os

os.environ.setdefault("SIBYL_SCHEDULER", "false")
