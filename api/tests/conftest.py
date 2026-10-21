"""Test environment.

soc_api.main builds the app when it is imported, and prod refuses to start
without a console allowlist. Tests default to dev; the tests that care about
prod build their own Settings with env="prod" (explicit arguments win over the
environment).
"""

import os

os.environ["SOC_ENV"] = "dev"
