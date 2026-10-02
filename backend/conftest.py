import os
import sys
import tempfile
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# CRITICAL: point the intelligence layer at a throwaway database *before* any
# test module imports app.main / app.intel.db. Without this the test suite
# would create and drop tables in the seeded demo database.
os.environ["REDFLAG_DATABASE_URL"] = "sqlite:///" + os.path.join(
    tempfile.gettempdir(), "redflag_pytest.db"
)
