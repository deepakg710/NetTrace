import os
import shutil
import atexit
import tempfile
from pathlib import Path

# Create an isolated temporary directory for pytest before importing any app modules
_TEST_TMP_DIR = Path(tempfile.mkdtemp(prefix="nettrace_pytest_"))
_TEST_DATA_DIR = _TEST_TMP_DIR / "data"
_TEST_UPLOADS_DIR = _TEST_DATA_DIR / "uploads"
_TEST_REPORTS_DIR = _TEST_DATA_DIR / "reports"
_TEST_DB_PATH = _TEST_DATA_DIR / "test_nettrace.db"

_TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)
_TEST_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
_TEST_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

os.environ["NETTRACE_DATA_DIR"] = str(_TEST_DATA_DIR)
os.environ["NETTRACE_UPLOADS_DIR"] = str(_TEST_UPLOADS_DIR)
os.environ["NETTRACE_REPORTS_DIR"] = str(_TEST_REPORTS_DIR)
os.environ["NETTRACE_DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH.as_posix()}"


def _cleanup_test_dir() -> None:
    shutil.rmtree(_TEST_TMP_DIR, ignore_errors=True)


atexit.register(_cleanup_test_dir)
