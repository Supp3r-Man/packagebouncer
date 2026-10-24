import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scan import load_top  # noqa: E402


@pytest.fixture(scope="session")
def top():
    return load_top(ROOT / "data" / "top_packages.txt")
