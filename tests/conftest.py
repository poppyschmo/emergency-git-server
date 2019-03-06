import os
import sys

pytest_plugins = "pytester"

# Allow running pytest from project root
if not os.path.basename(sys.argv[0]) == "setup.py":
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))


def pytest_addoption(parser):
    group = parser.getgroup("misc")
    group.addoption("--dump-dlog", action="store_true", dest="dump_dlog")
