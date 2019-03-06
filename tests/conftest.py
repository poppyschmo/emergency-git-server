import os
import sys

pytest_plugins = "pytester"

# Allow running pytest from project root
if not os.path.basename(sys.argv[0]) == "setup.py":
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))

is_27 = sys.version_info[:2] == (2, 7)


def replace_all(s, reps):
    """
    >>> replace_all("a", ("ab", "bc", "cd"))
    'd'
    >>> replace_all("ab", (("b", "c"), ("a", "B"), ("c", "A")))
    'BA'
    """
    from functools import reduce
    return reduce(lambda x, y: x.replace(*y), reps, s)


def pytest_addoption(parser):
    group = parser.getgroup("misc")
    group.addoption("--dump-dlog", action="store_true", dest="dump_dlog")
