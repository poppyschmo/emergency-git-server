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


def ensure_crlf(string_or_bytes, trailing=None):
    r"""
    >>> ensure_crlf('\nfoo\nbar\nbaz\n\n')
    'foo\r\nbar\r\nbaz\r\n\r\n'

    >>> ensure_crlf('\nfoo\nbar\nbaz\n\nspam\n')
    'foo\r\nbar\r\nbaz\r\n\r\nspam'
    """
    is_bytes = isinstance(string_or_bytes, bytes)
    if trailing is None:
        trailing = string_or_bytes.endswith(b"\n\n" if is_bytes else "\n\n")
    lines = string_or_bytes.strip().splitlines()
    sp = b"\r\n" if is_bytes else "\r\n"
    if trailing:
        lines.append(sp)
    return sp.join(lines)


def pytest_addoption(parser):
    group = parser.getgroup("misc")
    group.addoption("--dump-dlog", action="store_true", dest="dump_dlog")
