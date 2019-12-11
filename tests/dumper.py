from collections.abc import MutableMapping, MutableSequence


def find_last_picks(num=None):
    """Find latest dumps.

    This is only for REPLing.`` test_create_ioset`` uses /pytest-current

        >>> from dumper import collect_picks, find_last_picks
        >>> collect_picks(*find_last_picks())  # doctest: +SKIP
        ...
        >>> [(name, [t for t in trans if "cmdline" not in t]) for
        ...  name, trans in collected.items()]  # doctest: +SKIP
    """
    # Doubt this works in < 3.5
    # tempfile.gettempdir()
    from _pytest.tmpdir import get_user
    from pathlib import Path

    top = Path("/tmp/pytest-of-%s" % get_user())
    for numbed in top.iterdir():  # pytest-99, pytest-98, ...
        if numbed.name.endswith("-current"):
            continue
        if num and not numbed.name.endswith(str(num)):
            continue
        picks = [
            p
            for p in numbed.glob("srv-*/data.pickle")
            if not p.parent.name.endswith("current")
        ]
        if picks:
            return picks
    raise RuntimeError("No picks found!")


class CallHandler(object):
    envvars = (
        "GIT_PROJECT_ROOT",
        "PATH_INFO",
        "PATH_TRANSLATED",
        "QUERY_STRING",
        "GIT_NAMESPACE",
    )
    entry = None
    docroot = None

    def __init__(self, include_all=False):
        self.include_all = include_all

        # Not available at import time for module/class
        from emergency_git_server import config
        from conftest import replace_all

        self.default_config = dict(config)
        self.replace_all = replace_all

    def __call__(self, call):
        f = getattr(self, call["name"])
        # If method returns record non-None, caller retire this instance
        return f(call["tag"], call["kwargs"])

    def maybe_create_repo(self, tag, kwargs):
        if tag == "git-init":
            self.entry["new_repo"] = kwargs["new_repo"]

    def parse_request(self, tag, kwargs):
        if self.entry is not None:
            if tag == "top":
                # Last call must not have been CGI
                assert "GIT_PROJECT_ROOT" not in self.entry
                if self.include_all:
                    return self.entry
            elif tag == "determine_env_vars()":
                self.entry.update(kwargs)
            else:
                assert tag == "headers"

        if tag == "top":
            # Only save non-default items
            config = {
                k: v for k, v in kwargs["config"].items()
                if self.default_config[k] != v
            }

            self.docroot = kwargs["docroot"]
            self.entry = {
                "parts": kwargs["parts"],
                "config": config,
                "command": kwargs["command"],
                "path": kwargs["path"],
            }
            if kwargs["auth_dict"]:
                self.entry["auth_dict"] = kwargs["auth_dict"]

    def handle_error(self, tag, kwargs):
        assert tag == "exception"
        # Gets axed unless include_all passed
        self.entry.update(exception=kwargs)
        if self.include_all:
            return self.entry

    def _populate_envvars(self, tag, kwargs):
        # Not actually adding anythin here
        if tag == "envvars":
            for k, v in kwargs.items():
                if k in self.envvars:
                    assert v == self.entry[k]

    def _replace_stuff(self, thing):
        if isinstance(thing, tuple):
            thing = list(thing)
        if isinstance(thing, MutableSequence):
            for n, e in enumerate(list(thing)):
                thing[n] = self._replace_stuff(e)
        elif isinstance(thing, MutableMapping):
            for k, v in dict(thing).items():
                thing[k] = self._replace_stuff(v)
        elif isinstance(thing, str):
            thing = self.replace_all(thing, self.reps)
        return thing

    def run_cgi(self, tag, kwargs):
        self.reps = [(self.docroot, "$DOCROOT")]
        assert tag == "subprocess"
        # Simplify by subsituting explicit paths with ssymbols
        return self._replace_stuff(self.entry)


def collect_picks(*picks, **handler_kwargs):
    """Extract and collect relevant items from dumped pickle data.

    Return a dict with these items::

        config: module dict
        parts: fs path components corresponding to /uri
        command: HTTP verb
        path: full /uri including query, etc.
        auth_dict: (when nonempty)

        GIT_PROJECT_ROOT: '{docroot}/rest'
        PATH_INFO: '/repo.git/...'
        PATH_TRANSLATED: the previous two combined
        QUERY_STRING: 'service=...' or ''

        GIT_NAMESPACE: when set
        ...
    """
    import pickle
    from py.path import local as LocalPath
    from conftest import replace_all

    if not isinstance(picks[0], LocalPath):
        picks = [LocalPath(str(p)) for p in picks]

    collected = {}
    reps = (("-__-", "-"), ("-__", ""), ("__-", ""), ("test_", ""))
    # FIXME remove auth stuff; it DOES impact path translation
    skip = ("ssl-", "-ssl", ".ssl", "auth-", "-auth", ".auth")

    for pick in picks:
        _tname = pick.parts()[-2].basename.replace("srv-", "")
        # Skip TLS-related variants
        if any(s in _tname for s in skip):
            continue

        with pick.open("rb") as flor:
            calls = pickle.load(flor)

        tname = replace_all(_tname, reps).rstrip("0123456789._")
        collected[tname] = []
        handler = None

        for call in calls:
            if handler is None:
                handler = CallHandler(**handler_kwargs)
            res = handler(call)
            if res is not None:
                collected[tname].append(res)
                handler = None

    return collected


def save_as_json(path):
    # To view: jq '.[] | .[] | .key ' < foo.json
    import json
    from dumper import collect_picks, find_last_picks

    collected = collect_picks(*find_last_picks())
    with open(path, "w") as flow:
        json.dump(collected, flow, separators=",:")


def group_parts_by_existence(docroot, path):
    """Return continguous subpaths grouped by existence

    Even-numbered groups, starting from zero are real. Query strings are
    dropped entirely. Two example outcomes where the docroot is
    ``/docroot``::

        # uri = "/gitroot/repo.git/info/refs"
        # fs = "/docroot/gitroot/repo.git/info"
        ["gitroot", "repo.git", "info"], ["refs"]

        # uri = "/gitroot/my_ns/repo.git?service=foo"
        # fs  = "/docroot/gitroot/repo.git"
        ["gitroot"], ["my_ns"], ["repo.git"]

        # uri = "/my_ns/repo.git?service=foo"
        # fs  = "/docroot/repo.git"
        [], ["my_ns"], ["repo.git"]

    """
    from pathlib import Path  # 3.x

    path, *_ = path.split("?")
    trunk = Path(docroot).resolve(True)
    parts = iter(Path(path.strip("/")).parts)
    out = []
    current = []

    for p in parts:
        is_real = (trunk / p).exists()
        is_fake = not is_real
        is_odd = bool(len(out) % 2)
        is_even = not is_odd

        if is_real:
            trunk /= p

        if (is_odd and is_real) or (is_even and is_fake):
            out.append(tuple(current))
            current = [p]
            continue
        current.append(p)

    out.append(tuple(current))
    return tuple(out)


if __name__ == "__main__":
    # This used to mock-wrap calls to Popen, but the results were not useful
    # (boring). The action/danger happens earlier during env var assignment.
    import os
    import sys
    import pickle
    import inspect
    import emergency_git_server

    data = []
    pickfile = os.getenv("_PICKFILE")
    if not pickfile:
        raise RuntimeError("No _PICKFILE found")

    if os.path.exists(pickfile):
        from datetime import datetime as dt
        import shutil

        rotated = "{}.{}".format(pickfile, dt.utcnow().isoformat())
        shutil.copyfile(pickfile, rotated)
        os.truncate(pickfile, 0)

    # Hard KILL signal from pexpect means atexit doesn't run, so this
    def server_close(inst):
        super(emergency_git_server.TlsServer, inst).server_close()
        with open(pickfile, "wb") as flow:
            pickle.dump(data, flow)

    def handle_error(inst, *a, **kw):
        super(emergency_git_server.TlsServer, inst).handle_error(*a, **kw)
        typ, val, __ = sys.exc_info()
        inst.RequestHandlerClass.dlog(
            None, "exception", name=typ.__name__, msg=getattr(val, "args")
        )

    def _topper(inst, kwargs):
        # Drop unpicklables
        for k, v in list(kwargs.items()):
            if type(v) not in (int, float, bytes, type(None), str):
                r = repr(v)
                if r.startswith("<") and r.endswith(">"):
                    kwargs[k] = r

        # Inject
        kwargs.update(
            parts=group_parts_by_existence(inst.docroot, inst.path),
            config=emergency_git_server.config
        )

    def dpick(inst, tag, **kwargs):
        ctx = inspect.stack()[1]
        if hasattr(ctx, "function"):
            name = ctx.function
        else:
            name = ctx[3]

        if name == "parse_request" and tag == "top":
            _topper(inst, kwargs)
        data.append(dict(name=name, tag=tag, kwargs=kwargs))

    emergency_git_server.HTTPBackendHandler.dlog = dpick
    emergency_git_server.TlsServer.server_close = server_close
    emergency_git_server.TlsServer.handle_error = handle_error
    sys.exit(emergency_git_server.main(DEBUG=True))
