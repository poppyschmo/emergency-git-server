
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
        picks = [p for p in numbed.glob("srv-*/data.pickle") if not
                 p.parent.name.endswith("current")]
        if picks:
            return picks
    raise RuntimeError("No picks found!")


def collect_picks(*picks, include_all=False):
    """Extract and collect relevant items from dumped pickle data.

    Return a dict with these keys::

       'command' verb
       'path': everything after hostname:port in full URL
       'GIT_PROJECT_ROOT': '{docroot}/rest'
       'PATH_INFO': '/repo.git/...'
       'PATH_TRANSLATED': the previous two combined
       'QUERY_STRING': 'service=...' or ''
       'GIT_NAMESPACE': maybe absent
       'cmdline': ['/usr/libexec/git-core/git-http-backend']
    """
    import pickle
    from py.path import local as LocalPath
    from conftest import replace_all
    if not isinstance(picks[0], LocalPath):
        picks = [LocalPath(str(p)) for p in picks]
    collected = {}
    envvars = "GIT_PROJECT_ROOT PATH_INFO PATH_TRANSLATED QUERY_STRING".split()
    reps = [("-__-", "-"), ("-__", ""), ("__-", ""), ("test_", "")]

    for pick in picks:
        tname = pick.parts()[-2].basename.replace("srv-", "")
        # These don't impact path translation
        if any(s in tname for s in ("ssl-", "-ssl", ".ssl",
                                    "auth-", "-auth", ".auth")):
            continue
        tname = replace_all(tname, reps).rstrip("0123456789._")
        transactions = collected[tname] = []
        with pick.open("rb") as flor:
            calls = pickle.load(flor)
        entry = None
        docroot = None
        for call in calls:
            name = call["name"]
            tag = call["tag"]
            if name == "parse_request":
                if entry is not None:
                    if "cmdline" in entry:
                        raise RuntimeError("cmdline shouldn't be in entry; "
                                           "ensure DEBUG is set")
                    if "command" in entry:
                        assert entry["command"] == "GET"
                    if include_all:
                        transactions.append(entry)
                entry = {}  # Throw away GETs that didn't trigger action
                docroot = call["kwargs"]["docroot"]
                entry.update(command=call["kwargs"]["command"],
                             path=call["kwargs"]["path"].replace("test_", ""))
            elif name == "handle_error":
                assert tag == "exception"
                # Gets axed unless include_all passed
                entry.update(exception=call["kwargs"])
            elif name == "run_cgi":
                if tag == "envvars":
                    assert "env" not in entry
                    entry.update(
                        {k: v.replace(docroot, "$DOCROOT").replace("test_", "")
                         for k, v in call["kwargs"].items() if k in envvars}
                    )
                    ns = call["kwargs"].get("GIT_NAMESPACE")
                    if ns:
                        entry["GIT_NAMESPACE"] = ns
                elif tag == "cmdline":
                    assert "cmdline" not in entry
                    entry["cmdline"] = call["kwargs"]["cmdline"]
                    transactions.append(entry)
                    docroot = entry = None

    return collected


def save_as_json(path):
    import json
    from dumper import collect_picks, find_last_picks
    collected = collect_picks(*find_last_picks())
    with open(path, "w") as flow:
        json.dump(collected, flow)


if __name__ == "__main__":
    import os
    import sys
    import pickle
    import emergency_git_server

    data = []
    orig_parse_request = emergency_git_server.HTTPBackendHandler.parse_request

    def parse_request(inst):
        """Manual patch for handler when dumping data. Noisy."""
        rv = orig_parse_request(inst)
        # print("\n<<<<<<<<<<: %r" % inst.raw_requestline, file=sys.stderr)
        inst.dlog("parsed",
                  requestline=inst.requestline,
                  version=inst.request_version,
                  docroot=inst.docroot,
                  command=inst.command,
                  headers=inst.headers,
                  path=inst.path)
        return rv

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
        super(emergency_git_server.CtxServer, inst).server_close()
        with open(pickfile, "wb") as flow:
            pickle.dump(data, flow)

    def handle_error(inst, *a, **kw):
        super(emergency_git_server.CtxServer, inst).handle_error(*a, **kw)
        typ, val, __ = sys.exc_info()
        inst.RequestHandlerClass.dlog(None, "exception",
                                      name=typ.__name__,
                                      msg=getattr(val, "args"))

    def dpick(inst, tag, **kwargs):
        # tag is fmt
        import inspect
        ctx = inspect.stack()[1]
        if hasattr(ctx, "function"):
            name = ctx.function
        else:
            name = ctx[3]
        data.append(dict(name=name, tag=tag, kwargs=kwargs))

    emergency_git_server.HTTPBackendHandler.dlog = dpick
    emergency_git_server.HTTPBackendHandler.parse_request = parse_request
    emergency_git_server.CtxServer.server_close = server_close
    emergency_git_server.CtxServer.handle_error = handle_error
    sys.exit(emergency_git_server.main(DEBUG=True))
