"""

The following should be of no interest to most users.


Nots on git-http-backend
~~~~~~~~~~~~~~~~~~~~~~~~

Git's client-side ``*-pack`` commands use at least two different URL request
styles re CGI scripts.

1. ``/git_root/myrepo.git/info/refs?service=git-cmd``

2. ``/git_root/myrepo.git/git-cmd``

Here, ``git_root`` is merely a stand-in for the leading components of the
target Git repo's URI. The first thing to note is that the main CGI command
spawned by the server as a child process never changes::

    /usr/libexec/git-core/git-http-backend

This is sometimes exported as ``$SCRIPT_FILENAME``, along with a shorter,
tail-only (basename) version in ``$SCRIPT_NAME``, which would expand to
``git-http-backend``. Likewise, ``$GIT_PROJECT_ROOT`` is always set to::

    $DOCROOT/git_root

where ``$DOCROOT`` is something like ``/var/www`` and ``git_root`` the
intermediate dirs between ``$DOCROOT`` and the Git repo. The only real
difference between forms (1) and (2) lies in how they impact the value of
two environment variables::

    # (1) GET /git_root/myrepo.git/info/refs?service=git-upload-pack HTTP/1.1
    $PATH_INFO    == "/myrepo.git/info/refs"
    $QUERY_STRING == "service=git-upload-pack"

    # (2) POST /git_root/myrepo.git/git-upload-pack HTTP/1.1
    $PATH_INFO    == "/myrepo.git/git-upload-pack"
    $QUERY_STRING == ""

See also: `cgi spec`_ and man page for `git-http-backend`_.

.. _`cgi spec`: http://www.ietf.org/rfc/rfc3875
.. _`git-http-backend`: https://github.com/git/git
   /Documentation/git-http-backend.txt

"""
import os
import pytest
from itertools import chain

_data = {}


def get_path_data():
    import json

    if _data:
        return _data
    with open(os.path.join(os.path.dirname(__file__), "paths.json")) as f:
        data = json.load(f)
    for k, v in data.items():
        assert isinstance(v, list)
        for n, entry in enumerate(v):
            _data["{}-{}".format(k, n)] = entry
    return _data


def pytest_generate_tests(metafunc):
    if "path_data" not in metafunc.fixturenames:
        return
    data = get_path_data()
    metafunc.parametrize("path_data", data.items())


def make_parts(root, parts):
    assert type(root)().strpath.startswith("/tmp")
    trunk = root
    for component in chain.from_iterable(parts):
        if not component:
            continue
        trunk = trunk / component
        if not trunk.exists():
            trunk.mkdir()
        else:
            assert trunk.isdir()
            assert trunk.basename == "info"
        if trunk.ext == ".git":
            head = trunk / "HEAD"
            head.write("")
            info = trunk / "info"
            info.mkdir()
            refs = trunk / "refs" / "heads" / "master"
            refs.ensure()


def test_determine_env_vars(path_data, tmpdir):
    from emergency_git_server import determine_env_vars
    from pprint import pformat
    from traceback import format_exception

    tmpdir.chdir()

    variant, data = path_data
    parts = data["parts"]
    reals = parts[0::2]  # concrete existing components
    fakes = parts[1::2]

    docroot = tmpdir.strpath
    command = data["command"]
    uri = data["path"]
    config = data["config"]

    log = tmpdir / ("%s.log" % variant)
    log.write("%s\n" % pformat(data))

    if not any(reals):
        with pytest.raises(AssertionError) as exc_info:
            determine_env_vars(docroot, command, uri, **config)
        errlog = tmpdir / "exception.log"
        errlog.write("\n".join(format_exception(*exc_info._excinfo)))

        leading = []
        for p in chain.from_iterable(fakes):
            leading.append(p)
            if p.endswith(".git"):
                break
        else:
            pytest.fail("Can't deal with non-git-suffixed unknowns")
        # XXX not sure what best approach here is (impossible combo)
        if len(leading) > 1 and config["USE_NAMESPACES"]:
            pytest.xfail("TODO: depends on refactor")
        # Anything not ending in .git must be part of gitroot
        make_parts(tmpdir, (leading,))
    else:
        assert any(any(p.endswith(".git") for p in group) for group in reals)
        make_parts(tmpdir, reals)

    env = determine_env_vars(docroot, command, uri, **config)

    assert len(env) in (4, 5)

    env["GIT_PROJECT_ROOT"] = env["GIT_PROJECT_ROOT"].replace(
        tmpdir.strpath, "$DOCROOT"
    )
    env["PATH_TRANSLATED"] = env["PATH_TRANSLATED"].replace(
        tmpdir.strpath, "$DOCROOT"
    )

    log.write("\n%s\n" % pformat(env), mode="a")

    assert env["GIT_PROJECT_ROOT"] == data["GIT_PROJECT_ROOT"]
    assert env["PATH_INFO"] == data["PATH_INFO"]
    assert env["PATH_TRANSLATED"] == data["PATH_TRANSLATED"]
    assert env["QUERY_STRING"] == data["QUERY_STRING"]
    assert env.get("GIT_NAMESPACE") == data.get("GIT_NAMESPACE")


@pytest.mark.parametrize("vs", [
    ("/foo/repo.git", "/foo/repo.git", "/foo/repo.git"),
    ("foo/repo.git", "foo/repo.git", "/foo/repo.git"),
    ("/repo.git", "/repo.git", "//repo.git"),
    ("repo.git", "repo.git", "//repo.git"),
    # EXACTLY same as above but with trailing slash (could add another param
    # but helps to see because upstream is quirky)
    ("/foo/repo.git/", "/foo/repo.git/", "/foo/repo.git/"),
    ("foo/repo.git/", "foo/repo.git/", "/foo/repo.git/"),
    ("/repo.git/", "/repo.git/", "/repo.git/"),
    ("repo.git/", "repo.git/", "/repo.git/"),
])
@pytest.mark.parametrize("query", ["", "?a=b"])
@pytest.mark.parametrize("frag", ["", "#bar"])
def test_url_collapse_path(vs, query, frag):
    from emergency_git_server import url_collapse_path

    try:
        from CGIHTTPServer import _url_collapse_path
    except ImportError:
        from http.server import _url_collapse_path

    upstream = _url_collapse_path

    if query:
        vs = ("%s%s" % (s, query) for s in vs)
    if frag:
        vs = ("%s%s" % (s, frag) for s in vs)

    give, ours, them = vs

    path, sep, rest = url_collapse_path(give)

    assert rest == query + frag

    assert them == upstream(give)
    assert ours == "".join((path, sep, rest))

    # General rule for upstream:
    import re
    if "/" not in give[1:]:
        assert re.match(r"^//[^/].+", them)
    else:
        assert re.match(r"^/[^/].+", them)


@pytest.mark.parametrize("gitroot", ["", "html", "html/repos"])
@pytest.mark.parametrize("ns", ["", "foo", "foo/bar"])
@pytest.mark.parametrize("query", ["", "?service=git-upload-pack"])
@pytest.mark.parametrize(
    "extra", ["", "/info/refs", "/git-upload-pack", "/baz/", "/baz/spam/"]
)
def test_dismember_target(tmpdir, gitroot, ns, extra, query):
    from emergency_git_server import dismember_target

    tmpdir.chdir()
    absgr = tmpdir / gitroot
    absgr.ensure(dir=True)

    repo = absgr / "repo.git"
    repo.mkdir()
    (repo / "refs/heads/master").ensure()

    repoplus = "repo.git%s" % extra
    combined = "/".join(filter(None, [gitroot, ns, repoplus, query]))
    path = "/" + combined
    result = dismember_target(tmpdir.strpath, path)
    assert result == (gitroot, ns, repoplus.rstrip("/"), query)
