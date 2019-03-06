# -*- coding: utf-8 -*-
"""
This file is completely worthless. Should skip it completely till it can be
redone.
"""

import pytest

from conftest import is_27


@pytest.fixture
def make_temptree(tmpdir):
    """Make this thing::
        >$ mkdir -p a/b/c
        >$ touch a/{b/{c/,},}{1,2,3}
        a
        ├── b
        │   ├── c
        │   │   ├── 1
        │   │   ├── 2
        │   │   └── 3
        │   ├── 1
        │   ├── 2
        │   └── 3
        ├── 1
        ├── 2
        └── 3
    """
    import os
    this_dir = os.getcwd()
    os.chdir(tmpdir.strpath)
    os.makedirs("a/b/c")

    from itertools import product
    paths = (os.path.join(*p) for
             p in product("a a/b a/b/c".split(), "1 2 3".split()))
    for path in paths:
        # Is there no os.touch?
        # os.mknod(path, os.path.stat.S_IFREG | 0o600)
        with open(path, "w"):
            pass
        assert os.path.exists(path)
    os.chdir(this_dir)
    return tmpdir


@pytest.fixture
def bhstub():
    from emergency_git_server import HTTPBackendHandler

    class BhStub(HTTPBackendHandler):
        def __init__(self):
            import os
            if os.sys.version_info >= (3, 7):
                self.directory = os.getcwd()
            if is_27:
                self.client_address = ("localhost", 8000)
            self.docroot = None

    return BhStub()  # request, client_address, server ... [directory= ...]


git_root_name = "repos"
repo_relpaths = "a.git A/b.git A/B/c.git".split()


@pytest.fixture(scope="session")
def make_gitroot(tmpdir_factory):
    import os
    # Make git_root, call it "repos"
    git_root = str(tmpdir_factory.mktemp(git_root_name, numbered=False))
    os.chdir(git_root)
    os.makedirs("A/B")
    names = repo_relpaths
    try:
        from subprocess import run
    except ImportError:  # 27
        from subprocess32 import run
    for name in names:
        run(("git init -q --bare %s" % name).split())
    return str(tmpdir_factory.getbasetemp()), git_root, names


def test_dlog(bhstub, capsys, monkeypatch):
    if is_27:
        pytest.skip("3 only")
    bh = bhstub
    bh.dlog.__globals__["DEBUG"] = True
    fakes = ("localhost", "1/Jan/1970 00:00:00")

    def mock_as():
        return fakes[0]

    def mock_ldts():
        return fakes[1]

    monkeypatch.setattr(bh, "address_string", mock_as)
    monkeypatch.setattr(bh, "log_date_time_string", mock_ldts)

    def f():
        bh.dlog("foo")

    f()
    output = capsys.readouterr()[1].rstrip()
    assert output == "%s - - [%s] f() - foo" % fakes

    bh.dlog("")
    fmtstr = "%s - - [%s]" % fakes
    fmtstr += " test_dlog()%s"
    output = capsys.readouterr()[1].rstrip()
    assert output == fmtstr % ""

    bh.dlog("bh is: %s", bh)
    output = capsys.readouterr()[1].rstrip()
    assert output == fmtstr % (" - bh is: " + repr(bh))

    bh.dlog("bh is: {}", bh)
    output = capsys.readouterr()[1].rstrip()
    assert output == fmtstr % (" - bh is: " + repr(bh))

    def fkv(**kwargs):
        maxlen = max(len(k) for k in kwargs) + 1
        return "".join(("\n{:2}{:<{w}} {!r}".format("", k + ":", v, w=maxlen)
                        for k, v in kwargs.items()))

    foo, bar, baz = range(3)
    kw = dict(foo=foo, bar=bar, baz=baz)
    bh.dlog("some kwargs:", **kw)
    output = capsys.readouterr()[1].rstrip()
    assert output == fmtstr % (" - some kwargs:" + fkv(**kw))

    bh.dlog("auto kwargs:", locals="foo bar baz".split())
    output = capsys.readouterr()[1].rstrip()
    assert output == fmtstr % (" - auto kwargs:" + fkv(**kw))

    bh.dlog("", locals="fakes kw baz".split())
    output = capsys.readouterr()[1].rstrip()
    assert output == fmtstr % fkv(fakes=fakes, kw=kw, baz=2)

    class Spam(bh.__class__):
        foo = 0
        bar = 1

        def f(self):
            baz = 2  # noqa
            self.dlog("auto kwargs:", locals="self.foo self.bar baz".split())

    spam = Spam()
    monkeypatch.setattr(spam, "address_string", mock_as)
    monkeypatch.setattr(spam, "log_date_time_string", mock_ldts)
    spam.f()
    output = capsys.readouterr()[1].rstrip()
    from textwrap import dedent
    assert output == dedent("""
        localhost - - [1/Jan/1970 00:00:00] f() - auto kwargs:
          self.foo: 0
          self.bar: 1
          baz:      2
    """).strip()


def test_translate_path(bhstub, make_temptree):
    """Confirm some facts about the base-method.
    """
    import os
    from functools import partial

    hh = bhstub
    hh.docroot = make_temptree.strpath
    # We're not at doc root
    assert os.getcwd() != hh.docroot
    if os.sys.version_info >= (3, 7):
        # RHS is py._path.local.LocalPath but its eq works with strings
        assert hh.directory != hh.docroot

    # This is the tmpdir standing in for /var/www/html
    orig_dr = getattr(hh, "docroot")
    drplus = partial(os.path.join, orig_dr)

    # Paths can be real or fake
    assert hh.translate_path("a/1") == drplus("a/1")
    assert hh.translate_path("foo/bar") == drplus("foo/bar")

    # Leading slashes are dropped
    assert hh.translate_path("/foo") == drplus("foo")

    # Trailing slashes are not
    assert hh.translate_path("foo/") == drplus("foo/")

    # Spaces are not backslash-escaped
    assert hh.translate_path("foo%20bar/") == drplus("foo bar/")

    # Trailing queries are dropped
    path = "/foo/bar?baz=spam"
    assert hh.translate_path(path) == drplus("foo/bar")

    # We're *still* not at doc root and .directory hasn't changed
    assert os.getcwd() != orig_dr and orig_dr == hh.docroot
    if os.sys.version_info >= (3, 7):
        assert hh.directory != orig_dr

    # From glancing at the parent method, it might appear that overlapping
    # components are merged in a "union" type operation, but the next few
    # stanzas show otherwise
    hh.docroot = drplus("a/b")  # <- *Rewrite* docroot but don't cd
    drplus = partial(os.path.join, hh.docroot)

    # Here ``a`` is the parent of docroot, but a child ``a`` is appended
    assert drplus("a/b/1").endswith("a/b/a/b/1")
    assert hh.translate_path("a/b/1") == drplus("a/b/1")
    # Same for docroot tail (basename)
    assert drplus("b/1").endswith("b/b/1")
    assert hh.translate_path("b/1") == drplus("b/1")

    # ``os.curdir`` (single dots) are always dropped (posixpath.normpath)
    assert hh.translate_path("./foo/./") == drplus("foo/")
    assert hh.translate_path("/./foo") == drplus("foo")
    assert hh.translate_path(".//./foo/.///bar") == drplus("foo/bar")

    # ``os.pardir`` (double dots) get filtered out if they lead above docroot
    assert hh.translate_path("../foo") == drplus("foo")
    assert hh.translate_path("../../b") == drplus("b")
    assert hh.translate_path("/../../../b") == drplus("b")

    # Relative paths below docroot are resolved as if they existed
    assert hh.translate_path("./bar/..") == hh.docroot
    assert hh.translate_path("a/b/..") == drplus("a")

    # All components of docroot must exist
    hh.docroot = os.path.join(orig_dr, "fake")  # <- *Rewrite docroot*
    drplus = partial(os.path.join, hh.docroot)
    if is_27:
        with pytest.raises(OSError):
            assert hh.translate_path("foo") == drplus("foo")
    else:
        with pytest.raises(FileNotFoundError):
            assert hh.translate_path("foo") == drplus("foo")


class TestFindRepoBasic:

    @pytest.fixture(autouse=True)
    def _faux_init(self, make_gitroot, bhstub):
        self.docroot, self.gitroot, self.repos = make_gitroot
        self.bhstub = bhstub
        self.bhstub.docroot = self.docroot

    @pytest.fixture(autouse=True, params=range(2))
    def git_root_variants(self, request):
        """The script considers "git root" to be the longest path under
        docroot with no $GIT_DIR siblings and at least one $GIT_DIR
        descendant
        """
        if request.param == 1:
            self.gitroot = self.gitroot.replace(git_root_name, "fake")

    @pytest.fixture(autouse=True,
                    params=["info/refs?service=git-foo", "git-foo"])
    def query_string_variants(self, request):
        self.extra = request.param

    @pytest.fixture(autouse=True, params=list(range(3)))
    def repo_path_variants(self, request):
        self.repo = self.repos[request.param]

    @pytest.fixture(autouse=True, params=list(range(3)))
    def cwd_variants(self, request):
        import os
        dirs = (self.docroot, os.path.join(self.docroot, "repos"), "/tmp")
        self.cd = dirs[request.param]

    def test_find_repo_basic(self):
        """Asserts the following:
        1. The current working directory doesn't matter
        2. Same for stuff below "myrepo.git" (query string or cgi cmd)
        3. Canonical paths matter. Only extant components are
           tacked on to "head", everything else is left for the "tail."
           Doesn't matter whether the tail includes the "git root" or
           valid repos.
        4. Real components above "myrepo.git" (and below ``git_root``)
           are popped off the tail and appended to the head.
        """
        import os
        os.chdir(self.cd)                    # (1)
        ex = self.extra                      # (2)
        gr = os.path.basename(self.gitroot)  # (3)
        rp = self.repo                       # (4)

        path = "/%s/%s/%s" % (gr, rp, ex)  # <- url "path," not os path

        repo_path = os.path.join(self.docroot, gr, rp)
        if os.path.exists(repo_path):
            __, rp = os.path.split(rp)
            # Avoid cases like ``os.path.join("/tmp", "") == "/tmp/"``; this is
            # preferable to ``rstrip()``, which might mask other issues.
            if __ != "":
                gr = os.path.join(gr, __)
            msg = "\033[32mReal path:\033[m %r"
            head = "/%s" % gr
            tail = "%s/%s" % (rp, ex)
        else:
            msg = "\033[31mFake path:\033[m %r"
            head = "/"
            tail = "%s/%s/%s" % (gr, rp, ex)
        print(msg % repo_path)
        assert (head, tail) == self.bhstub.find_repo(path)


def pytest_generate_tests(metafunc):
    if metafunc.function != test_find_repo_rhs:
        return
    #
    args = "splits, queries, ind_cwds"
    #
    splits = []
    # Mix in alternate git_root directory name called "fake"
    for gr in (git_root_name, "fake"):
        for relpath in (repo_relpaths):
            full = ["", gr] + relpath.split("/")
            for i in range(1, len(full) + 1):
                splits.append(("/".join(full[:i]) if full[:i - 1] else "/",
                               "/".join(full[i:])))
    p = {
        "splits": splits,
        "queries": ("info/refs?service=git-foo", "git-foo"),
        "cwds": range(5)
    }
    from itertools import product
    vals = product(p["splits"], p["queries"], p["cwds"])
    metafunc.parametrize(args, vals, indirect=["ind_cwds"])


@pytest.fixture
def ind_cwds(request):
    i = request.param
    dr, gr, repo_names = request.getfixturevalue("make_gitroot")
    if i >= 0 and i < len(repo_names):
        import os
        return os.path.join(gr, repo_names[i])
    elif i == len(repo_names):
        return dr
    else:
        return "/tmp"


def test_find_repo_rhs(make_gitroot, bhstub, splits, queries, ind_cwds):
    """Call find_repo with optional rhs arg. Pretty useless/confusing
    without the print statements. Pass ``-s`` option to show. The
    "basic" variant above passes query strings via lhs (rhs is always
    None/empty).
    """
    docroot = make_gitroot[0]
    bhstub.docroot = docroot
    import os
    os.chdir(ind_cwds)
    #
    query = queries
    #
    # ``head`` and ``tail`` are the expected outcomes
    repo_path = os.path.join(docroot, splits[0].lstrip("/"), splits[1])
    if os.path.exists(repo_path):
        lhs, rhs = splits
        dirname_rhs, rhs = os.path.split(rhs)
        # Leading path components in tail are appended to head. Head should
        # never have a trailing slash:
        if dirname_rhs != "":
            lhs = os.path.join(lhs, dirname_rhs)
        head = lhs
        if rhs:
            tail = "%s/%s" % (rhs, query)
        else:
            # TODO add case for query without leading path components
            tail = query
            dirname_q, basename_q = os.path.split(query)
            if dirname_q:
                head = os.path.join(head, dirname_q)
                tail = basename_q
        msg = "\033[32mReal path:\033[m %r"
    else:
        # XXX potentially broken: it may only appear that args are returned
        # unchanged because the only case currently tested involves a fake dir
        # at depth 1, i.e, ``/var/html/www(docroot)/fake(gitroot)/rest``
        head = splits[0]
        tail = os.path.join(splits[1], query)
        msg = "\033[31mFake path:\033[m %r"
    print(msg % repo_path)
    print("passed: %r, %r" % (splits[0], os.path.join(splits[1], query)))
    print("expect: %r, %r" % (head, tail))
    assert (head, tail) == bhstub.find_repo(splits[0],
                                            os.path.join(splits[1], query))
