"""
As noted elsewhere, the author now considers this project absolute garbage.
This module may help some future person writing their own server validate
expected behavior for common use cases.


Old namespace issue
-------------------
When including an existing namespace as the repo's prefix in the url arg to
``git-clone``, this warning appears: ``warning: remote HEAD refers to
nonexistent ref, unable to checkout.`` The cloned work tree is empty until
issuing a ``git pull origin master``.

Upon updating ``remote.origin.url`` with a new namespace prefix, and pushing,
everything seems okay. The remote HEAD is even updated to point to the new
namespaced ref.

When cloning without any (existing) namespace prefixing the repo component of
the url, a familiar refrain appears::

    Note: checking out '2641d08..'
    You are in 'detached HEAD' state. You can look around ...
    ...
    git checkout -b <new-branch-name>

And ``status`` says ``not on any branch``. But, checking out master without the
``-b`` fixes everything. After updating the remote url and issuing a ``push -u
origin master``, the new namespace is created successfully on the remote.

Update 1. -- it seems most of the above only applies to remotes that were
initialized without the normal refs/heads/master but whose HEAD still pointed
thus before being pushed to.

This may have arisen from a fundamental misunderstanding of how namespaces are
supposed to work.

"""
import os
import re
import sys
import shutil
import pytest
import subprocess
import emergency_git_server

from _pytest.pytester import LineMatcher

from conftest import is_27

try:
    import dumper
except Exception:
    assert is_27
try:
    from pexpect import EOF
except ImportError:
    assert is_27

pytestmark = pytest.mark.skipif(is_27, reason="Python2 must run in subproc")

bw_script = os.path.join(os.path.dirname(__file__), "bw.sh")

is_travis = os.getenv("TRAVIS")
is_sub = os.getenv("TOXENV", "fake").endswith("sub")


gitignore = "\nspawn.out\n"
gitconfig = """
[user]
        name = {USER}
        email = {USER}@{HOSTNAME}.localhost
"""

certconf_source = """
[ req ]
utf8                   = yes
default_bits           = 1024
default_keyfile        = {path}
distinguished_name     = req_distinguished_name
encrypt_key            = no
prompt                 = no

[ req_distinguished_name ]
C                      = --
ST                     = DummyState
L                      = DummyCity
O                      = DummyOrg
OU                     = DummyOrgUnit
CN                     = localhost
emailAddress           = {email}
"""

authconf_source = """
{
  "%(pre)s/test_namespaces.git": {
    "description": "Bot",
    "secretsfile": "%(secretsfile)s",
    "privaterepo": false
  },
  "%(pre)s/maintainer": {
    "description": "Boss of public repo",
    "secretsfile": "%(secretsfile)s",
    "privaterepo": false
  },
  "%(pre)s/contributor": {
    "description": "Volunteer",
    "secretsfile": "%(secretsfile)s",
    "privaterepo": true
  }
}
"""
secrets_source = """
scmbot:T0NXShw7R7Gfg
maintainer:qSJwKT4k0OE2o
contributor:T0NXShw7R7Gfg
"""

bash_prompt = r"bash.*\$"
prompt_re = bash_prompt


def get_twofer(child, prompt=prompt_re):
    def _twofer(*args, **kwargs):
        child.sendline(*args, **kwargs)
        return child.expect(prompt)

    return _twofer


class Server:
    proc = None
    port = None
    url = None
    port_pat = re.compile(r"port (\d+)")

    def __init__(
        self,
        # *, <- no py27
        docroot,
        request,
        bw_path,
        server_path,
        py_executable,
        missing_envvars,
    ):
        self.docroot = docroot
        self.request = request
        self.bw_path = bw_path
        self.missing_envvars = missing_envvars

        self.logfile = docroot.join("server.log")
        self.pickfile = docroot.join("data.pickle")
        self.cachedir = request.config.cache.makedir("gitsrv")
        self._certfile = self.cachedir.join("dummycert.pem")
        self._authfile = docroot.join("auth.json")
        self.cmdline = [py_executable, server_path, self.docroot.strpath]

    def dumb_waiter(self, func, maxiter=30, wait_for=0.1):
        from time import sleep

        while maxiter > 0:
            rv = func()
            if rv:
                return rv
            sleep(wait_for)
            maxiter -= 1
        if maxiter == 0:
            raise RuntimeError("Timed out waiting for %s" % func)

    def find_port(self):
        m = self.port_pat.search(self.dumb_waiter(self.logfile.read))
        if m:
            return int(m.groups()[0])
        raise RuntimeError("Couldn't get port")

    def start(self, **env):
        env = dict(os.environ, **env)
        env.setdefault("_LOGFILE", self.logfile.strpath)
        env.setdefault("_PICKFILE", self.pickfile.strpath)
        proc = subprocess.Popen(self.cmdline, env=env)
        self.proc = proc
        assert self.dumb_waiter(self.logfile.exists) is True
        self.port = env.get("_PORT") or self.find_port()
        scheme = ("http", "https")["_CERTFILE" in env]
        self.url = "{}://localhost:{}".format(scheme, self.port)
        return proc

    def stop(self):
        self.proc.terminate()
        return self.proc.wait(timeout=2)

    def truncate_log(self):
        self.logfile.write("")

    def consume_log(self, pattern, truncate=True):
        from _pytest.outcomes import Failed

        def inner():
            lines = self.logfile.readlines()
            if lines:
                latest = LineMatcher(lines)
                try:
                    latest.fnmatch_lines(pattern)
                except Failed:
                    return None
                return True

        self.dumb_waiter(inner)
        if truncate:
            self.truncate_log()

    def log_empty(self):
        return self.logfile.size() == 0

    def clone(self, repo, subpath=None):
        """Clone LocalPath repo and return remote for client to add."""
        cwd = self.docroot
        name = None
        if subpath:
            subpath = subpath.strip("/")
            if subpath.endswith(".git"):
                subpath, name = os.path.split(subpath)
            if subpath:
                cwd = cwd.join(subpath)
                if not cwd.exists():
                    cwd.ensure(dir=True)
        out = err = b""
        env = os.environ.copy()
        env.update(BWRAP_NOREPO="1")
        if not name:
            name = repo.basename.rstrip("0123456789") + ".git"
        cmd = [] if is_travis else [self.bw_path.strpath]
        cmd += ["git", "clone", "--bare", repo.join(".git").strpath, name]
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.PIPE, cwd=cwd.strpath, env=env
            )
        except subprocess.CalledProcessError as exc:
            out = exc.output
            err = exc.stderr
            raise
        finally:
            if out:
                self.docroot.join("git.out").write(out)
            if err:
                self.docroot.join("git.err").write(err)
        path = "{}/{}".format(subpath, name) if subpath else name
        return "{}/{}".format(self.url, path)

    @property
    def certfile(self):
        assert self.create_cert()
        return self._certfile

    def create_cert(self):
        certstr = self._certfile.strpath
        if self._certfile.exists():
            try:  # Allow self-signed
                subprocess.check_call(
                    ["openssl", "verify", "-trusted", certstr, certstr]
                )
            except subprocess.CalledProcessError:
                self._certfile.remove()
            else:
                return True

        env = os.environ.copy()
        if self.missing_envvars:  # TOX
            env.update(self.missing_envvars)

        openssl_cnf = self.cachedir.join("openssl.cnf")
        if not openssl_cnf.exists():
            cmd = [] if is_travis else [self.bw_path.strpath]
            env.update(BWRAP_NOREPO="1")
            cmd += ["git", "config", "user.email"]
            email = subprocess.check_output(cmd, env=env)
            email = email.strip().decode()
            openssl_cnf.write(
                certconf_source.format(path=certstr, email=email)
            )
        # Some sites need -newkey algo to be passed
        cmdline = ["openssl", "req", "-config", openssl_cnf.strpath]
        cmdline += ["-x509", "-days", "1", "-newkey", "rsa", "-out", certstr]
        subprocess.check_call(cmdline, env=env)
        return True

    @property
    def authfile(self):
        if not self._authfile.exists():
            secretsfile = self.docroot.join("secrets")
            # Use crypt(3)-generated passwords, which don't require
            # openssl: maintainer: "forkme", contributor: "changeme"
            secretsfile.write(secrets_source)
            pre = ("/org", "")["first" in self.request._pyfuncitem.name]
            self._authfile.write(
                authconf_source
                % dict(pre=pre, secretsfile=secretsfile.strpath)
            )
        return self._authfile

    @property
    def pe_child_cmd(self):  # doesn't belong here but whatever
        if is_travis:
            return "bash --noprofile --norc -i"

        # bw.sh wants the project directory path as $1
        return "bash {} {}".format(
            self.bw_path.strpath, self.request.config.rootdir.strpath
        )

    def spawn_client(self, td):
        # Use self.tmphome instead of pytest's USERPROFILE
        if self.missing_envvars:
            for k, v in self.missing_envvars.items():
                td.monkeypatch.setenv(k, v)
        return td.spawn(self.pe_child_cmd)


@pytest.fixture
def server(request, tmpdir_factory):
    if not is_travis and shutil.which("bwrap") is None:
        pytest.fail("Bubblewrap not installed")

    tmpname = request._pyfuncitem.name.replace("[", ".").strip("]")
    tmphome = tmpdir_factory.mktemp("home-{}".format(tmpname), numbered=True)
    docroot = tmpdir_factory.mktemp("srv-{}".format(tmpname), numbered=True)

    docroot.chdir()

    server_path = docroot.join("emergency_git_server.py").strpath
    shutil.copyfile(emergency_git_server.__file__, server_path)
    # Wrap script with dumper when --dump-dlog passed
    if request.config.getoption("dump_dlog"):
        server_path = docroot.join("dumper.py").strpath
        shutil.copyfile(dumper.__file__, server_path)

    if is_travis:
        bw_path = None
    else:
        bw_path = docroot.join("bw.sh")
        shutil.copyfile(bw_script, bw_path.strpath)
        bw_path.chmod(0o700)

    missing_envvars = {
        "HOME": tmphome.strpath,
        "USER": sys.modules[type(tmpdir_factory).__module__].get_user(),
        "TERM": os.getenv("TERM") or "xterm",
        "HOSTNAME": os.getenv("HOSTNAME", "ci-worker" if is_travis else None),
    }
    assert all(missing_envvars.values())

    # Global git config
    (tmphome / ".config/git").ensure(dir=True)  # XDG_CONFIG_HOME
    (tmphome / ".config/git/ignore").write(gitignore)
    (tmphome / ".config/git/config").write(gitconfig.format(**missing_envvars))

    py_executable = os.getenv("GITSRV_TEST_PYEXE")
    if py_executable:
        _py_vers = subprocess.check_output(
            [py_executable, "--version"], stderr=subprocess.STDOUT
        )
        docroot.join("py_executable.version").write(_py_vers)
    else:
        py_executable = sys.executable

    server = Server(
        docroot=docroot,
        request=request,
        missing_envvars=missing_envvars,
        py_executable=py_executable,
        server_path=server_path,
        bw_path=bw_path,
    )
    yield server
    if server.proc:
        server.proc.kill()


# XXX param ``first`` used to mean option _FIRST_CHILD_OK, which has been
# retired. It now signifies a "git root" of at least 1 path component.


@pytest.mark.parametrize("create", [False, True], ids=["__", "create"])
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_basic_errors(server, testdir, create, ssl):
    # XXX no response may be sent after exception
    # TODO find out when this happens, fix; should always send something
    env = {}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started*"])
    pe = server.spawn_client(testdir)
    pe.expect(prompt_re)
    twofer = get_twofer(pe)
    if ssl:
        twofer("export GIT_SSL_NO_VERIFY=1")
    twofer("echo foo > foo.txt")
    twofer("git init")
    twofer("git add -A && git commit -m 'Init'")
    # Regression (invalid email), also triggered by "config --global"
    assert b"fatal" not in pe.before

    # Errors
    if create:
        remote = "%s/test_basic_errors.git" % server.url
    else:
        remote = server.clone(testdir.tmpdir)
    twofer("git remote add origin %s" % remote)
    twofer("git config -l")
    pe.sendline("git push -u origin master")
    if create:
        pe.expect("fatal")
        server.consume_log(["*RuntimeError*", "*500*Problem parsing path*"])
    else:
        pe.expect("up-to-date")
        server.consume_log("*GET /test_basic_errors*200*")

    if create:
        if ssl:
            url = "%s/test_basic_errors.git" % server.url
            twofer("curl --insecure --include --data init=1 %s" % url)
        else:
            from textwrap import dedent

            post_src = """
            POST /test_basic_errors.git HTTP/1.1
            Host: localhost:%s
            User-Agent: nc
            Accept: */*
            Content-Length: 7
            Content-Type: application/x-www-form-urlencoded

            init=1
            """
            post_src = dedent(post_src % server.port).strip().splitlines()
            post = testdir.tmpdir / "post"
            post.write("\r\n".join(post_src))
            twofer("nc localhost %s < ./post" % server.port)
        pe.expect("created")

    twofer("git config -l")
    pe.sendline("git push -u origin master")
    if create:
        pe.expect("new branch")
        server.consume_log(
            ["*GET*/test_basic_errors.git*200*", "*POST*/*200*"]
        )
    else:
        pe.expect("up-to-date")
        server.consume_log("*GET*/test_basic_errors.git*200*")

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


@pytest.mark.parametrize("create", [False, True], ids=["__", "create"])
@pytest.mark.parametrize("first", [False, True], ids=["__", "first"])
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_simulate_teams(server, testdir, create, first, ssl):
    """This is from ProGit, the 'Git Book'."""
    env = {}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started*"])

    pe = server.spawn_client(testdir)
    twofer = get_twofer(pe)

    pe.expect(prompt_re)
    if ssl:
        twofer("export GIT_SSL_NO_VERIFY=1")

    if first:
        upath = "test_simulate_teams.git"
    else:
        upath = "repos/test_simulate_teams.git"
    url = "{}/{}".format(server.url, upath)

    # Dev creates
    dev = testdir.tmpdir.join("dev")
    dev.mkdir()
    twofer("cd dev")
    twofer("echo '# New project' > README.md")
    twofer("git init")
    twofer("git add -A && git commit -m 'Init'")
    twofer("git remote add origin {}".format(url))
    twofer("git config -l")
    if create:
        if ssl:
            pe.sendline("curl --insecure --include --data init=1 %s" % url)
        else:
            pe.sendline("curl --include --data init=1 %s" % url)
        pe.expect("created")
        pe.expect(prompt_re)
        pe.sendline("git push -u origin master")
        pe.expect("new branch")
        server.consume_log(["*GET*/*200*", "*POST*/*200*"])
        pe.expect(prompt_re)
    else:
        clone_rv = server.clone(dev, upath)
        assert clone_rv == url
        twofer("git fetch")
        twofer("git branch -u origin/master master")
    pe.sendline("git ls-remote")
    pe.expect(r"refs/heads/master")
    pe.expect(prompt_re)

    # Others join
    ops = testdir.tmpdir.join("ops")
    qa = testdir.tmpdir.join("qa")
    twofer("git clone {} {}".format(url, ops.strpath))
    twofer("git clone {} {}".format(url, qa.strpath))

    # Develop
    pe.sendline("git checkout -b topic")
    pe.expect(".*new branch.*topic")
    pe.expect(prompt_re)
    pe.sendline(
        "mkdir src && "
        "echo '#ifndef NUMS_H\n#define NUMS_H\n' > src/nums.h && "
        "git add -A && git commit -m 'Begin nums'"
    )
    pe.expect("1 file changed")
    pe.expect(prompt_re)
    pe.sendline("git push -u origin topic")
    pe.expect(".*new branch.*topic")
    pe.expect(prompt_re)
    pe.sendline("git checkout master && git merge topic")
    pe.expect("1 file changed")
    pe.expect(prompt_re)
    pe.sendline("git push")
    pe.expect("master -> master")
    pe.expect(prompt_re)

    # One-off fetching
    twofer("cd ../ops || exit")
    # Note: this is different from master:mymaster, which would create a new
    # local branch named mymaster (remote ref is LHS)
    twofer("git branch -vr")
    pe.sendline("git fetch origin master:refs/remotes/origin/mymaster")
    pe.expect(["master *-> *origin/mymaster", "master *-> *origin/master"])
    pe.expect(prompt_re)
    twofer("git branch -vr")

    # Dev rewrites shared history
    twofer("cd %s || exit" % dev.strpath)
    twofer("echo 'TODO:\n- finish nums' >> README.md")
    pe.sendline("git add -A && git commit --amend -C @")
    pe.expect("2 files changed")
    pe.expect(prompt_re)
    pe.sendline("git push --force")
    pe.expect("forced update")
    pe.expect(prompt_re)

    # Rejected fetch
    twofer("cd %s || exit" % ops.strpath)
    pe.sendline(
        "git fetch origin master:refs/remotes/origin/mymaster \\\n"
        "topic:refs/remotes/origin/topic"
    )
    pe.expect(["rejected", "new branch"])
    pe.expect(prompt_re)

    # Pushing refspecs
    twofer("cd %s || exit" % qa.strpath)
    twofer("git fetch")
    twofer("echo 'dist: stable' > .qa-ci.dsl")
    pe.sendline("git add -A && git commit -m 'add qa-ci config'")
    pe.expect("1 file changed")
    pe.expect(prompt_re)
    twofer(
        "git config remote.origin.push "
        "refs/heads/master:refs/heads/qa/master"
    )
    pe.sendline("git push")
    pe.expect("new branch.*master.*->.*qa/master")
    pe.expect(prompt_re)
    twofer("git ls-remote --refs")

    # Multi-valued fetch entry
    twofer("cd %s || exit" % dev.strpath)
    twofer(
        "git config remote.origin.fetch "
        "'+refs/heads/master:refs/remotes/origin/master'"
    )
    twofer(
        "git config --add remote.origin.fetch "
        "'+refs/heads/qa/*:refs/remotes/origin/qa/*'"
    )
    twofer("git fetch")
    twofer("git show-ref")
    twofer("git log --oneline --decorate --graph --all")

    # Dev deletes topic
    twofer("git ls-remote --refs")
    pe.sendline("git push origin :topic")
    pe.expect("deleted")
    pe.expect(prompt_re)
    twofer("git ls-remote --refs")

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


@pytest.mark.parametrize("create", [False, True], ids=["__", "create"])
@pytest.mark.parametrize("first", [False, True], ids=["__", "first"])
@pytest.mark.parametrize("auth", [False, True], ids=["__", "auth"])
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_namespaces(server, testdir, create, first, auth, ssl):
    env = {"_USE_NAMESPACES": "1"}
    if auth:
        env.update(_AUTHFILE=server.authfile.strpath)
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    #
    server.start(**env)
    server.consume_log(["*Started*"])

    pe = server.spawn_client(testdir)
    twofer = get_twofer(pe)
    pe.expect(bash_prompt)

    def await_pass(username, passwd):
        pe.expect("Username.*: ?")  # greedy eats https://
        pe.sendline(username)  # ~~~~~~~~~~~~~~~~ ^
        pe.expect("Password.*: ?")
        pe.sendline(passwd)

    if ssl:
        pe.sendline("export GIT_SSL_NO_VERIFY=1")
        pe.expect(prompt_re)

    # Upstream
    project_scm = testdir.tmpdir.join("_project")  # somewhere else
    if first:
        project_path = "test_namespaces.git"
    else:
        project_path = "org/test_namespaces.git"
    project_dir = server.docroot.join(project_path)
    project_url = "{}/{}".format(server.url, project_path)
    project_scm.mkdir()
    twofer("cd %s || exit 1" % project_scm.strpath)
    twofer("echo 'foo' > foo.txt")
    twofer("git init")
    twofer("git add -A && git commit -m 'Init'")
    if create:
        curlargs = ["curl"]
        if ssl:
            curlargs += ["--insecure"]
        if auth:
            curlargs += ["--user", "scmbot"]
        curlargs += ["--include", "--data", "init=1", project_url]
        pe.sendline(" ".join(curlargs))
        if auth:
            pe.expect("password")
            pe.sendline("changeme")
        pe.expect("created")
        pe.expect(prompt_re)
        twofer("git remote add origin {}".format(project_url))
        pe.sendline("git push -u origin master")
        if auth:
            await_pass("scmbot", "changeme")
        pe.expect("new branch")
        server.consume_log(["*GET*/*200*", "*POST*/*200*"])
        pe.expect(bash_prompt)
    else:
        clone_rv = server.clone(project_scm, project_path)
        assert clone_rv == project_url

    twofer("cd %s || exit 1" % testdir.tmpdir.strpath)

    # Maintainer
    maintainer = testdir.tmpdir.join("maintainer")
    if first:
        maintainer_url = "%s/maintainer/test_namespaces.git" % server.url
    else:
        maintainer_url = "%s/org/maintainer/test_namespaces.git" % server.url
    twofer(
        "git clone -b master -o upstream {} {}".format(
            project_url, maintainer.strpath
        )
    )
    twofer("cd %s || exit 1" % maintainer.strpath)
    twofer("git remote add origin %s" % maintainer_url)
    pe.sendline("git config branch.master.remote")
    pe.expect("upstream")
    pe.expect(bash_prompt)
    pe.sendline("git push -u origin master")
    if auth:
        await_pass("maintainer", "forkme")
    pe.expect(".*master.*->.*master")
    server.consume_log(["*GET**200*", "*POST*/*200*"])
    pe.expect(bash_prompt)
    pe.sendline("git config branch.master.remote")
    pe.expect("origin")
    pe.expect(bash_prompt)
    if not auth:
        twofer("git ls-remote")
    twofer("git remote -v")

    # Ensure server tree looks as expected
    nsdir = project_dir.join("refs", "namespaces")
    nsdir_main = nsdir.join("maintainer")
    nsdir_cont = nsdir.join("contributor")
    assert nsdir.exists()
    assert nsdir_main.exists()
    twofer("cd %s || exit 1" % testdir.tmpdir.strpath)

    # Contrib
    contributor = testdir.tmpdir.join("contributor")
    if first:
        contributor_url = "%s/contributor/test_namespaces.git" % server.url
    else:
        contributor_url = "%s/org/contributor/test_namespaces.git" % server.url
    twofer(
        "git clone -b master -o upstream {} {}".format(
            maintainer_url, contributor.strpath  # <-
        )
    )
    twofer("cd %s || exit 1" % contributor.strpath)
    twofer("git remote add origin %s" % contributor_url)
    pe.sendline("git config branch.master.remote")
    pe.expect("upstream")
    pe.expect(bash_prompt)

    # Ensure server tree looks as expected
    assert not nsdir_cont.exists()
    twofer("cd %s || exit 1" % testdir.tmpdir.strpath)

    # Maintainer
    twofer("cd %s || exit 1" % maintainer.strpath)
    twofer("echo 'bar' > bar.txt")
    twofer("git add -A && git commit -m 'Add bar'")
    pe.sendline("git push -u origin master")
    if auth:
        await_pass("maintainer", "forkme")
    pe.expect(".*master.*->.*master")
    server.consume_log(["*GET**200*", "*POST*/*200*"])
    pe.expect(bash_prompt)
    pe.sendline("git config branch.master.remote")
    pe.expect("origin")
    pe.expect(bash_prompt)
    if not auth:
        twofer("git ls-remote")
    twofer("git remote -v")

    # Contrib
    twofer("cd %s || exit 1" % contributor.strpath)
    twofer("echo 'baz' > baz.txt")
    twofer("git add -A && git commit -m 'Add baz'")
    pe.sendline("git push -u origin master")
    if auth:
        await_pass("contributor", "changeme")
    pe.expect(".*master.*->.*master")
    server.consume_log(["*GET**200*", "*POST*/*200*"])
    pe.expect(bash_prompt)
    pe.sendline("git config branch.master.remote")
    pe.expect("origin")
    pe.expect(bash_prompt)
    if not auth:
        twofer("git ls-remote")
    twofer("git remote -v")

    # Since contrib's repo is private, cloning prompts:
    if auth:
        twofer("cd %s || exit 1" % testdir.tmpdir.strpath)
        lurker = testdir.tmpdir.join("lurker")
        pe.sendline("git clone {} {}".format(contributor_url, lurker.strpath))
        await_pass("", "")
        pe.expect(["failed", "fatal", "403"])
        pe.expect(bash_prompt)
        pe.sendline("git clone {} {}".format(contributor_url, lurker.strpath))
        await_pass("contributor", "password123")
        pe.expect(["failed", "fatal", "403"])
        pe.expect(bash_prompt)

    # Ensure server tree looks as expected
    assert nsdir_cont.exists()
    twofer("command -v tree && tree %s" % nsdir.strpath)

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


def test_create_ioset(testdir):
    session_dir = testdir.tmpdir.parts()[-2]
    subs = (
        session_dir.join(d).join("data.pickle").realpath()
        for d in os.listdir(session_dir.strpath)
        if d.startswith("srv-") and d.endswith("current")
    )
    picks = [d for d in subs if d.exists()]
    if not picks:
        return
    collected = dumper.collect_picks(*picks)
    assert collected
    dumper.save_as_json(testdir.tmpdir.join("collected.json"))


pre_receive_hook = r"""
#!/usr/bin/bash

(( $# )) && { echo expected no args ; exit 1; }

declare -a stdin
readarray -t -d " " stdin
declare -p stdin
for n in $(seq 10); do
    echo "pre-receive running: $n/10"
    sleep 1
done >&2
date +%s.%N
"""


@pytest.mark.skipif(
    is_sub or sys.version_info[:2] < (3, 7), reason="Feature missing"
)
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_concurrent_separate(server, testdir, ssl):
    env = {}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started*"])

    pe = server.spawn_client(testdir)
    twofer = get_twofer(pe)

    pe.expect(prompt_re)
    if ssl:
        twofer("export GIT_SSL_NO_VERIFY=1")

    script = """
    set -e -x
    cd {path}
    git fetch
    git branch -u origin/master master
    git add -A
    git commit -m more
    git ls-remote
    {{ pwd; date +%s.%N; }} | tee .started
    git push
    {{ pwd; date +%s.%N; }} | tee .finished
    [[ {name} == two ]] && sleep 1
    echo "{name} is done"
    """

    def create(name):
        upath = "repos/test_concurrent_{}.git".format(name)
        url = "{}/{}".format(server.url, upath)

        path = testdir.tmpdir.join(name)
        twofer("mkdir {}".format(name))
        twofer("cd {}".format(name))

        twofer("echo '# New project' > README.md")
        twofer("git init")
        twofer("git add -A && git commit -m 'Init'")
        twofer("git remote add origin {}".format(url))

        clone_rv = server.clone(path, upath)
        assert clone_rv == url
        phook = (server.docroot / upath / "hooks/pre-receive")
        phook.write(pre_receive_hook)
        phook.chmod(0o700)

        local_script = script.format(name=name, path=path.strpath)
        testdir.makefile(".sh", **{"{}/run".format(name): local_script})
        twofer("cd {}".format(testdir.tmpdir.strpath))

    create("one")
    create("two")

    pe.sendline("bash one/run.sh & bash two/run.sh")
    pe.expect(r"refs/heads/master")
    pe.expect(r"remote: pre-receive running: 10/10", timeout=20)
    pe.expect(r"two is done")
    pe.expect(prompt_re)

    beg1 = (testdir.tmpdir / "one/.started").read().strip().splitlines().pop()
    beg2 = (testdir.tmpdir / "two/.started").read().strip().splitlines().pop()
    fin1 = (testdir.tmpdir / "one/.finished").read().strip().splitlines().pop()
    fin2 = (testdir.tmpdir / "two/.finished").read().strip().splitlines().pop()

    diff_beg = abs(float(beg2) - float(beg1))
    assert 0 < diff_beg < 0.1

    diff_fin = abs(float(fin2) - float(fin1))
    assert 0 < diff_fin < 0.1

    (testdir.tmpdir / ".diff").write(
        "beg: {}\nend: {}".format(diff_beg, diff_fin)
    )

    dur = (float(fin2) + float(fin1))/2 - (float(beg2) + float(beg1))/2
    assert 8 < dur < 12


@pytest.mark.skipif(
    is_sub or sys.version_info[:2] < (3, 7), reason="Feature missing"
)
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_concurrent_collision(server, testdir, ssl):
    env = {}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started*"])

    pe = server.spawn_client(testdir)
    twofer = get_twofer(pe)

    pe.expect(prompt_re)
    if ssl:
        twofer("export GIT_SSL_NO_VERIFY=1")

    script = """
    set -e -x
    [[ {name} == two ]] && sleep 0.25
    cd {path}
    git add -A
    git commit -m more
    git ls-remote
    {{ pwd; date +%s.%N; }} | tee .started
    git push
    {{ pwd; date +%s.%N; }} | tee .finished
    echo "{name} is done"
    """

    upath = "repos/test_concurrent.git"
    url = "{}/{}".format(server.url, upath)

    # Create one
    path = testdir.tmpdir.join("one")
    twofer("mkdir one")
    twofer("cd one")

    twofer("echo '# New project' > README.md")
    twofer("git init")
    twofer("git add -A && git commit -m Init")
    twofer("git remote add origin {}".format(url))

    clone_rv = server.clone(path, upath)
    assert clone_rv == url

    twofer("git fetch")
    twofer("git branch -u origin/master master")

    phook = (server.docroot / upath / "hooks/pre-receive")
    phook.write(pre_receive_hook)
    phook.chmod(0o700)

    local_script = script.format(name="one", path=path.strpath)
    testdir.makefile(".sh", **{"one/run": local_script})
    twofer("cd {}".format(testdir.tmpdir.strpath))

    # Clone two
    twofer("git clone {} two".format(clone_rv))
    local_script = script.format(
        name="two", path=testdir.tmpdir.join("two").strpath
    )
    testdir.makefile(".sh", **{"two/run": local_script})

    pe.sendline("bash one/run.sh & bash two/run.sh")
    pe.expect(r"refs/heads/master")
    pe.expect(r"one is done", timeout=20)
    pe.expect(r"error")
    pe.expect(prompt_re)
