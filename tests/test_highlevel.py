"""
As noted elsewhere, the author now considers this project absolute garbage.
This module may help some future person writing their own server validate
expected behavior for common use cases.
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

bw_script = os.path.join(os.path.dirname(__file__), "bw.sh")

is_travis = os.getenv("TRAVIS")


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

bash_prompt = (r"bash.*\$")
prompt_re = bash_prompt


def get_twofer(child, prompt=prompt_re):
    def _twofer(*args, **kwargs):
        child.sendline(*args, **kwargs)
        return child.expect(prompt)
    return _twofer


@pytest.fixture
def server(request, tmpdir_factory):
    if not is_travis and shutil.which("bwrap") is None:
        pytest.fail("Bubblewrap not installed")
    from time import sleep

    name = request._pyfuncitem.name.replace("[", ".").strip("]")
    name = "srv-{}".format(name)
    docroot = tmpdir_factory.mktemp(name, numbered=True)
    docroot.chdir()
    cachedir = request.config.cache.makedir("gitsrv")
    bw_path = docroot.join("bw.sh")
    server_path = docroot.join("emergency_git_server.py").strpath
    shutil.copyfile(emergency_git_server.__file__, server_path)
    if request.config.getoption("dump_dlog"):
        server_path = docroot.join("dumper.py").strpath
        shutil.copyfile(dumper.__file__, server_path)
    shutil.copyfile(bw_script, bw_path.strpath)
    bw_path.chmod(0o700)

    missing_envvars = {}
    misus = os.getenv("USER")
    misho = os.getenv("HOME")
    miste = os.getenv("TERM")
    mishn = os.getenv("HOSTNAME")
    # TOX/TRAVIS need these
    if not misus:
        from _pytest.tmpdir import get_user
        misus = get_user()
        missing_envvars.update(USER=misus)
    if not misho:
        misho = "/home/%s" % misus
        missing_envvars.update(HOME=misho)
    if not miste:
        miste = "xterm"
        missing_envvars.update(TERM=miste)
    if not mishn:
        if is_travis:
            mishn = "ci-worker"
        else:
            raise RuntimeError("HOSTNAME required in environment")
        missing_envvars.update(HOSTNAME=mishn)

    py_executable = os.getenv("GITSRV_TEST_PYEXE")
    if py_executable:
        _py_vers = subprocess.check_output([py_executable, "--version"],
                                           stderr=subprocess.STDOUT)
        docroot.join("py_executable.version").write(_py_vers)
    else:
        py_executable = sys.executable

    class Server:
        proc = None
        port = None
        url = None
        port_pat = re.compile(r"port (\d+)")

        def __init__(self):
            self.missing_envvars = missing_envvars
            self.rootdir = request.config.rootdir
            self.docroot = docroot
            self.cachedir = cachedir
            self.logfile = docroot.join("server.log")
            self.pickfile = docroot.join("data.pickle")
            self._certfile = cachedir.join("dummycert.pem")
            self._authfile = docroot.join("auth.json")
            self.cmdline = [py_executable, server_path, docroot.strpath]

        def dumb_waiter(self, func, maxiter=30, wait_for=0.1):
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
            cmd = [] if is_travis else [bw_path.strpath]
            cmd += ["git", "clone", "--bare", repo.join(".git").strpath, name]
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.PIPE,
                                              cwd=cwd.strpath, env=env)
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
                    subprocess.check_call(["openssl", "verify", "-trusted",
                                           certstr, certstr])
                except subprocess.CalledProcessError:
                    self._certfile.remove()
                else:
                    return True

            env = os.environ.copy()
            if self.missing_envvars:  # TOX
                env.update(self.missing_envvars)

            openssl_cnf = self.cachedir.join("openssl.cnf")
            if not openssl_cnf.exists():
                email = subprocess.check_output(
                    ["git", "config", "user.email"], env=env
                )
                openssl_cnf.write(certconf_source.format(path=certstr,
                                                         email=email.decode()))
            # Some sites need -newkey algo to be passed
            cmdline = ["openssl", "req", "-config", openssl_cnf.strpath,
                       "-x509", "-days", "1", "-newkey", "rsa",
                       "-out", certstr]
            subprocess.check_call(cmdline, env=env)
            return True

        @property
        def authfile(self):
            if not self._authfile.exists():
                secretsfile = self.docroot.join("secrets")
                # Use crypt(3)-generated passwords, which don't require
                # openssl: maintainer: "forkme", contributor: "changeme"
                secretsfile.write(secrets_source)
                pre = ("/org", "")["first" in request._pyfuncitem.name]
                self._authfile.write(
                    authconf_source % dict(pre=pre,
                                           secretsfile=secretsfile.strpath)
                )
            return self._authfile

        @property
        def pe_child_cmd(self):  # doesn't belong here but whatever
            if is_travis:
                assert self.missing_envvars
                cmd = ("env -i - USER={USER} HOME={HOME} TERM={TERM} "
                       "HOSTNAME={HOSTNAME} bash --noprofile --norc -i")
                env = os.environ.copy()
                env.update(self.missing_envvars)
                return cmd.format(**env)
            else:
                cmd = "bash {} {}"
                return cmd.format(bw_path.strpath,
                                  request.config.rootdir.strpath)

    s = Server()
    yield s
    if s.proc:
        s.proc.kill()


@pytest.mark.skipif(is_27, reason="Python2 must run in subproc")
@pytest.mark.parametrize("create", [False, True], ids=["__", "create"])
@pytest.mark.parametrize("first", [False, True], ids=["__", "first"])
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_basic_errors(server, testdir, create, first, ssl):
    # XXX no response may be sent after exception
    # TODO find out when this happens, fix; should always send something
    env = {}
    if first:
        env.update({"_FIRST_CHILD_OK": "1"})
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started serving*"])
    pe = testdir.spawn(server.pe_child_cmd)
    pe.expect(prompt_re)
    twofer = get_twofer(pe)
    if ssl:
        twofer("export GIT_SSL_NO_VERIFY=1")
    twofer("echo foo > foo.txt")
    twofer("git init")
    twofer("git add -A && git commit -m 'Init'")

    # Errors
    if create:
        remote = "%s/test_basic_errors.git" % server.url
    else:
        remote = server.clone(testdir.tmpdir)
    twofer("git remote add origin %s" % remote)
    twofer("git config -l")
    pe.sendline("git push -u origin master")
    if create:
        twofer("fatal")  # trips before first child warning
        server.consume_log(["*GET*403*", "*_CREATE_MISSING*"])
    elif first:
        twofer("up-to-date")
        server.consume_log("*GET /test_basic_errors*200*")
    else:
        twofer(r"fatal")
        server.consume_log(["*WARNING*", "*first child*"])

    # OK
    if create:
        remote = "%s/repos/test_basic_errors.git" % server.url
        assert server.stop() == 0  # restart server with envvar
        server.start(_CREATE_MISSING="1", **env)
        server.consume_log(["*Started serving*"])
    else:
        remote = server.clone(testdir.tmpdir, "repos")
    twofer("git remote set-url origin %s" % remote)
    twofer("git config -l")
    pe.sendline("git push -u origin master")
    if create:
        twofer("new branch")
        server.consume_log(["*GET*/*200*", "*POST*/*200*"])
    else:
        twofer("up-to-date")
        server.consume_log("*GET*repos*200*")

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


@pytest.mark.skipif(is_27, reason="Python2 must run in subproc")
@pytest.mark.parametrize("create", [False, True], ids=["__", "create"])
@pytest.mark.parametrize("first", [False, True], ids=["__", "first"])
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_simulate_teams(server, testdir, create, first, ssl):
    """This is from ProGit, the 'Git Book'."""
    env = {}
    if create:
        env.update(_CREATE_MISSING="1")
    if first:
        env.update(_FIRST_CHILD_OK="1")
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started serving*"])

    pe = testdir.spawn(server.pe_child_cmd)
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
    pe.sendline("mkdir src && "
                "echo '#ifndef NUMS_H\n#define NUMS_H\n' > src/nums.h && "
                "git add -A && git commit -m 'Begin nums'")
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
    pe.expect(["master *-> *origin/mymaster",
               "master *-> *origin/master"])
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
    pe.sendline("git fetch origin master:refs/remotes/origin/mymaster \\\n"
                "topic:refs/remotes/origin/topic")
    pe.expect(["rejected", "new branch"])
    pe.expect(prompt_re)

    # Pushing refspecs
    twofer("cd %s || exit" % qa.strpath)
    twofer("git fetch")
    twofer("echo 'dist: stable' > .qa-ci.dsl")
    pe.sendline("git add -A && git commit -m 'add qa-ci config'")
    pe.expect("1 file changed")
    pe.expect(prompt_re)
    twofer("git config remote.origin.push "
           "refs/heads/master:refs/heads/qa/master")
    pe.sendline("git push")
    pe.expect("new branch.*master.*->.*qa/master")
    pe.expect(prompt_re)
    twofer("git ls-remote --refs")

    # Multi-valued fetch entry
    twofer("cd %s || exit" % dev.strpath)
    twofer("git config remote.origin.fetch "
           "'+refs/heads/master:refs/remotes/origin/master'")
    twofer("git config --add remote.origin.fetch "
           "'+refs/heads/qa/*:refs/remotes/origin/qa/*'")
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


@pytest.mark.skipif(is_27, reason="Python2 must run in subproc")
@pytest.mark.parametrize("create", [False, True], ids=["__", "create"])
@pytest.mark.parametrize("first", [False, True], ids=["__", "first"])
@pytest.mark.parametrize("auth", [False, True], ids=["__", "auth"])
@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_namespaces(server, testdir, create, first, auth, ssl):
    env = {"_USE_NAMESPACES": "1"}
    if create:
        env.update(_CREATE_MISSING="1")
    if first:
        env.update(_FIRST_CHILD_OK="1")
    if auth:
        env.update(_AUTHFILE=server.authfile.strpath)
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    #
    server.start(**env)
    server.consume_log(["*Started serving*"])

    pe = testdir.spawn(server.pe_child_cmd)
    twofer = get_twofer(pe)
    pe.expect(bash_prompt)

    def await_pass(username, passwd):
        pe.expect("Username.*: ?")  # greedy eats https://
        pe.sendline(username)       # ~~~~~~~~~~~~~~~~ ^
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
    twofer("git clone -b master -o upstream {} {}".format(project_url,
                                                          maintainer.strpath))
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
    twofer("git clone -b master -o upstream {} {}".format(maintainer_url,  # <-
                                                          contributor.strpath))
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


@pytest.mark.skipif(is_27, reason="Python2 must run in subproc")
def test_create_ioset(testdir):
    session_dir = testdir.tmpdir.parts()[-2]
    subs = (session_dir.join(d).join("data.pickle").realpath() for
            d in os.listdir(session_dir.strpath)
            if d.startswith("srv-") and d.endswith("current"))
    picks = [d for d in subs if d.exists()]
    if not picks:
        return
    collected = dumper.collect_picks(*picks)
    assert collected

    import json
    with testdir.tmpdir.join("collected.json").open("w") as flow:
        json.dump(collected, flow, indent=2)
