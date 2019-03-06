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
import dumper

from _pytest.pytester import LineMatcher

from pexpect import EOF

bw_script = os.path.join(os.path.dirname(__file__), "bw.sh")


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


def get_twofer(child, prompt=bash_prompt):
    def _twofer(*args, **kwargs):
        child.sendline(*args, **kwargs)
        return child.expect(prompt)
    return _twofer


@pytest.fixture
def server(request, tmpdir_factory):
    if shutil.which("bwrap") is None:
        pytest.fail("Bubblewrap not installed")
    from time import sleep

    name = request._pyfuncitem.name.replace("[", ".").strip("]")
    name = "srv-{}".format(name)
    docroot = tmpdir_factory.mktemp(name, numbered=True)
    docroot.chdir()
    bw_path = docroot.join("bw.sh")
    server_path = docroot.join("emergency_git_server.py").strpath
    shutil.copyfile(emergency_git_server.__file__, server_path)
    if request.config.getoption("dump_dlog"):
        server_path = docroot.join("dumper.py").strpath
        shutil.copyfile(dumper.__file__, server_path)
    shutil.copyfile(bw_script, bw_path)
    bw_path.chmod(0o700)

    class Server:
        proc = None
        port = None
        url = None
        port_pat = re.compile(r"port (\d+)")

        def __init__(self):
            self.rootdir = request.config.rootdir
            self.docroot = docroot
            self.logfile = docroot.join("server.log")
            self.pickfile = docroot.join("data.pickle")
            self._certfile = docroot.join("dummycert.pem")
            self._authfile = docroot.join("auth.json")
            self.openssl_cnf = docroot.join("openssl.cnf")
            self.cmdline = [sys.executable, server_path, docroot.strpath]

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
            try:
                out = subprocess.check_output(
                    [bw_path, "git", "clone", "--bare",
                     repo.join(".git").strpath, name],
                    stderr=subprocess.PIPE,
                    cwd=cwd.strpath, env=env
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
                subprocess.check_call(["openssl", "verify", certstr])
                return True

            if not self.openssl_cnf.exists():
                email = subprocess.check_output(["git",
                                                 "config", "user.email"])
                self.openssl_cnf.write(
                    certconf_source.format(path=certstr, email=email.decode())
                )
            cmdline = ["openssl", "req", "-config",
                       self.openssl_cnf.strpath,
                       "-x509", "-days", "1", "-out", certstr]
            subprocess.check_call(cmdline)
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

    s = Server()
    yield s
    if s.proc:
        s.proc.kill()


@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_receive_with_subdir(server, testdir, ssl):
    env = {}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started serving*"])
    pe = testdir.spawn("bash %s %s" % (bw_script,
                                       str(testdir.request.config.rootdir)))
    pe.expect(r"bash.*\$")
    if ssl:
        pe.sendline("export GIT_SSL_NO_VERIFY=1")
        pe.expect(r"bash.*\$")
    pe.sendline("echo foo > foo.txt")
    pe.expect(r"bash.*\$")
    pe.sendline("git init")
    pe.expect(r"bash.*\$")
    pe.sendline("git add -A && git commit -m 'Init'")
    pe.expect(r"bash.*\$")

    # Repo too shallow
    remote = server.clone(testdir.tmpdir)

    pe.sendline("git remote add origin %s" % remote)
    pe.expect(r"bash.*\$")
    pe.sendline("git config -l")
    pe.expect(r"bash.*\$")
    pe.sendline("git push -u origin master")
    pe.expect(r"fatal")
    server.consume_log(["*WARNING*", "*first child*"])
    pe.expect(r"bash.*\$")

    # Right depth
    remote = server.clone(testdir.tmpdir, "repos")

    pe.sendline("git remote set-url origin %s" % remote)
    pe.expect(r"bash.*\$")
    pe.sendline("git config -l")
    pe.expect(r"bash.*\$")
    pe.sendline("git push -u origin master")
    pe.expect("up-to-date")
    server.consume_log("*GET*repos*200*")
    pe.expect(r"bash.*\$")

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_receive_first_child(server, testdir, ssl):
    env = {"_FIRST_CHILD_OK": "1"}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    server.start(**env)
    server.consume_log(["*Started serving*"])
    pe = testdir.spawn("bash %s %s" % (bw_script,
                                       str(testdir.request.config.rootdir)))
    pe.expect(r"bash.*\$")
    if ssl:
        pe.sendline("export GIT_SSL_NO_VERIFY=1")
        pe.expect(r"bash.*\$")
    pe.sendline("echo foo > foo.txt")
    pe.expect(r"bash.*\$")
    pe.sendline("git init")
    pe.expect(r"bash.*\$")
    pe.sendline("git add -A && git commit -m 'Init'")
    pe.expect(r"bash.*\$")

    remote = server.clone(testdir.tmpdir)

    pe.sendline("git remote add origin %s" % remote)
    pe.expect(r"bash.*\$")
    pe.sendline("git config -l")
    pe.expect(r"bash.*\$")
    pe.sendline("git push -u origin master")
    pe.expect("up-to-date")
    server.consume_log("*GET /test_receive_first_child*200*")
    pe.expect(r"bash.*\$")

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


@pytest.mark.parametrize("ssl", [False, True], ids=["__", "ssl"])
def test_receive_create_missing(server, testdir, ssl):
    env = {}
    if ssl:
        env.update(_CERTFILE=server.certfile.strpath)
    # No envvar
    server.start(**env)
    server.consume_log(["*Started serving*"])

    pe = testdir.spawn("bash %s %s" % (bw_script,
                                       str(testdir.request.config.rootdir)))
    pe.expect(r"bash.*\$")

    if ssl:
        pe.sendline("export GIT_SSL_NO_VERIFY=1")
        pe.expect(r"bash.*\$")
    pe.sendline("echo foo > foo.txt")
    pe.expect(r"bash.*\$")
    pe.sendline("git init")
    pe.expect(r"bash.*\$")
    pe.sendline("git add -A && git commit -m 'Init'")
    pe.expect(r"bash.*\$")
    url = "{}/repos/test_receive_create_missing.git".format(server.url)
    pe.sendline("git remote add origin {}".format(url))
    pe.expect(r"bash.*\$")
    pe.sendline("git config -l")
    pe.expect(r"bash.*\$")
    pe.sendline("git push -u origin master")
    pe.expect("fatal")
    server.consume_log(["*GET*403*", "*_CREATE_MISSING*"])
    pe.expect(r"bash.*\$")
    assert server.stop() == 0
    server.truncate_log()

    # Add envvar
    server.start(_CREATE_MISSING="1", **env)
    server.consume_log(["*Started serving*"])

    pe.sendline("git push -u origin master")
    pe.expect("new branch")
    server.consume_log(["*GET*repos/*200*", "*POST*/repos/*200*"])
    pe.expect(r"bash.*\$")

    pe.sendline("exit")
    pe.expect(EOF)
    assert server.stop() == 0


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

    pe = testdir.spawn("bash %s %s" % (bw_script,
                                       str(testdir.request.config.rootdir)))
    twofer = get_twofer(pe)

    pe.expect(r"bash.*\$")
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
        pe.expect(r"bash.*\$")
    else:
        clone_rv = server.clone(dev, upath)
        assert clone_rv == url
        twofer("git fetch")
        twofer("git branch -u origin/master master")
    pe.sendline("git ls-remote")
    pe.expect(r"refs/heads/master")
    pe.expect(r"bash.*\$")

    # Others join
    ops = testdir.tmpdir.join("ops")
    qa = testdir.tmpdir.join("qa")
    twofer("git clone {} {}".format(url, ops.strpath))
    twofer("git clone {} {}".format(url, qa.strpath))

    # Develop
    pe.sendline("git checkout -b topic")
    pe.expect(".*new branch.*topic.*")
    pe.expect(r"bash.*\$")
    pe.sendline("mkdir src && "
                "echo '#ifndef NUMS_H\n#define NUMS_H\n' > src/nums.h && "
                "git add -A && git commit -m 'Begin nums'")
    pe.expect("1 file changed")
    pe.expect(r"bash.*\$")
    pe.sendline("git push -u origin topic")
    pe.expect(".*new branch.*topic.*")
    pe.expect(r"bash.*\$")
    pe.sendline("git checkout master && git merge topic")
    pe.expect("1 file changed")
    pe.expect(r"bash.*\$")
    pe.sendline("git push")
    pe.expect("master -> master")
    pe.expect(r"bash.*\$")

    # One-off fetching
    twofer("cd ../ops || exit")
    # Note: this is different from master:mymaster, which would create a new
    # local branch named mymaster (remote ref is LHS)
    twofer("git branch -vr")
    pe.sendline("git fetch origin master:refs/remotes/origin/mymaster")
    pe.expect(["master *-> *origin/mymaster",
               "master *-> *origin/master"])
    pe.expect(r"bash.*\$")
    twofer("git branch -vr")

    # Dev rewrites shared history
    twofer("cd %s || exit" % dev.strpath)
    twofer("echo 'TODO:\n- finish nums' >> README.md")
    pe.sendline("git add -A && git commit --amend -C @")
    pe.expect("2 files changed")
    pe.expect(r"bash.*\$")
    pe.sendline("git push --force")
    pe.expect("forced update")
    pe.expect(r"bash.*\$")

    # Rejected fetch
    twofer("cd %s || exit" % ops.strpath)
    pe.sendline("git fetch origin master:refs/remotes/origin/mymaster \\\n"
                "topic:refs/remotes/origin/topic")
    pe.expect(["rejected", "new branch"])
    pe.expect(r"bash.*\$")

    # Pushing refspecs
    twofer("cd %s || exit" % qa.strpath)
    twofer("git fetch")
    twofer("echo 'dist: stable' > .qa-ci.dsl")
    pe.sendline("git add -A && git commit -m 'add qa-ci config'")
    pe.expect("1 file changed")
    pe.expect(r"bash.*\$")
    twofer("git config remote.origin.push "
           "refs/heads/master:refs/heads/qa/master")
    pe.sendline("git push")
    pe.expect("new branch.*master.*->.*qa/master")
    pe.expect(r"bash.*\$")
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
    pe.expect(r"bash.*\$")
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

    pe = testdir.spawn("bash %s %s" % (bw_script,
                                       str(testdir.request.config.rootdir)))
    twofer = get_twofer(pe)
    pe.expect(bash_prompt)

    def await_pass(username, passwd):
        pe.expect("Username.*: ?")  # greedy eats https://
        pe.sendline(username)       # ~~~~~~~~~~~~~~~~ ^
        pe.expect("Password.*: ?")
        pe.sendline(passwd)

    if ssl:
        pe.sendline("export GIT_SSL_NO_VERIFY=1")
        pe.expect(r"bash.*\$")

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
