import pytest
from conftest import is_27


def test_boolify_envvar():
    from emergency_git_server import _boolify_envvar

    assert _boolify_envvar(None) is False

    for v in ("", "None", "null"):
        assert _boolify_envvar(v) is True

    for v in "false nil no off 0 False Nil No Off".split():
        assert _boolify_envvar(v) is False


def test_set_ssl_context(tmpdir):
    from emergency_git_server import set_ssl_context

    fake = "/tmp/___fake/somefile"
    certfile = tmpdir.join("cert.pem")
    keyfile = tmpdir.join("key.pem")
    dhpfile = tmpdir.join("dhparams")

    keyfile.write("")
    dhpfile.write("")

    assert set_ssl_context(certfile.strpath, fake, fake) is None
    assert set_ssl_context(certfile.strpath, fake, dhpfile) is None
    assert set_ssl_context(certfile.strpath, keyfile, dhpfile) is None

    try:
        from unittest.mock import patch, Mock
    except ImportError:  # 27
        from mock import patch, Mock

    certfile.write(
        "zDJpxEFgCYcydw==\n"
        "-----END PRIVATE KEY-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "foo"
    )

    with patch("ssl.create_default_context") as m_cdc:
        context = Mock()
        m_cdc.return_value = context
        assert set_ssl_context(certfile.strpath, None, None)
        context.load_cert_chain.assert_called_with(certfile.strpath, None)

        assert set_ssl_context(certfile.strpath, None, dhpfile.strpath)
        context.load_dh_params.assert_called_with(dhpfile.strpath)

    certfile.write(
        "-----BEGIN CERTIFICATE-----\n" "foo\n" "-----END CERTIFICATE-----\n"
    )

    with pytest.raises(RuntimeError):
        assert set_ssl_context(certfile.strpath, None, None)

    certfile.write(
        "-----BEGIN CERTIFICATE-----\n"
        "foo\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "bar\n"
        "-----END PRIVATE KEY-----\n"
    )

    with pytest.raises(RuntimeError):
        assert set_ssl_context(certfile.strpath, None, None)


@pytest.fixture
def safe_debug():
    import emergency_git_server

    orig = emergency_git_server.config["DEBUG"]
    try:
        yield
    finally:
        emergency_git_server.config["DEBUG"] = orig


def test_dlog(safe_debug):
    from conftest import is_27
    import emergency_git_server

    class Fake(object):
        last = None
        dlog = emergency_git_server.HTTPBackendHandler.dlog
        if is_27:

            def __init__(self):
                self.dlog = Fake.dlog.__get__(self)

        def log_message(self, thing):
            self.last = thing

    fake = Fake()

    assert emergency_git_server.config["DEBUG"] is False
    with pytest.raises(RuntimeError):
        fake.dlog("foo")

    emergency_git_server.config["DEBUG"] = True
    fake.dlog("foo")
    assert fake.last == "test_dlog() - foo"

    spam = "abc"
    something = 1

    fake.dlog("bar", spam=spam, something=something)
    from textwrap import dedent

    src = """
        test_dlog() - bar
          spam:      'abc'
          something: 1
    """
    if is_27:
        src1 = dedent(src).strip()
        a, b, c = src1.splitlines()
        src2 = "\n".join([a, c, b])
        assert fake.last in (src1, src2)
    else:
        assert dedent(src).strip() == fake.last


srv_src = r"""
from __future__ import print_function
import sys
from emergency_git_server import (
    config, register_signals, CGIHTTPRequestHandler, HTTPServer
)
config['DEBUG'] = True

address = ('localhost', 8000)
server = HTTPServer(address, CGIHTTPRequestHandler)
register_signals(server, ("INT", "TERM"), ("TSTP",))
print('ready', file=sys.stderr)
sys.stderr.flush()
server.serve_forever()

"""


def test_register_signals(testdir, request):
    import sys
    import time
    import signal
    import subprocess
    import emergency_git_server

    mod = type(testdir.tmpdir)(emergency_git_server.__file__)
    assert request.config.rootdir.strpath == mod.dirname
    env = None
    # XXX unsure why bad encoding when copying byte for byte in py27
    # For now, hack path instead
    if is_27:
        import os
        env = dict(os.environ)
        env.update(PYTHONPATH=mod.dirname)
    else:
        target = testdir.tmpdir / "emergency_git_server.py"
        mod.copy(target)

    testdir.makepyfile(serve=srv_src)
    proc = subprocess.Popen(
        [sys.executable, "serve.py"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env
    )
    import select

    def genny():
        line = yield
        assert line == b"ready\n"
        time.sleep(0.1)
        proc.send_signal(signal.SIGTSTP)
        line = yield
        assert b"Received SIGTSTP" in line
        assert b"Ignoring" in line
        proc.send_signal(signal.SIGTERM)
        line = yield
        assert b"Received SIGTERM" in line
        assert b"Quitting" in line
        assert b"successfully closed" in line

    expect = genny()
    next(expect)
    while True:
        if select.select([proc.stderr], [], [], 0)[0]:
            if is_27:
                chunk = os.read(proc.stderr.fileno(), 1024)
            else:
                chunk = proc.stderr.read1(1024)
            try:
                expect.send(chunk)
            except StopIteration:
                break
        else:
            time.sleep(0.1)

    if is_27:
        proc.wait()
    else:
        proc.wait(timeout=1)
    assert proc.returncode == 0
