import pytest


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

    certfile.write("zDJpxEFgCYcydw==\n"
                   "-----END PRIVATE KEY-----\n"
                   "-----BEGIN CERTIFICATE-----\n"
                   "foo")

    with patch("ssl.create_default_context") as m_cdc:
        context = Mock()
        m_cdc.return_value = context
        assert set_ssl_context(certfile.strpath, None, None)
        context.load_cert_chain.assert_called_with(certfile.strpath, None)

        assert set_ssl_context(certfile.strpath, None, dhpfile.strpath)
        context.load_dh_params.assert_called_with(dhpfile.strpath)

    certfile.write("-----BEGIN CERTIFICATE-----\n"
                   "foo\n"
                   "-----END CERTIFICATE-----\n")

    with pytest.raises(RuntimeError):
        assert set_ssl_context(certfile.strpath, None, None)

    certfile.write("-----BEGIN CERTIFICATE-----\n"
                   "foo\n"
                   "-----END CERTIFICATE-----\n"
                   "-----BEGIN PRIVATE KEY-----\n"
                   "bar\n"
                   "-----END PRIVATE KEY-----\n")

    with pytest.raises(RuntimeError):
        assert set_ssl_context(certfile.strpath, None, None)
