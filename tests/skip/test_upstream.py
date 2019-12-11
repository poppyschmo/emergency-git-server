# Some comments in standard-lib modules suggest changes to header-related
# classes. With 27's EOL, we need CI/CD to keep us informed.
from io import BytesIO

from conftest import ensure_crlf, is_27

try:
    from unittest.mock import Mock
except ImportError:
    assert is_27
    from mock import Mock  # noqa: F811

src_1 = b"""
POST / HTTP/1.1
Host: localhost:4443
Authorization: Basic Y29udHJpYnV0b3I6cGFzc3dvcmQxMjM=
User-Agent: git/2.23.0
Accept: */*
Accept-Encoding: deflate, gzip, br
Accept-Language: en-US, *;q=0.9
Content-Length: 7
Content-Type: application/x-www-form-urlencoded
Pragma: no-cache

foo=bar
"""


def test__populate_vanilla_envvars(tmpdir):
    from emergency_git_server import HTTPBackendHandler as Handler

    src = ensure_crlf(src_1)
    inst = Mock()
    buf = BytesIO(src)

    if is_27:
        import mimetools
        assert Handler.MessageClass is mimetools.Message
        # Signature: (self, fp, seekable = 1)
        inst.headers = Handler.MessageClass(buf, 0)
        assert not hasattr(inst.headers, "get_content_type")
        assert hasattr(inst.headers, "typeheader")
        assert hasattr(inst.headers, "type")

        line2 = src.index(b"Host")
        assert int(buf.tell()) == line2  # same w. real disk file
        assert buf.read(1) == src[line2]

    else:
        import http.client
        assert Handler.MessageClass is http.client.HTTPMessage
        inst.headers = http.client.parse_headers(buf, Handler.MessageClass)
        assert hasattr(inst.headers, "get_content_type")

        assert buf.tell() == src.index(b"foo")
        assert buf.read() == b"foo=bar"
