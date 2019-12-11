#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Usage::
\x0c
    python3 emergency_git_server.py [DOCROOT]

        DOCROOT
            Path to root URI exposed by server, commonly /var/www/html;
            defaults to current working directory; repo names must end
            in dot git, e.g., /var/www/html/repos/foo.git


    Environment options:

        GITSRV_PREFIX <str>
            Prefix for the following env vars; defaults to _ (shown)

        _HOST <hostname>
            IP address or hostname; defaults to localhost

        _PORT <port>
            Port number; defaults to 8000 (may need to be above 1023)

        _LOGFILE <path>
            Redirect all server messages (from standard error) to path;
            <path> need not exist and is truncated at startup

        _DEBUG
            Print verbose logging info for every request/response

        _ALLOW_CREATION
            Allow initializing of bare repo via POST; defaults to true.
            Response is 201 on success::

            $ curl --data init=1 http://localhost:8000/git_root/myrepo.git

            As with existing repos, these must end in ".git".  Note: HEAD is
            currently left unset.

        _USE_NAMESPACES
            Interpret non-existent path components between DOCROOT/real
            and the target repo (exclusive) as $GIT_NAMESPACE, e.g.,
            /var/www/html/git_root/$GIT_NAMESPACE/myrepo.git; see
            gitnamespaces(7)

        _AUTHFILE <path|str>
            Enforce "basic access" authentication. This can either be an
            absolute path to a .json file or a stringified json-style
            "object" with these fields:
            {
              "/some/path/below/docroot": {
                "description": STR, optional message for realm challenge
                "secretsfile": STR, required abs path to .htpasswd-like file
                "privaterepo": BOOL, optional; deny public read access
              }, ...
            }

        _CERTFILE <path>
            Path to an x509 cert in PEM format or a combined cert plus RSA
            key (which must appear first). If the path is valid, the server
            will listen on port 4443 (if PORT is 8000 or not specified).
            Note: certificate chains must end with a root cert.

        _KEYFILE <path>
            Path to a valid RSA key in PEM format. If absent, CERTFILE must
            contain the key.

        _DHPARAMS <path>
            Path to an optional DH parameter file, also in PEM format.
\x0c

Notes
-----

This is a minimal, sequential, "single-serving" Git server geared toward
emergency use, ad hoc experimentation, and basic Git education. General use is
strongly discouraged, not least because of a total lack of attention paid to
matters of security and performance.

While it's possible, say, to run this behind a reverse proxy for more legit
auth/auth and TLS, it's better to opt for a real server like cgit, which is
just a ``docker-run`` away.


Dealing with git-http-backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following should be of no interest to most users.  Confusingly, Git's
client-side commands utilize at least two different URL request syntaxes re CGI
scripts.

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

.. _spec: http://www.ietf.org/rfc/rfc3875
.. _git-http-backend: https://github.com/git/git
   /Documentation/git-http-backend.txt

"""

# Author: Jane Soko
# License: Apache License 2.0
# Portions derived from Python modules may apply other terms.
# See <https://docs.python.org/3.5/license.html> for details.
#
# TODO remove USE_NAMESPACES in favor of a namespace=foo field for
# repo-init requests (creating an empty refs/namespaces directory)
#
# TODO simplify auth handling and follow web standards
#
# TODO All HTTPStatus codes are naively assigned and largely misapplied. Use
# official IANA RFC when revising.

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import

import os
import sys
import json
import select

from subprocess import check_output, Popen, PIPE, CalledProcessError

if sys.version_info < (3, 0):
    import httplib as HTTPStatus
    from future_builtins import filter
    from CGIHTTPServer import CGIHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
else:
    from http import HTTPStatus
    from http.server import CGIHTTPRequestHandler, HTTPServer

__version__ = "0.0.8"

config = {
    "DOCROOT": "/tmp/__fake__",
    "HOST": "localhost",
    "PORT": 8000,
    "LOGFILE": None,
    "AUTHFILE": None,
    "DEBUG": False,
    "ALLOW_CREATION": True,
    "USE_NAMESPACES": False,
    "CERTFILE": None,
    "KEYFILE": None,
    "DHPARAMS": None,
}


def get_libexec_dir():
    """Return path to dir containing Git plumbing exes"""
    out_path = None
    #
    try:
        out_path = check_output(("git", "--exec-path"))
    except CalledProcessError:
        out_path = "/usr/libexec/git-core"
    except FileNotFoundError:
        try:
            out_path = check_output("command -p git --exec-path".split())
        except FileNotFoundError:
            print(
                "Could not locate primary git program in $PATH",
                file=sys.stderr,
            )
            raise
    else:
        out_path = out_path.decode().strip()
    return out_path


def get_auth_dict(authfile):
    if authfile is None:
        return {}
    if os.path.exists(authfile):
        with open(authfile) as f:
            outdict = json.load(f)
    else:
        outdict = json.loads(authfile)
    return outdict


def url_collapse_path(uripath):
    """Mimic standard lib's _url_collapse_path() but return a tuple

    That is, a tuple of path, trailing slash, everything else (query and
    fragment).

    The only other difference is that the path component will have at
    most one leading slash. The upstream namesake double-prepends leading
    slashes for slug-only paths (leafs), even when they start with a slash, so
    "/foo.git" and "foo.git" both become "//foo.git".

    """
    import posixpath
    try:
        from urllib.parse import unquote
    except ImportError:
        from urllib import unquote

    # No catch, *all, destructuring in py27
    path, sep, rest = uripath.partition('?')
    if not any((sep, rest)):
        path, sep, rest = path.partition('#')

    trailing_slash = "/" if path.rstrip().endswith('/') else ""

    try:
        path = unquote(path, errors='surrogatepass')
    except (UnicodeDecodeError, TypeError):
        path = unquote(path)
    path = posixpath.normpath(path)

    return (path, trailing_slash, "".join((sep, rest)))


def translate_path(basedir, uripath):
    """Interpret URI path as fs path under basedir, return abspath.

    See ``http.server.SimpleHTTPRequestHandler.translate_path``

    This is from the 3.7 version but uses explicit arg basedir instead
    of the current directory.

    """
    assert os.path.isabs(basedir)
    path, trailing_slash, _ = url_collapse_path(uripath)

    words = (
        w for w in path.split('/') if
        w
        and not os.path.dirname(w)  # doesn't contain a /
        and w not in (os.curdir, os.pardir)  # and is not . or ..
    )
    path = os.path.join(basedir, *words)
    if trailing_slash:
        path += os.path.sep
    return path


def is_repo(abspath):
    """Predicate returning true if abspath is a GITDIR"""
    if os.path.isfile(os.path.join(abspath, "HEAD")) or os.path.isdir(
        os.path.join(abspath, "refs", "heads")
    ):
        return True
    return False


def find_git_root(docroot, target):
    """Return relative subpath below docroot and above target"""
    out = []
    for part in target.split("/"):
        if not part:
            continue
        sofar = os.path.join(docroot, *out)
        maybe = os.path.join(sofar, part)  # 27 can't do: *foo, bar
        if not os.path.exists(maybe):  # skip phantom ns components
            continue
        if is_repo(maybe):
            break
        out.append(part)
    return "/".join(out)


def _find_namespaces(env, config):
    """Update env dict with namespace info"""
    parts = iter(env["PATH_INFO"].split("/"))
    ns = []
    for part in parts:
        if not part:
            continue
        if part.endswith(".git") or is_repo(
            os.path.join(env["GIT_PROJECT_ROOT"], part)
        ):
            break
        ns.append(part)
    parts = list(parts)
    if ns:
        assert all(parts), locals()
        env["GIT_NAMESPACE"] = "/".join(ns)
    env["PATH_INFO"] = "/".join(["", part] + parts)


def determine_env_vars(docroot, verb, target, **config):
    """Return dict of env vars needed by git-http-backend

    Assume target is in "origin-form" as described by
    https://tools.ietf.org/html/rfc7230#section-5.3.1

    Note: this function was machine-generated and cleaned up. It's
    not worth trying to follow; just treat it like a black box.
    """
    assert docroot.startswith("/") and not docroot.endswith("/")
    gitroot = find_git_root(docroot, target)
    assert not gitroot.startswith("/")
    assert target.lstrip("/").startswith(gitroot), locals()
    env = {}
    env["GIT_PROJECT_ROOT"] = (
        os.path.join(docroot, gitroot) if gitroot else docroot
    )
    assert not env["GIT_PROJECT_ROOT"].endswith("/"), locals()

    path, maybe_qmark, query = target.partition("?")
    if verb == "GET":
        assert maybe_qmark == "?"
        env["QUERY_STRING"] = query
        assert query in ("service=git-receive-pack", "service=git-upload-pack")
        repo = path
    else:
        assert verb == "POST"
        env["QUERY_STRING"] = ""
        repo, exename = os.path.split(path)
        assert exename == "git-receive-pack" or exename == "git-upload-pack"

    assert any(c.endswith(".git") for c in repo.split("/")), locals()

    env["PATH_INFO"] = path.replace("/" + gitroot, "", 1) if gitroot else path

    if config.get("USE_NAMESPACES") is True:
        _find_namespaces(env, config)

    env["PATH_TRANSLATED"] = "/".join(
        (env["GIT_PROJECT_ROOT"], env["PATH_INFO"].lstrip("/"))
    )
    if any(
        env["PATH_TRANSLATED"].endswith(s)
        for s in ("/info/refs", "/git-upload-pack", "/git-receive-pack")
    ):
        assert os.path.exists(os.path.dirname(env["PATH_TRANSLATED"]))
    else:
        assert os.path.exists(env["PATH_TRANSLATED"]), locals()
    return env


def is_ghb_bound(command, path):
    """Return whether path is destined for git-http-backend"""

    if command == "GET":
        tails = (
            "/info/refs?service=git-upload-pack",
            "/info/refs?service=git-receive-pack",
        )
        return any(path.endswith(t) for t in tails)

    assert command == "POST"
    return any(
        path.endswith(t) for t in ("git-upload-pack", "git-receive-pack")
    )


def create_repo_from_uri(abspath):
    """Ensure dirpath and call git-init

    Caller should catch exceptions and inform client of success or
    failure.
    """
    assert abspath.endswith(".git"), locals()
    try:
        # Assume mode is set according to umask
        os.makedirs(abspath)
    except Exception as err:
        try:
            if not isinstance(err, FileExistsError):
                raise
        except NameError:  # 2.7
            if not isinstance(err, OSError) or err.errno != os.errno.EEXIST:
                raise
    # See notes on evolving meaning of os.makedirs kwarg exist_ok
    # https://docs.python.org/3.8/library/os.html#os.makedirs
    if len(os.listdir(abspath)) != 0:
        raise RuntimeError("Leaf not empty: %s" % abspath)
    return check_output(("git", "-C", abspath, "init", "--bare"))


def verify_pass(saved, received):
    """Attempt to compare .htpasswd file entry to the sent password

    The only supported formats are unix crypt(3) and sha1. Both args
    must be strings.
    """
    if saved.startswith("$apr1"):
        salt = saved.split("$")[2]
        # Allow CalledProcessError to propagate
        args = ["openssl", "passwd", "-apr1", "-salt", salt, received]
        checked = check_output(args)
        if checked.decode().strip() == saved:
            return True
    elif saved.startswith("{SHA}"):
        import base64
        import hashlib

        binpass = saved.partition("{SHA}")[-1].encode()
        binpass = base64.b64decode(binpass)
        if hashlib.sha1(received.encode()).digest() == binpass:
            return True
    # TODO maybe accept $2b METHOD_BLOWFISH
    elif len(saved) == 13:
        import crypt

        if crypt.crypt(received, saved[:2]) == saved:
            return True
    return False


class TlsServer(HTTPServer, object):
    """SSL-aware HTTPServer.

    This uses standard per-request wrapping rather than wrapping the
    bound listen socket as an instance attribute prior to starting the
    loop. The latter approach actually seems to work just as well, but
    this mimics the example given in the docs_. Would be nice to get rid
    of this class, though.

    BTW, that example also uses ``socket.SHUT_RDWR`` instead of the
    write-only variant, used here.  But read-write seems to trigger "bad
    FD" errors during error handling.

    .. _docs: https://docs.python.org/3.6/library
       /ssl.html#server-side-operation
    """

    def __init__(self, server_address, RequestHandlerClass, context=None):
        self.ssl_context = context
        super(TlsServer, self).__init__(
            server_address, RequestHandlerClass, bind_and_activate=True
        )

    def _handle_request_noblock(self):
        """No idea how this really works. See superclass docstring.
        """
        try:
            request, client_address = self.get_request()
        except OSError:
            return
        if self.verify_request(request, client_address):
            try:
                if self.ssl_context:
                    try:
                        request = self.ssl_context.wrap_socket(
                            request, server_side=True
                        )
                    except Exception as e:
                        import ssl

                        # Usually means client hasn't okay'd self-signed certs
                        if isinstance(e, ssl.SSLError):
                            print("%r" % e, file=sys.stderr)
                            self.shutdown_request(request)
                            return
                        else:
                            raise
                    else:
                        if (
                            config["DEBUG"]
                            and self.RequestHandlerClass.cipher is None
                        ):
                            self.RequestHandlerClass.cipher = request.cipher()
                self.process_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            except:  # noqa: E722
                self.shutdown_request(request)
                raise
        else:
            self.shutdown_request(request)
        #
        # XXX workaround for the lack of a ``service_actions()`` hook in 2.7's
        # ``serve_forever`` loop. Unsure how safe this is. Unlike in py3, this
        # doesn't run between selector poll intervals (when fd is busy).
        if not hasattr(HTTPServer, "service_actions") and hasattr(
            self, "service_actions"
        ):
            self.service_actions()


class HTTPBackendHandler(CGIHTTPRequestHandler, object):
    """A CGI handler for git-http-backend"""

    docroot = None
    auth_dict = None
    git_exec_path = None
    has_openssl = None
    cipher = None

    def __init__(self, *args, **kwargs):
        self.docroot = config["DOCROOT"]
        self.git_exec_path = get_libexec_dir()
        self.auth_dict = get_auth_dict(config["AUTHFILE"])
        self.auth_env = {}
        super(HTTPBackendHandler, self).__init__(*args, **kwargs)

    def dlog(self, tag, **kwargs):
        """Print one k/v pair per line below standard heading

        Calls. ``.log_message`` to do the actual printing.

        """
        if config["DEBUG"] is not True:
            raise RuntimeError("DEBUG is OFF but dlog called")
        caller = sys._getframe().f_back.f_code.co_name
        first = "{}()".format(caller)
        if tag:
            first = "{} - {}".format(first, tag)
        out = [first]
        if kwargs:
            maxlen = max(len(k) for k in kwargs) + 1
            out += [
                "{:2}{:<{w}} {!r}".format("", "%s:" % k, v, w=maxlen)
                for k, v in kwargs.items()
            ]
        self.log_message("\n".join(out))

    def consume_and_exhaust(self, length=None):
        """Return up to length bytes from remote and discard the rest.
        """
        if length is None:
            length = int(self.headers.get("content-length"))
        data = self.rfile.read(length)
        # Bad content-length? (see comment in CGIHTTPRequestHandler.run_cgi)
        while select.select([self.rfile._sock], [], [], 0)[0]:
            if not self.rfile._sock.recv(1):
                break
        return data

    def _joined(self, path):
        abspath = translate_path(self.docroot, path)
        compre = os.path.commonprefix((self.docroot, abspath))
        assert compre == self.docroot
        return abspath

    def _send_header_only(self, code, message):
        """Send header with no body"""
        self.send_response(code, message)
        self.end_headers()
        if hasattr(self, "flush_headers"):
            self.flush_headers()

    def log_exception(self, msg=None):
        import traceback
        formatted = traceback.format_exc()
        self.log_error("%s\n%s" % (msg, formatted) if msg else formatted)

    def maybe_create_repo(self):
        """Init repo if non-cgi POST seems legit

        Return True if successful, False otherwise.

        Intervening path components are created if they don't already
        exist.
        """
        assert self.path.endswith(".git") and len(self.path) > 5

        request_body = self.consume_and_exhaust()  # -> bytes

        abspath = self._joined(self.path)
        config["DEBUG"] and self.dlog(
            "read", request_body=request_body, abspath=abspath
        )
        contype = self.headers.get("content-type").lower()

        def bail():
            if os.path.exists(abspath):
                msg = (HTTPStatus.BAD_REQUEST, "Invalid content")
            else:
                msg = (HTTPStatus.NOT_FOUND, "Repo does not exist")
            self.send_error(*msg)

        if "json" in contype:
            data = json.loads(request_body)
            if data.get("init") != 1:
                bail()
                return False
        if "form" in contype:
            # pointless
            if "urlencoded" in contype:
                try:
                    from urllib.parse import unquote_plus
                except ImportError:
                    from urllib import unquote_plus
                request_body = unquote_plus(request_body.decode())
            if "init=1" not in request_body:
                bail()
                return False

        try:
            _stdout = create_repo_from_uri(abspath)
        except Exception:
            self.log_exception("E: Problem creating repo")
            self.send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR, "Problem creating repo"
            )
            return False

        config["DEBUG"] and self.dlog(
            "git-init", stdout=_stdout, new_repo=abspath
        )
        self._send_header_only(HTTPStatus.CREATED, "Successfully created repo")
        return True

    def is_cgi(self):
        """Check if request is destined for git-http-backend

        Return True if caller should call run_cgi, False otherwise

        If user wishes to restrict GET requests to git ops only,
        collapsed path must match regexp

        """

        if self.git_env:
            return True
        return False

    def _get_htpasswd_info(self, lines):
        """Given .htpasswd lines, return dict of user/pass k/v pairs"""
        secdict = {}
        for line in lines:
            if ":" not in line:
                continue
            u, p = line.split(":")
            if p.startswith("$apr1") and self.has_openssl is None:
                try:
                    check_output(("openssl", "version"))
                except (FileNotFoundError, CalledProcessError):
                    self.log_error("E: required openssl exe not found")
                    self.has_openssl = False
                    raise
                else:
                    self.has_openssl = True
            elif p.startswith("$2y"):
                msg = "E: bcrypt support requested but not found"
                self.log_error(msg)
                raise RuntimeError(msg)
            secdict[u.strip()] = p.strip()
        return secdict

    def handle_auth(self):
        """Return True if authorized or False to close connection

        Return True when (1) authorization doesn't apply to a particular
        protection space or (2) credentials check out. Otherwise, respond with
        UNAUTHORIZED (or more relevant error) and return False.

        https://tools.ietf.org/html/rfc7235
        """
        # NOTE: if messing with path, beware that ``send_head`` will eventually
        # get called for GET and HEAD requests. The base method requires a
        # trailing slash for dirs below DOCROOT, if an html directory listing
        # (web page) is to be generated and returned. Otherwise, it responds
        # with a 301 MOVED_PERMANENTLY.
        self.auth_env.clear()

        if not self.auth_dict:
            return True
        elif not sys.platform.startswith("linux"):
            raise RuntimeError("Auth options are Linux only")

        # For GHB-related requests, this will end with query or fake leaf
        collapsed_path = "".join(url_collapse_path(self.path))

        for maybe_restricted_path, realm_info in self.auth_dict.items():
            maybe_restricted_path = maybe_restricted_path.rstrip("/")
            if (
                collapsed_path == maybe_restricted_path
                or collapsed_path.startswith(maybe_restricted_path + "/")
            ):
                break
        else:
            return True

        # Allow fetching from protected GHB-related realms that aren't private
        if (
                is_ghb_bound(self.command, self.path)
                and not realm_info.get("privaterepo")
                and not collapsed_path.endswith("git-receive-pack")
        ):
            assert collapsed_path.endswith("git-upload-pack"), locals()
            return True

        description = realm_info.get("description", "Basic auth requested")

        try:
            secretsfile = realm_info.get("secretsfile")
            with open(secretsfile) as f:
                secretlines = f.readlines()
            secdict = self._get_htpasswd_info(secretlines)
        except Exception:
            self.log_exception("E: Problem reading .htpasswd file")
            self.send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "Application error looking up auth",
            )
            return True

        authorization = self.headers.get("authorization")

        # Prompt user to supply auth
        if not authorization:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header(
                "WWW-Authenticate", 'Basic realm="%s"' % description
            )
            self.end_headers()
            self.wfile.flush()
            return False

        authorization = authorization.split()

        try:
            authtype, authval = authorization
        except Exception:
            self.log_exception("E: Problem parsing authorization")
            self.send_error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "Problem reading authorization",
            )
            return False

        if authtype.lower() != "basic":
            msg = "Auth type %r not supported!" % authtype
            self.send_error(HTTPStatus.BAD_REQUEST, msg)
            return False

        self.auth_env["AUTH_TYPE"] = authtype
        import base64
        import binascii

        try:
            authorization = base64.b64decode(authval.encode("ascii"))
            username, password = authorization.decode("ascii").split(":")
        except (binascii.Error, UnicodeError):
            pass
        else:
            config["DEBUG"] and self.dlog("auth", authorization=authorization)
            if verify_pass(secdict[username], password):
                self.auth_env["REMOTE_USER"] = username
                return True

        self.send_error(HTTPStatus.UNAUTHORIZED, "No permission")
        return False

    def parse_request(self):
        """Populate git_env attr for git requests

        Otherwise check auth, if necessary.  Only return False after
        sending error (if base method's rv is False, assume it already
        did so).
        """
        rv = super(HTTPBackendHandler, self).parse_request()
        self.git_env = None

        if rv is not True:
            return rv

        if config["DEBUG"]:
            self.dlog("top", **dict(vars(self)))
            self.dlog("headers", **self.headers)

        if self.handle_auth() is not True:
            # Error message already sent, so tell caller to close connection
            return False

        # Allow SimpleHTTPRequestHandler to attempt fulfilling request
        if not is_ghb_bound(self.command, self.path):
            if self.command == "POST":
                if self.path.endswith(".git"):
                    self.maybe_create_repo()
                else:
                    msg = "Non-git POST only allowed when creating new repos"
                    self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, msg)
                return False
            return True

        # This is a CGI request meant for git-http-backend, but is the path
        # valid? If so, populate self.git_env so interested do_* methods know.
        result = {}
        try:
            result = determine_env_vars(
                self.docroot, verb=self.command, target=self.path, **config
            )
        except Exception:
            self.log_exception("E: Problem parsing path")
            msg = HTTPStatus.INTERNAL_SERVER_ERROR, "Problem parsing path"
            self.send_error(*msg)
            return False

        config["DEBUG"] and self.dlog("determine_env_vars()", **result)

        try:
            from types import MappingProxyType
        except ImportError:
            self.git_env = result
        else:
            self.git_env = MappingProxyType(result)

        return True

    def _populate_envvars(self):
        """Return CGI-related env vars

        Mostly straight from ``CGIHTTPRequestHandler.run_cgi``.
        This takes request header fields and parsed-path info and
        sets env vars required by rfc3875_ and some HTTP ones.

        .. _rfc3875: https://tools.ietf.org/html/rfc3875#section-4.1
        """
        full_env = dict(os.environ)

        # As required by git-http-backend(1); These never change.
        cgi_env = dict(self.git_env)
        cgi_env["GIT_HTTP_EXPORT_ALL"] = ""

        cgi_env.update(self.auth_env)
        # FIXME previous comment said, "Fallback for when auth isn't used,"
        # but that implies auth is mandatory, which it's not
        if self.path.endswith("git-receive-pack"):
            cgi_env.setdefault("REMOTE_USER", full_env.get("USER", "nobody"))

        # Vanilla from here on down
        always = {
                "SCRIPT_NAME": "git-http-backend",
                "SERVER_SOFTWARE": self.version_string(),
                "SERVER_NAME": self.server.server_name,
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": self.protocol_version,
                "SERVER_PORT": str(self.server.server_port),
                "REQUEST_METHOD": self.command,
                "REMOTE_ADDR": self.client_address[0],
            }
        cgi_env.update(always)

        if hasattr(self.headers, "get_content_type"):
            cgi_env["CONTENT_TYPE"] = self.headers.get(
                "content-type", self.headers.get_content_type()
            )
        else:  # 27
            cgi_env["CONTENT_TYPE"] = (
                self.headers.typeheader or self.headers.type
            )

        length = self.headers.get("content-length")
        if length:
            cgi_env["CONTENT_LENGTH"] = length

        referer = self.headers.get("referer")
        if referer:
            cgi_env["HTTP_REFERER"] = referer

        accept = []
        # Actual type is X-<custom>
        for line in self.headers.getallmatchingheaders("accept"):
            if line[:1] in "\t\n\r ":
                accept.append(line.strip())
            else:
                accept += accept + line[7:].split(",")
        cgi_env["HTTP_ACCEPT"] = ",".join(accept)

        ua = self.headers.get("user-agent")
        if ua:
            cgi_env["HTTP_USER_AGENT"] = ua

        if hasattr(self.headers, "get_all"):
            co = filter(None, self.headers.get_all("cookie", []))
        else:
            co = filter(None, self.headers.getheaders("cookie"))
        cookie_str = ", ".join(co)
        if cookie_str:
            cgi_env["HTTP_COOKIE"] = cookie_str

        config["DEBUG"] and self.dlog("envvars", **cgi_env)

        full_env.update(cgi_env)
        # 4.1 says: "an optional meta-variable may be omitted (left unset) if
        # its value is NULL" (a zero-length string).
        #
        # EDIT: upstream includes CONTENT_LENGTH here but it has been removed
        # below. The RFC says it can be NULL but also says it MUST be set IFF
        # content exists (meaning unset otherwise). Since we only read what's
        # reported by the request (and discard the rest), there's no sense in
        # using a fallback, no?
        rfcvars = (
            "QUERY_STRING",
            "REMOTE_HOST",  # SHOULD (can also be REMOTE_HOST)
            "HTTP_USER_AGENT",
            "HTTP_COOKIE",
            "HTTP_REFERER",
        )
        for k in rfcvars:
            full_env.setdefault(k, "")

        return full_env

    def run_cgi(self):
        """Send input to git-http-backend, return output to client

        GnuTLS issue
        ~~~~~~~~~~~~
        On Debian (and probably Ubuntu), both curl and git are built
        against GnuTLS, which raises error -110: "the TLS connection was
        non-properly terminated." So, either http-backend isn't sending
        ``Content-Length`` or it's getting lost somewhere. Looking at
        the source_, we see that ``get_info_refs`` does indeed send
        it when the "service" param isn't present in the query string,
        which isn't the case with everyday requests like fetches and
        pushes.

        Also Tried messing with the ``Connection: close`` header field,
        but that didn't seem to do anything (or I wasn't reading the spec_
        correctly).

        .. _source: https://github.com/git/git/http-backend.c
        .. _spec: https://tools.ietf.org/html/rfc2616#section-14.10
        """
        env = self._populate_envvars()

        self.send_response(HTTPStatus.OK, "Script output follows")
        if hasattr(self, "flush_headers"):
            self.flush_headers()

        try:
            nbytes = int(env.get("CONTENT_LENGTH", 0))
        except (TypeError, ValueError):
            nbytes = 0

        backend_input = self.consume_and_exhaust(nbytes) or None
        if backend_input is None:
            assert "CONTENT_LENGTH" not in env

        cmdline = [os.path.join(self.git_exec_path, "git-http-backend")]
        proc = Popen(cmdline, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env)
        stdout, stderr = proc.communicate(input=backend_input)

        proc.stderr.close()
        proc.stdout.close()

        # See note in docstring re GnuTLS and Content-Length
        hdr, _, payload = stdout.partition(b"\r\n\r\n")
        if self.command == "GET" and b"Content-Length" in hdr:
            self.log_error("W: 'Content-Length' in header from cgi: %r", hdr)

        self.send_header("Content-Length", len(payload))
        if hasattr(self, "flush_headers"):
            self.flush_headers()
        self.wfile.write(stdout)

        assert proc.returncode is not None  # possible w. concurrent variants
        status = proc.returncode
        if stderr:  # also impossible?
            self.log_error("E: Got unexpected stderr: %r", stderr)
        if status:
            self.log_error("E: CGI script exit status %#x", status)
        else:
            config["DEBUG"] and self.dlog("subprocess", exit_status=status)


def register_signals(server, quitters, keepers=None):
    """Attach a handler to signals named in quitters or keepers.
    The module's default behavior is to quit without teardown for
    certain "unknown" signals like USR1.
    """
    quitters = (
        s.upper() if s.upper().startswith("SIG") else "SIG" + s.upper()
        for s in quitters
    )
    if keepers is not None:
        keepers = [
            s.upper() if s.upper().startswith("SIG") else "SIG" + s.upper()
            for s in keepers
        ]
    else:
        keepers = ()
    # This syntax is forbidden in Python 2.7: ``set((*quitters, *keepers))``
    signames = set(quitters) | set(keepers)
    import signal

    # Can also ``filter(None, Iterator)`` to get rid of falsey items
    numxsig = {
        getattr(signal, sig, None): sig
        for sig in signames
        if sig in dir(signal)
    }

    def handle_stay_signal(signo, frame):
        print(
            "\nReceived {!r} from controlling terminal; "
            "ignoring...".format(numxsig[signo]),
            file=sys.stderr,
        )
        return 0

    def handle_quit_signal(signo, frame):
        # This just calls ``socket.close()`` (rather than shutdown)
        server.server_close()
        msg = "\nReceived %r, {} server, quitting..." % numxsig[signo]
        if hasattr(server.socket, "_closed"):
            print(
                msg.format(
                    "successfully closed"
                    if server.socket._closed
                    else "FAILED TO CLOSE"
                ),
                file=sys.stderr,
            )
        else:
            print(
                msg.format(
                    "successfully closed"
                    if "closedsocket" in repr(server.socket._sock)
                    else "FAILED TO CLOSE"
                ),
                file=sys.stderr,
            )
        sys.exit(0)

    for num, name in numxsig.items():
        # Special case for job control signals propagated after a Ctrl-Z.
        if name in keepers:
            signal.signal(num, handle_stay_signal)
        else:
            signal.signal(num, handle_quit_signal)


def serve(server_class, name="Git services", context=None):
    """This is basically just ``__main__`` from ``http.server``
    """
    from time import strftime

    server = server_class(
        (config["HOST"], config["PORT"]), HTTPBackendHandler, context
    )

    register_signals(server, ("TERM", "HUP", "INT"), ("TSTP", "TTOU", "TTIN"))

    # Copy fmt from ``BaseHTTPRequestHandler.log_message``
    bookend_fmt = "{0} - - [{2}] {3} serving %s on {0} over port {1}" % name
    time_fmt = "%d/%b/%Y %H:%M:%S"
    #
    host, port = server.socket.getsockname()
    print(
        bookend_fmt.format(host, port, strftime(time_fmt), "Started"),
        file=sys.stderr,
    )
    print(
        "{} - - [{}] PID: {}, PPID: {}".format(
            host, strftime(time_fmt), os.getpid(), os.getppid()
        ),
        file=sys.stderr,
    )
    if not config["LOGFILE"]:
        print("\n{}\n".format("Hit Ctrl-C to exit."), file=sys.stderr)
    sys.stderr.flush()

    try:
        server.serve_forever()
    finally:
        print(
            "\n"
            + bookend_fmt.format(host, port, strftime(time_fmt), "Stopped"),
            file=sys.stderr,
        )
        server.server_close()


def set_ssl_context(certfile=None, keyfile=None, dhparams=None):
    """Verify certs exist on filesystem, return an SSL context object.
    """

    def verify(val):
        if val:
            fpath = os.path.expanduser(os.path.expandvars(val))
            if os.path.isfile(fpath):
                return os.path.realpath(fpath)

    certfile = verify(certfile)
    if certfile is None:
        return None

    # Ensure lone certificates include a key
    keyfile = verify(keyfile)
    if keyfile is None:
        with open(certfile) as f:
            pem = f.readlines()  # Can't just iter f, must expand/tee
            msg = None
            try:
                k = next(pem.index(l) for l in pem if "END PRIVATE" in l)
                c = next(pem.index(l) for l in pem if "CERTIFICATE" in l)
            except StopIteration:
                msg = (
                    "Invalid certificate. Please set ``*_KEYFILE`` or "
                    "provide a combined cert in PEM format."
                )
            else:
                if not k < c:
                    msg = (
                        "Invalid certificate. For combined PEM certs, "
                        "the key must appear first."
                    )
            if msg:
                raise RuntimeError(msg)
    import ssl

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    # Like ``SSLContext.set_default_verify_paths()``, ``set_ecdh_curve()``
    # doesn't exist in 3.5.x, at least not on Fedora's system python3.
    # XXX some expert tutorial from 2013 says to set this to ``secp384r1``
    # on Apache/NGINX. Not sure if that's still the way to go.
    dhparams = verify(dhparams)
    if dhparams:
        context.load_dh_params(dhparams)
    # XXX probably best not to mess with these...
    # context.set_ciphers("EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH")
    context.load_cert_chain(certfile, keyfile)
    return context


def validate_logpath(inpath=None, create=False, maxsize=2):
    import os

    outpath = None
    if inpath is not None:
        # On UNIX, write permissions of parent dir don't matter for
        # existing files
        if os.path.isfile(inpath) and os.access(inpath, os.W_OK):
            outpath = inpath
        elif os.access(os.path.dirname(inpath), os.W_OK):
            outpath = inpath
            if os.path.isfile(outpath):
                outpath += ".new"
            os.mknod(outpath, 0o644)
        else:
            return None
        # If attempting to support Windows, assume Python version >= 3.5
        if os.path.getsize(outpath) > 2 ** 20 * maxsize:
            try:
                os.truncate(outpath, 0)
            except AttributeError:
                # Surely there's some simpler way to do this
                with open(outpath, "w") as f:
                    os.ftruncate(f.fileno(), 0)
    return outpath


def _boolify_envvar(val):
    """Interpret boolean environment variables.
    True whenever set/exported, even if value is an empty string,
    "null", or "none".
    """
    falsey = ("false", "nil", "no", "off", "0")
    return (val if val is not None else "false").lower() not in falsey


def main(**overrides):
    """Set globals from environment and call serve()

    Overrides should be unprefixed names and native types, e.g. DEBUG=1
    not _DEBUG="1".

    """
    if sys.version_info < (3, 5) and sys.version_info[:2] != (2, 7):
        print(
            "WARNING: untried on Python versions < 3.5, except for 2.7",
            file=sys.stderr,
        )

    if any(a.lstrip("-") in ("help", "h") for a in sys.argv[1:]):
        print(__doc__.split("\x0c")[1])  # long, autouse pager?
        return

    # Real, local path exposed by server as '/'. Full dereferencing with
    # os.path.realpath() might not be desirable in some situations.
    config["DOCROOT"] = os.path.abspath(
        sys.argv[1]
        if len(sys.argv) > 1 and os.path.isdir(sys.argv[1])
        else "."
    )

    # Options
    envvar_prefix = os.getenv("GITSRV_PREFIX", "_")
    config.update(overrides)

    for key, value in list(config.items()):
        if key in overrides:
            continue
        fixed = "{}{}".format(envvar_prefix, key)
        if fixed in os.environ:
            val = os.getenv(fixed)
            if isinstance(value, bool):
                config[key] = _boolify_envvar(val)
            else:
                config[key] = type(value)(val) if value is not None else val

    # Deprecations
    dep_msg = "\x1b[33;1mWARNING\x1b[m: Option {} is no longer supported."
    for opt in ("ENFORCE_DOTGIT", "FIRST_CHILD_OK", "CREATE_MISSING"):
        name = "{}{}".format(envvar_prefix, opt)
        if name in os.environ:
            if opt == "CREATE_MISSING":
                msg = "See --help under ALLOW_CREATION."
            else:
                msg = "The old 'on' behavior is now hard-coded."
            print(dep_msg.format(opt), msg)

    # SSL
    context = set_ssl_context(
        certfile=config["CERTFILE"],
        keyfile=config["KEYFILE"],
        dhparams=config["DHPARAMS"],
    )

    if context and config["PORT"] == 8000:
        config["PORT"] = 4443

    logfile = validate_logpath(config["LOGFILE"], create=True, maxsize=0)

    if logfile is None:
        serve(TlsServer, context=context)
        return

    class AsRequested(TlsServer):  # Really need whole other cls here?
        def service_actions(self):
            sys.stderr.flush()
            sys.stdout.flush()

    with open(logfile, "a") as f:
        try:
            from contextlib import redirect_stderr, redirect_stdout
        except ImportError:
            try:
                _stderr = sys.stderr
                sys.stderr = f
                serve(AsRequested, context=context)
            finally:
                sys.stderr = _stderr
        else:
            # Actually, probably shouldn't redirect stdout, but some inherited
            # methods like ``SocketServer.BaseServer.handle_error`` don't print
            # to stderr.
            with redirect_stderr(f), redirect_stdout(sys.stderr):
                serve(AsRequested, context=context)


if __name__ == "__main__":
    sys.exit(main())


# Copyright 2016 Jane Soko <boynamedjane@misled.ml>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
