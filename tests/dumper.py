from functools import namedtuple

data = []
Call = namedtuple("Call", "tag, fmt, msg, kwargs")


def dpick(inst, fmt, *msg, **kwargs):
    import inspect
    ctx = inspect.stack()[1]
    if hasattr(ctx, "function"):
        tag = ctx.function
    else:
        tag = ctx[3]
    data.append(Call(tag, fmt, msg, kwargs))


if __name__ == "__main__":
    import os
    import sys
    import pickle
    import emergency_git_server

    def parse_request(inst):
        """Manual patch for handler when dumping data. Noisy."""
        rv = super(emergency_git_server.HTTPBackendHandler,
                   inst).parse_request()
        # print("\n<<<<<<<<<<: %r" % inst.raw_requestline, file=sys.stderr)
        inst.dlog("parsed",
                  requestline=inst.requestline,
                  version=inst.request_version,
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

    emergency_git_server.HTTPBackendHandler.dlog = dpick
    emergency_git_server.HTTPBackendHandler.parse_request = parse_request
    emergency_git_server.CtxServer.server_close = server_close
    emergency_git_server.DEBUG = True
    sys.exit(emergency_git_server.main())
