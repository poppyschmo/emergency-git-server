====================
Emergency Git Server
====================

A minimal, "single-serving" Git HTTP server for

1. Emergencies
2. Local, ad hoc experimentation
3. Git education

Normal, everyday use is not recommended unless security and performance are
non-issues. Requires a normal Git installation.

There's really no need to ``git clone`` or ``pip install`` since this thing is
a single file.  See ``--help`` for available options like  basic auth,
create-on-clone, create-on-push, SSL/TLS, etc.


Example
-------

Use case
    Some VM or container in which SSH/NFS/SMB aren't desired and for which
    folder sharing or volume mapping aren't worth configuring

On the host
    .. code:: console

        laptop:~$ curl -L "$github_raw_url" | python3 - ./www &
        Serving over port 8000 ...

On the client
    .. code:: console

        [my_vm]# git clone http://laptop.local:8000/repos/my_repo.git
        Cloning ...

Some caveats
    1. Your network setup might require that you provide an IP address
       (likely of a virtual bridge) in place of ``localhost`` or
       ``laptop.local``. Export that (or ``0.0.0.0``) as ``_HOST`` to the
       server's environment.
    2. The ``$GIT_DIR`` (``.git`` folder or bare repo) being cloned must
       reside 2+ levels below the "document root" (``~/www`` in the example
       above). If that's a problem, export ``_FIRST_CHILD_OK=1`` or make a
       dummy tree and nest a link to the repo::

            ~/
            ├── www/
            │   └── repos/
            │       └── my_repo.git -> ../../my_repo/.git
            └── my_repo/
                └── .git/

    3. Non-bare repos must have the ``receive.denyCurrentBranch`` option
       set to ``updateInstead`` in order to receive updates (pushes) and
       update the working directory

       .. code:: console

            laptop:my_repo$ git config --add receive.denyCurrentBranch "updateInstead"

