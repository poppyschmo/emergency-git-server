#!/bin/python3
# -*- coding: UTF-8 -*-


def test_boolify_envvar():
    import os

    from emergency_git_server import boolify_envvar, envvar_prefix

    if os.getenv("_TEST_ENVVAR"):
        del os.environ["_TEST_ENVVAR"]
    assert boolify_envvar("TEST_ENVVAR") is False

    os.environ["_TEST_ENVVAR"] = ""
    assert boolify_envvar("TEST_ENVVAR") is True

    os.environ["_TEST_ENVVAR"] = "None"
    assert boolify_envvar("TEST_ENVVAR") is True

    os.environ["_TEST_ENVVAR"] = "null"
    assert boolify_envvar("TEST_ENVVAR") is True

    for v in "false nil no off 0 False Nil No Off".split():
        os.environ["_TEST_ENVVAR"] = v
        assert boolify_envvar("TEST_ENVVAR") is False


#
