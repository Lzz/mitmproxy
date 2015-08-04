import os
import shutil
import tempfile
import argparse
import sys
import mock_urwid
from cStringIO import StringIO
from contextlib import contextmanager
from nose.plugins.skip import SkipTest
from mock import Mock
from time import time

from netlib import certutils, odict
import netlib.tutils

from libmproxy import flow, utils, controller
from libmproxy.protocol import http, http_wrappers
from libmproxy.proxy.connection import ClientConnection, ServerConnection
from libmproxy.console.flowview import FlowView
from libmproxy.console import ConsoleState
from libmproxy.protocol.primitives import Error


def _SkipWindows():
    raise SkipTest("Skipped on Windows.")


def SkipWindows(fn):
    if os.name == "nt":
        return _SkipWindows
    else:
        return fn


def tflow(client_conn=True, server_conn=True, req=True, resp=None, err=None):
    """
    @type client_conn: bool | None | libmproxy.proxy.connection.ClientConnection
    @type server_conn: bool | None | libmproxy.proxy.connection.ServerConnection
    @type req:         bool | None | libmproxy.protocol.http.HTTPRequest
    @type resp:        bool | None | libmproxy.protocol.http.HTTPResponse
    @type err:         bool | None | libmproxy.protocol.primitives.Error
    @return:           bool | None | libmproxy.protocol.http.HTTPFlow
    """
    if client_conn is True:
        client_conn = tclient_conn()
    if server_conn is True:
        server_conn = tserver_conn()
    if req is True:
        req = netlib.tutils.treq()
    if resp is True:
        resp = netlib.tutils.tresp()
    if err is True:
        err = terr()

    if req:
        req = http_wrappers.HTTPRequest.wrap(req)
    if resp:
        resp = http_wrappers.HTTPResponse.wrap(resp)

    f = http.HTTPFlow(client_conn, server_conn)
    f.request = req
    f.response = resp
    f.error = err
    f.reply = controller.DummyReply()
    return f


def tclient_conn():
    """
    @return: libmproxy.proxy.connection.ClientConnection
    """
    c = ClientConnection.from_state(dict(
        address=dict(address=("address", 22), use_ipv6=True),
        clientcert=None
    ))
    c.reply = controller.DummyReply()
    return c


def tserver_conn():
    """
    @return: libmproxy.proxy.connection.ServerConnection
    """
    c = ServerConnection.from_state(dict(
        address=dict(address=("address", 22), use_ipv6=True),
        state=[],
        source_address=dict(address=("address", 22), use_ipv6=True),
        cert=None
    ))
    c.reply = controller.DummyReply()
    return c



def terr(content="error"):
    """
    @return: libmproxy.protocol.primitives.Error
    """
    err = Error(content)
    return err


def tflowview(request_contents=None):
    m = Mock()
    cs = ConsoleState()
    if request_contents is None:
        flow = tflow()
    else:
        flow = tflow(req=treq(request_contents))

    fv = FlowView(m, cs, flow)
    return fv


def get_body_line(last_displayed_body, line_nb):
    return last_displayed_body.contents()[line_nb + 2]


@contextmanager
def tmpdir(*args, **kwargs):
    orig_workdir = os.getcwd()
    temp_workdir = tempfile.mkdtemp(*args, **kwargs)
    os.chdir(temp_workdir)

    yield temp_workdir

    os.chdir(orig_workdir)
    shutil.rmtree(temp_workdir)


class MockParser(argparse.ArgumentParser):
    """
    argparse.ArgumentParser sys.exits() by default.
    Make it more testable by throwing an exception instead.
    """

    def error(self, message):
        raise Exception(message)


def raises(exc, obj, *args, **kwargs):
    """
        Assert that a callable raises a specified exception.

        :exc An exception class or a string. If a class, assert that an
        exception of this type is raised. If a string, assert that the string
        occurs in the string representation of the exception, based on a
        case-insenstivie match.

        :obj A callable object.

        :args Arguments to be passsed to the callable.

        :kwargs Arguments to be passed to the callable.
    """
    try:
        obj(*args, **kwargs)
    except Exception as v:
        if isinstance(exc, basestring):
            if exc.lower() in str(v).lower():
                return
            else:
                raise AssertionError(
                    "Expected %s, but caught %s" % (
                        repr(str(exc)), v
                    )
                )
        else:
            if isinstance(v, exc):
                return
            else:
                raise AssertionError(
                    "Expected %s, but caught %s %s" % (
                        exc.__name__, v.__class__.__name__, str(v)
                    )
                )
    raise AssertionError("No exception raised.")


@contextmanager
def capture_stderr(command, *args, **kwargs):
    out, sys.stderr = sys.stderr, StringIO()
    command(*args, **kwargs)
    yield sys.stderr.getvalue()
    sys.stderr = out

test_data = utils.Data(__name__)
