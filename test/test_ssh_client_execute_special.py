#    Copyright 2018 Alexey Stepanov aka penguinolog.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import logging
import threading
import typing

import mock
import pytest

import exec_helpers
from exec_helpers import proc_enums


class FakeFileStream:
    """Mock-like object for stream emulation."""

    def __init__(self, *args):
        self.__src = list(args)
        self.closed = False
        self.channel = None

    def __iter__(self):
        """Normally we iter over source."""
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)

    def fileno(self):
        return hash(tuple(self.__src))

    def close(self):
        """We enforce close."""
        self.closed = True


def read_stream(stream: FakeFileStream) -> typing.Tuple[bytes, ...]:
    return tuple([line for line in stream])


host = "127.0.0.1"
host2 = "127.0.0.2"
port = 22
username = "user"
password = "pass"

command = "ls ~\nline 2\nline 3\nline с кирилицей"
command_log = "Executing command:\n{!r}\n".format(command.rstrip())
stdout_src = (b" \n", b"2\n", b"3\n", b" \n")
stderr_src = (b" \n", b"0\n", b"1\n", b" \n")
encoded_cmd = base64.b64encode("{}\n".format(command).encode("utf-8")).decode("utf-8")

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


@pytest.fixture
def auto_add_policy(mocker):
    return mocker.patch("paramiko.AutoAddPolicy", return_value="AutoAddPolicy")


@pytest.fixture
def paramiko_ssh_client(mocker):
    mocker.patch("time.sleep")
    return mocker.patch("paramiko.SSHClient")


@pytest.fixture
def chan_makefile():
    class MkFile:
        def __init__(self):
            self.stdin = None
            self.stdout = None
            self.channel = None

        def __call__(self, flags: str):
            if "wb" == flags:
                self.stdin = mock.Mock()
                self.stdin.channel = self.channel
                return self.stdin
            elif "rb" == flags:
                self.stdout = FakeFileStream(*stdout_src)
                self.stdout.channel = self.channel
                return self.stdout
            raise ValueError("Unexpected flags: {!r}".format(flags))

    return MkFile()


@pytest.fixture
def ssh_transport_channel(paramiko_ssh_client, chan_makefile):
    chan = mock.Mock(makefile=chan_makefile, closed=False)
    chan_makefile.channel = chan
    chan.attach_mock(mock.Mock(return_value=FakeFileStream(*stderr_src)), "makefile_stderr")
    chan.configure_mock(exit_status=0)
    chan.status_event.attach_mock(mock.Mock(return_value=True), "is_set")
    open_session = mock.Mock(return_value=chan)
    transport = mock.Mock()
    transport.attach_mock(open_session, "open_session")
    get_transport = mock.Mock(return_value=transport)
    _ssh = mock.Mock()
    _ssh.attach_mock(get_transport, "get_transport")
    paramiko_ssh_client.return_value = _ssh
    return chan


@pytest.fixture
def ssh_auth_logger(mocker):
    return mocker.patch("exec_helpers.ssh_auth.logger")


@pytest.fixture
def get_logger(mocker):
    return mocker.patch("logging.getLogger")


@pytest.fixture
def ssh(paramiko_ssh_client, ssh_transport_channel, auto_add_policy, ssh_auth_logger, get_logger):
    return exec_helpers.SSHClient(host=host, port=port, auth=exec_helpers.SSHAuth(username=username, password=password))


@pytest.fixture
def ssh2(paramiko_ssh_client, ssh_transport_channel, auto_add_policy, ssh_auth_logger, get_logger):
    return exec_helpers.SSHClient(
        host=host2, port=port, auth=exec_helpers.SSHAuth(username=username, password=password)
    )


@pytest.fixture
def exec_result():
    return exec_helpers.ExecResult(cmd=command, stdin=None, stdout=stdout_src, stderr=stderr_src, exit_code=0)


def teardown_function(function):
    """Clean-up after tests."""
    with mock.patch("warnings.warn"):
        exec_helpers.SSHClient._clear_cache()


def test_001_mask_command(ssh, get_logger) -> None:
    cmd = "USE='secret=secret_pass' do task"
    log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
    masked_cmd = "USE='secret=<*masked*>' do task"
    cmd_log = "Executing command:\n{!r}\n".format(masked_cmd)
    done_log = "Command {!r} exit code: {!s}".format(masked_cmd, proc_enums.EXPECTED)

    log = get_logger(ssh.__class__.__name__).getChild("{host}:{port}".format(host=host, port=port))
    res = ssh.execute(cmd, log_mask_re=log_mask_re)
    assert res.cmd == masked_cmd
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=cmd_log)
    assert log.mock_calls[-1] == mock.call.log(level=logging.DEBUG, msg=done_log)


def test_002_mask_command_global(ssh, get_logger) -> None:
    cmd = "USE='secret=secret_pass' do task"
    log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
    masked_cmd = "USE='secret=<*masked*>' do task"
    cmd_log = "Executing command:\n{!r}\n".format(masked_cmd)
    done_log = "Command {!r} exit code: {!s}".format(masked_cmd, proc_enums.EXPECTED)

    log = get_logger(ssh.__class__.__name__).getChild("{host}:{port}".format(host=host, port=port))

    ssh.log_mask_re = log_mask_re
    res = ssh.execute(cmd)
    assert res.cmd == masked_cmd
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=cmd_log)
    assert log.mock_calls[-1] == mock.call.log(level=logging.DEBUG, msg=done_log)


def test_003_execute_verbose(ssh, get_logger) -> None:
    cmd_log = "Executing command:\n{!r}\n".format(command)
    done_log = "Command {!r} exit code: {!s}".format(command, proc_enums.EXPECTED)

    log = get_logger(ssh.__class__.__name__).getChild("{host}:{port}".format(host=host, port=port))
    ssh.execute(command, verbose=True)

    assert log.mock_calls[0] == mock.call.log(level=logging.INFO, msg=cmd_log)
    assert log.mock_calls[-1] == mock.call.log(level=logging.INFO, msg=done_log)


def test_004_execute_timeout(ssh) -> None:
    """We allow timeout and not crush on it if fit."""
    ssh.execute(command, timeout=0.01)


def test_005_execute_timeout_fail(ssh, ssh_transport_channel, exec_result) -> None:
    """We allow timeout and not crush on it if fit."""
    ssh_transport_channel.status_event = threading.Event()
    with pytest.raises(exec_helpers.ExecHelperTimeoutError) as e:
        ssh.execute(command, timeout=0.01)
    exc = e.value  # type: exec_helpers.ExecHelperTimeoutError
    assert exc.timeout == 0.01
    assert exc.cmd == command
    assert exc.stdout == exec_result.stdout_str
    assert exc.stderr == exec_result.stderr_str


def test_006_execute_together_exceptions(ssh, ssh2, mocker) -> None:
    mocker.patch("exec_helpers.ssh_client.SSHClient.execute_async", side_effect=RuntimeError)
    remotes = [ssh, ssh2]

    with pytest.raises(exec_helpers.ParallelCallExceptions) as e:
        ssh.execute_together(remotes=remotes, command=command)
    exc = e.value  # type: exec_helpers.ParallelCallExceptions
    assert list(sorted(exc.exceptions)) == [(host, port), (host2, port)]
    for exception in exc.exceptions.values():
        assert isinstance(exception, RuntimeError)
