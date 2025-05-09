#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.
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

from __future__ import annotations

import base64
import datetime
import logging
import threading
from unittest import mock

import pytest

import exec_helpers
from exec_helpers import proc_enums
from exec_helpers._ssh_base import SshExecuteAsyncResult

pytestmark = pytest.mark.skip("Rewrite whole execute tests.")


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


def read_stream(stream: FakeFileStream) -> tuple[bytes, ...]:
    return tuple(stream)


host = "127.0.0.1"
host2 = "127.0.0.2"
port = 22
username = "user"
password = "pass"

command = "ls ~\nline 2\nline 3\nline c кирилицей"
command_log = f"Executing command:\n{command.rstrip()!r}\n"
stdout_src = (b" \n", b"2\n", b"3\n", b" \n")
stderr_src = (b" \n", b"0\n", b"1\n", b" \n")
encoded_cmd = base64.b64encode(f"{command}\n".encode()).decode("utf-8")

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


@pytest.fixture
def chan_makefile():
    class MkFile:
        def __init__(self):
            self.stdin = None
            self.stdout = None
            self.channel = None

        def __call__(self, flags: str):
            if flags == "wb":
                self.stdin = mock.Mock()
                self.stdin.channel = self.channel
                return self.stdin
            if flags == "rb":
                self.stdout = FakeFileStream(*stdout_src)
                self.stdout.channel = self.channel
                return self.stdout
            raise ValueError(f"Unexpected flags: {flags!r}")

    return MkFile()


@pytest.fixture
def ssh_transport_channel(paramiko_ssh_client, chan_makefile):
    chan = mock.Mock(makefile=chan_makefile, closed=False)
    chan_makefile.channel = chan
    chan.attach_mock(
        mock.Mock(return_value=FakeFileStream(*stderr_src)),
        "makefile_stderr",
    )
    chan.configure_mock(exit_status=0)
    chan.status_event.attach_mock(mock.Mock(return_value=True), "is_set")
    open_session = mock.Mock(return_value=chan)
    transport = mock.Mock()
    transport.attach_mock(open_session, "open_session")
    get_transport = mock.Mock(return_value=transport)
    ssh_ = mock.Mock()
    ssh_.attach_mock(get_transport, "get_transport")
    paramiko_ssh_client.return_value = ssh_
    return chan


@pytest.fixture
def ssh(
    paramiko_ssh_client,
    ssh_transport_channel,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    return exec_helpers.SSHClient(
        host=host,
        port=port,
        auth=exec_helpers.SSHAuth(username=username, password=password),
    )


@pytest.fixture
def ssh2(
    paramiko_ssh_client,
    ssh_transport_channel,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    return exec_helpers.SSHClient(
        host=host2,
        port=port,
        auth=exec_helpers.SSHAuth(username=username, password=password),
    )


@pytest.fixture
def exec_result():
    return exec_helpers.ExecResult(
        cmd=command,
        stdin=None,
        stdout=stdout_src,
        stderr=stderr_src,
        exit_code=0,
    )


def test_001_mask_command(ssh, get_logger) -> None:
    cmd = "USE='secret=secret_pass' do task"
    log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
    masked_cmd = "USE='secret=<*masked*>' do task"
    cmd_log = f"Executing command:\n{masked_cmd!r}\n"
    done_log = f"Command {masked_cmd!r} exit code: {proc_enums.EXPECTED!s}"

    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    res = ssh.execute(cmd, log_mask_re=log_mask_re)
    assert res.cmd == masked_cmd
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=cmd_log)
    assert log.mock_calls[-1] == mock.call.log(level=logging.DEBUG, msg=done_log)


def test_002_mask_command_global(ssh, get_logger) -> None:
    cmd = "USE='secret=secret_pass' do task"
    log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
    masked_cmd = "USE='secret=<*masked*>' do task"
    cmd_log = f"Executing command:\n{masked_cmd!r}\n"
    done_log = f"Command {masked_cmd!r} exit code: {proc_enums.EXPECTED!s}"

    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")

    ssh.log_mask_re = log_mask_re
    res = ssh.execute(cmd)
    assert res.cmd == masked_cmd
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=cmd_log)
    assert log.mock_calls[-1] == mock.call.log(level=logging.DEBUG, msg=done_log)


def test_003_execute_verbose(ssh, get_logger) -> None:
    cmd_log = f"Executing command:\n{command!r}\n"
    done_log = f"Command {command!r} exit code: {proc_enums.EXPECTED!s}"

    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
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
    exc: exec_helpers.ExecHelperTimeoutError = e.value
    assert exc.timeout == 0.01
    assert exc.cmd == command
    assert exc.stdout == exec_result.stdout_str
    assert exc.stderr == exec_result.stderr_str


def test_006_execute_together_exceptions(ssh, ssh2, mocker) -> None:
    mocker.patch("exec_helpers.ssh.SSHClient._execute_async", side_effect=RuntimeError)
    remotes = [ssh, ssh2]

    with pytest.raises(exec_helpers.ParallelCallExceptionsError) as e:
        ssh.execute_together(remotes=remotes, command=command)
    exc: exec_helpers.ParallelCallExceptionsError = e.value
    assert sorted(exc.exceptions) == [(host, port), (host2, port)]
    for exception in exc.exceptions.values():
        assert isinstance(exception, RuntimeError)


def test_007_execute_command_as_chain(ssh, get_logger) -> None:
    cmd = ("echo", "hello world")
    decoded_cmd = "echo 'hello world'"
    cmd_log = f"Executing command:\n{decoded_cmd!r}\n"
    done_log = f"Command {decoded_cmd!r} exit code: {proc_enums.EXPECTED!s}"

    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    res = ssh.execute(cmd)
    assert res.cmd == decoded_cmd
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=cmd_log)
    assert log.mock_calls[-1] == mock.call.log(level=logging.DEBUG, msg=done_log)


def test_006_execute_together_as_chain(ssh, ssh2, mocker) -> None:
    stdout = ("hello world",)
    cmd = ("echo", "hello world")
    decoded_cmd = "echo 'hello world'"

    def get_patched_execute_async_retval() -> SshExecuteAsyncResult:
        stdout_part = FakeFileStream(*stdout)
        stderr_part = FakeFileStream()

        exit_code = 0
        chan = mock.Mock()
        chan.attach_mock(mock.Mock(return_value=exit_code), "recv_exit_status")

        status_event = mock.Mock()
        status_event.attach_mock(mock.Mock(), "wait")
        chan.attach_mock(status_event, "status_event")
        chan.configure_mock(exit_status=exit_code)
        return SshExecuteAsyncResult(
            interface=chan,
            stdin=mock.Mock,
            stdout=stdout_part,
            stderr=stderr_part,
            started=datetime.datetime.now(tz=datetime.timezone.utc),
        )

    execute_async = mocker.patch(
        "exec_helpers.ssh.SSHClient._execute_async",
        side_effect=[
            get_patched_execute_async_retval(),
            get_patched_execute_async_retval(),
        ],
    )

    remotes = [ssh, ssh2]

    results = exec_helpers.SSHClient.execute_together(remotes=remotes, command=cmd)
    execute_async.assert_has_calls(
        (
            mock.call(
                decoded_cmd,
                stdin=None,
                log_mask_re=None,
                open_stdout=True,
                open_stderr=True,
                timeout=default_timeout,
            ),
            mock.call(
                decoded_cmd,
                stdin=None,
                log_mask_re=None,
                open_stdout=True,
                open_stderr=True,
                timeout=default_timeout,
            ),
        )
    )
    for result in results.values():
        assert result.cmd == decoded_cmd
