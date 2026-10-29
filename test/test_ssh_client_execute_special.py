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

"""SSHClient: special cases of the output, the timeouts, the command forms and the parallel execution."""

from __future__ import annotations

import threading
from unittest import mock

import pytest

import exec_helpers
from exec_helpers import proc_enums
from fakes import fake_channel
from fakes import host
from fakes import host2
from fakes import port
from subprocess_cases import LINES
from subprocess_cases import SPECIAL_ARGNAMES
from subprocess_cases import SPECIAL_CASES
from subprocess_cases import command
from subprocess_cases import make_result

ERR_LINES = (b" \n", b"0\n", b"1\n", b" \n")


@pytest.mark.parametrize(SPECIAL_ARGNAMES, SPECIAL_CASES)
def test_execute_special(make_ssh, get_logger, stdout, execute_kwargs, runner_kwargs, masked, level) -> None:
    """The result and the log do not depend on the stdout problems, and the secrets are masked in the log."""
    ssh = make_ssh(fake_channel(stdout=stdout or ()))
    for name, value in runner_kwargs.items():
        setattr(ssh, name, value)

    res = ssh.execute(**{"command": command, "open_stdout": stdout is not None, **execute_kwargs})

    expected_stdout = None if stdout is None else tuple(line for line in stdout if isinstance(line, bytes))
    assert res == exec_helpers.ExecResult(cmd=masked, stdout=expected_stdout, stderr=(), exit_code=0)
    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    assert log.mock_calls[0] == mock.call.log(level=level, msg=f"Executing command:\n{masked.rstrip()!r}\n")
    assert log.mock_calls[-1] == mock.call.log(
        level=level,
        msg=f"Command {masked.rstrip()!r} exit code: {proc_enums.EXPECTED!s}",
    )


def test_execute_closed_channel(make_ssh, get_logger) -> None:
    """STDIN is not sent to a closed channel, and the execution is not failed."""
    chan = fake_channel(stdout=LINES)
    chan.closed = True
    ssh = make_ssh(chan)

    res = ssh.execute(command, stdin="test")

    assert res.exit_code == 0
    chan.stdin_file.write.assert_not_called()
    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    log.warning.assert_called_once_with("STDIN Send failed: closed channel")


def test_execute_timeout(make_ssh) -> None:
    """The channel is closed, and the output received before the timeout is in the error."""
    chan = fake_channel(stdout=LINES, stderr=ERR_LINES)
    chan.status_event = threading.Event()
    ssh = make_ssh(chan)

    with pytest.raises(exec_helpers.ExecHelperTimeoutError) as exc_info:
        ssh.execute(command, timeout=0.01)

    exc = exc_info.value
    assert exc.timeout == 0.01
    assert exc.cmd == command
    assert exc.stdout == make_result(stdout=LINES, stderr=ERR_LINES).stdout_str
    assert exc.stderr == make_result(stdout=LINES, stderr=ERR_LINES).stderr_str
    chan.close.assert_called_with()


def test_execute_together_exceptions(mocker, make_ssh) -> None:
    """A remote that failed to execute is reported with its exception, and does not hide the others."""
    remotes = [make_ssh(fake_channel(), hostname=name) for name in (host, host2)]
    mocker.patch("exec_helpers.ssh.SSHClient.open_execute_context", side_effect=RuntimeError)

    with pytest.raises(exec_helpers.ParallelCallExceptionsError) as exc_info:
        exec_helpers.SSHClient.execute_together(remotes=remotes, command=command)

    exceptions = exc_info.value.exceptions
    assert sorted(exceptions) == [(host, port), (host2, port)]
    assert all(isinstance(exception, RuntimeError) for exception in exceptions.values())


def test_execute_together_command_as_chain(make_ssh) -> None:
    """The command given as the arguments is joined with the escaping for every remote."""
    channels = [fake_channel(stdout=(b"hello world\n",)), fake_channel(stdout=(b"hello world\n",))]
    remotes = [make_ssh(chan, hostname=name) for chan, name in zip(channels, (host, host2), strict=True)]

    results = exec_helpers.SSHClient.execute_together(remotes=remotes, command=("echo", "hello world"))

    assert {result.cmd for result in results.values()} == {"echo 'hello world'"}
    for chan in channels:
        chan.exec_command.assert_called_once_with("echo 'hello world'\n")
