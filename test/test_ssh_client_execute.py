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

"""SSHClient: execution of the commands over the channel, the arguments of the SSH, and the parallel execution."""

from __future__ import annotations

import logging
from unittest import mock

import pytest

import exec_helpers
from exec_helpers import proc_enums
from fakes import fake_channel
from fakes import host
from fakes import host2
from fakes import port
from subprocess_cases import EXECUTE_ARGNAMES
from subprocess_cases import EXECUTE_CASES
from subprocess_cases import command
from subprocess_cases import make_result
from subprocess_cases import stdin_bytes

command_log = f"Executing command:\n{command.rstrip()!r}\n"


@pytest.mark.parametrize("method", ["execute", "__call__"], ids=["execute", "call"])
@pytest.mark.parametrize(EXECUTE_ARGNAMES, EXECUTE_CASES)
def test_execute(make_ssh, get_logger, method, stdin, stdout, stderr, exit_code, open_stdout, open_stderr) -> None:
    """The command result is built from the channel streams and the exit code, and STDIN is sent to the channel."""
    chan = fake_channel(stdout=stdout, stderr=stderr, exit_code=exit_code)
    ssh = make_ssh(chan)

    res = getattr(ssh, method)(command, stdin=stdin, open_stdout=open_stdout, open_stderr=open_stderr)

    assert isinstance(res, exec_helpers.ExecResult)
    assert res == make_result(
        stdout=stdout or (),
        stderr=stderr or (),
        stdin=stdin,
        exit_code=exit_code,
    )
    chan.exec_command.assert_called_once_with(f"{command}\n")
    if stdin is None:
        chan.stdin_file.write.assert_not_called()
    else:
        chan.stdin_file.write.assert_called_once_with(stdin_bytes(stdin))
    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=command_log)


@pytest.mark.parametrize(
    ("kwargs", "pty_call"),
    [
        pytest.param({}, None, id="no_pty"),
        pytest.param(
            {"get_pty": True},
            mock.call(term="vt100", width=80, height=24, width_pixels=0, height_pixels=0),
            id="pty",
        ),
        pytest.param(
            {"get_pty": True, "width": 120, "height": 100},
            mock.call(term="vt100", width=120, height=100, width_pixels=0, height_pixels=0),
            id="pty_custom_size",
        ),
    ],
)
def test_pty(make_ssh, kwargs, pty_call) -> None:
    """PTY is requested from the channel only on demand, with the size given."""
    chan = fake_channel()

    make_ssh(chan).execute(command, **kwargs)

    assert chan.get_pty.call_args_list == ([pty_call] if pty_call else [])


@pytest.mark.parametrize("method", ["check_call", "check_stderr"])
def test_checkers_pass_ssh_arguments(mocker, make_ssh, method) -> None:
    """The validators pass the SSH specific arguments to the execution."""
    execute = mocker.patch("exec_helpers.ssh.SSHClient.execute", return_value=make_result(stdout=(), stderr=()))
    ssh = make_ssh(fake_channel())

    getattr(ssh, method)(command, get_pty=True, width=120, height=100)

    assert execute.call_args.kwargs.items() >= {"get_pty": True, "width": 120, "height": 100}.items()


@pytest.mark.parametrize(
    ("exit_codes", "expected"),
    [
        pytest.param((0, 0), (proc_enums.EXPECTED,), id="all_ok"),
        pytest.param((1, 1), [1], id="expected_code"),
    ],
)
def test_execute_together(make_ssh, exit_codes, expected) -> None:
    """The result is given for each remote."""
    remotes = [
        make_ssh(fake_channel(stdout=(b"out\n",), exit_code=ec), hostname=name)
        for name, ec in zip((host, host2), exit_codes, strict=True)
    ]

    results = exec_helpers.SSHClient.execute_together(remotes=remotes, command=command, expected=expected)

    assert results == {
        (host, port): make_result(stdout=(b"out\n",), exit_code=exit_codes[0]),
        (host2, port): make_result(stdout=(b"out\n",), exit_code=exit_codes[1]),
    }


def test_execute_together_failed(make_ssh) -> None:
    """An unexpected exit code of any remote is raised with the results of all of them."""
    remotes = [
        make_ssh(fake_channel(stdout=(b"out\n",), exit_code=ec), hostname=name) for name, ec in ((host, 0), (host2, 1))
    ]

    with pytest.raises(exec_helpers.ParallelCallProcessError) as exc_info:
        exec_helpers.SSHClient.execute_together(remotes=remotes, command=command)

    exc = exc_info.value
    assert exc.cmd == command
    assert exc.expected == (proc_enums.EXPECTED,)
    assert set(exc.results) == {(host, port), (host2, port)}
    assert set(exc.errors) == {(host2, port)}
