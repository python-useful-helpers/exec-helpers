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

"""Subprocess: special cases of the stdin, the stdout, the timeouts and the masking of the command."""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest

import exec_helpers
from subprocess_cases import EINVAL
from subprocess_cases import ESHUTDOWN
from subprocess_cases import LINES
from subprocess_cases import SPECIAL_ARGNAMES
from subprocess_cases import SPECIAL_CASES
from subprocess_cases import command
from subprocess_cases import default_timeout

timeout_expired = subprocess.TimeoutExpired(command, default_timeout)


@pytest.mark.parametrize(SPECIAL_ARGNAMES, SPECIAL_CASES)
def test_execute_special(fake_popen, subprocess_logger, stdout, execute_kwargs, runner_kwargs, masked, level) -> None:
    """The result and the log do not depend on the stdout problems, and the secrets are masked in the log."""
    fake_popen(stdout=stdout)
    runner = exec_helpers.Subprocess(**runner_kwargs)

    res = runner.execute(**{"command": command, **execute_kwargs})

    expected_stdout = None if stdout is None else tuple(line for line in stdout if isinstance(line, bytes))
    assert res == exec_helpers.ExecResult(cmd=masked, stdout=expected_stdout, stderr=(), exit_code=0)
    assert subprocess_logger.mock_calls[0] == mock.call.log(
        level=level,
        msg=f"Executing command:\n{masked.rstrip()!r}\n",
    )
    assert subprocess_logger.mock_calls[-1] == mock.call.log(
        level=level,
        msg=f"Command {masked.rstrip()!r} exit code: {res.exit_code!s}",
    )


@pytest.mark.parametrize(
    ("write", "close", "warning"),
    [
        pytest.param(BrokenPipeError(), None, "STDIN Send failed: broken PIPE", id="write_broken_pipe"),
        pytest.param(EINVAL, None, "STDIN Send failed: closed PIPE", id="write_closed_pipe"),
        pytest.param(ESHUTDOWN, None, "STDIN Send failed: broken PIPE", id="write_shutdown"),
        pytest.param(None, BrokenPipeError(), "STDIN Send failed: broken PIPE", id="close_broken_pipe"),
        pytest.param(None, ESHUTDOWN, "STDIN Send failed: broken PIPE", id="close_shutdown"),
        pytest.param(None, EINVAL, None, id="close_closed_pipe"),
    ],
)
def test_stdin_pipe_closed_by_process(fake_popen, subprocess_logger, write, close, warning) -> None:
    """The process that closed its stdin does not fail the execution."""
    fake_popen(stdout=LINES, stdin_write=write, stdin_close=close)

    res = exec_helpers.Subprocess().execute(command, stdin="Warning")

    assert res.exit_code == 0
    assert (mock.call.warning(warning) in subprocess_logger.mock_calls) == (warning is not None)


@pytest.mark.parametrize(
    ("write", "close"),
    [
        pytest.param(OSError(), None, id="write_error"),
        pytest.param(None, OSError(), id="close_error"),
    ],
)
def test_stdin_error(mocker, fake_popen, write, close) -> None:
    """Other stdin errors are raised, and the process is killed."""
    kill_tree = mocker.patch("exec_helpers._subprocess_helpers.kill_proc_tree")
    proc = fake_popen(stdout=LINES, stdin_write=write, stdin_close=close)

    with pytest.raises(OSError):
        exec_helpers.Subprocess().execute(command, stdin="Failed")

    proc.kill.assert_called_once_with()
    if write is not None:  # only the write error path stops the whole process tree
        kill_tree.assert_called_once_with(proc.pid)


@pytest.mark.parametrize(
    ("poll", "expected_exc"),
    [
        pytest.param(-9, exec_helpers.ExecHelperTimeoutError, id="killed"),
        pytest.param(None, exec_helpers.ExecHelperNoKillError, id="not_killed"),
    ],
)
def test_timeout(fake_popen, poll, expected_exc) -> None:
    """The timeout is reported, and the process that survived the kill is reported separately."""
    fake_popen(wait=(timeout_expired,), poll=(poll,))

    with pytest.raises(expected_exc):
        exec_helpers.Subprocess().execute(command)
