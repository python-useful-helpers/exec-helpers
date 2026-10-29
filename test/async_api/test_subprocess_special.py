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

"""Async Subprocess: special cases of the stdin, the stdout, the timeouts and the masking of the command."""

from __future__ import annotations

import asyncio
import typing
from unittest import mock

import pytest

import exec_helpers
from subprocess_cases import EINVAL
from subprocess_cases import ESHUTDOWN
from subprocess_cases import LINES
from subprocess_cases import SPECIAL_ARGNAMES
from subprocess_cases import SPECIAL_CASES
from subprocess_cases import command

pytestmark = pytest.mark.asyncio


@pytest.fixture
def logger(mocker):
    """Mock the logger of the runner."""
    return mocker.patch("exec_helpers.async_api.subprocess.Subprocess.logger", autospec=True)


@pytest.mark.parametrize(SPECIAL_ARGNAMES, SPECIAL_CASES)
async def test_execute_special(fake_async_popen, logger, stdout, execute_kwargs, runner_kwargs, masked, level) -> None:
    """The result and the log do not depend on the stdout problems, and the secrets are masked in the log."""
    fake_async_popen(stdout=stdout)
    runner = exec_helpers.async_api.Subprocess(**runner_kwargs)

    kwargs: dict[str, typing.Any] = {"command": command, **execute_kwargs}

    res = await runner.execute(**kwargs)

    expected_stdout = None if stdout is None else tuple(line for line in stdout if isinstance(line, bytes))
    assert res == exec_helpers.ExecResult(cmd=masked, stdout=expected_stdout, stderr=(), exit_code=0)
    assert logger.mock_calls[0] == mock.call.log(level=level, msg=f"Executing command:\n{masked.rstrip()!r}\n")
    assert logger.mock_calls[-1] == mock.call.log(
        level=level,
        msg=f"Command {masked.rstrip()!r} exit code: {res.exit_code!s}",
    )


@pytest.mark.parametrize(
    ("write", "close", "warning"),
    [
        pytest.param(BrokenPipeError(), None, "STDIN Send failed: broken PIPE", id="write_broken_pipe"),
        pytest.param(ESHUTDOWN, None, "STDIN Send failed: broken PIPE", id="write_shutdown"),
        pytest.param(ConnectionResetError(), None, "STDIN Send failed: closed PIPE", id="write_closed_pipe"),
        pytest.param(None, BrokenPipeError(), "STDIN Send failed: broken PIPE", id="close_broken_pipe"),
        pytest.param(None, ESHUTDOWN, "STDIN Send failed: broken PIPE", id="close_shutdown"),
        pytest.param(None, EINVAL, None, id="close_closed_pipe"),
    ],
)
async def test_stdin_pipe_closed_by_process(fake_async_popen, logger, write, close, warning) -> None:
    """The process that closed its stdin does not fail the execution."""
    fake_async_popen(stdout=LINES, stdin_write=write, stdin_close=close)

    res = await exec_helpers.async_api.Subprocess().execute(command, stdin="Warning")

    assert res.exit_code == 0
    assert (mock.call.warning(warning) in logger.mock_calls) == (warning is not None)


@pytest.mark.parametrize(
    ("write", "close"),
    [
        pytest.param(OSError(), None, id="write_error"),
        pytest.param(None, OSError(), id="close_error"),
    ],
)
async def test_stdin_error(mocker, fake_async_popen, write, close) -> None:
    """Other stdin errors are raised, and the process is killed."""
    kill_tree = mocker.patch("exec_helpers._subprocess_helpers.kill_proc_tree")
    proc = fake_async_popen(stdout=LINES, stdin_write=write, stdin_close=close)

    with pytest.raises(OSError):
        await exec_helpers.async_api.Subprocess().execute(command, stdin="Failed")

    proc.kill.assert_called()
    kill_tree.assert_called_with(proc.pid)


@pytest.mark.parametrize(
    ("second_wait", "expected_exc"),
    [
        pytest.param(-9, exec_helpers.ExecHelperTimeoutError, id="killed"),
        pytest.param(None, exec_helpers.ExecHelperNoKillError, id="not_killed"),
    ],
)
async def test_timeout(mocker, fake_async_popen, second_wait, expected_exc) -> None:
    """The process tree is killed on the timeout, and the process that survived is reported separately."""
    kill_tree = mocker.patch("exec_helpers._subprocess_helpers.kill_proc_tree")
    proc = fake_async_popen(wait=(TimeoutError(), second_wait))

    with pytest.raises(expected_exc):
        await exec_helpers.async_api.Subprocess().execute(command)

    kill_tree.assert_called_with(proc.pid)
    assert proc.wait.await_count == 2


async def test_output_is_not_lost_on_process_exit(fake_async_popen) -> None:
    """The output still in the pipes when the process exits is read completely."""
    lines = tuple(f"{num}\n".encode() for num in range(50))
    fake_async_popen(stdout=lines)

    res = await exec_helpers.async_api.Subprocess().execute(command)

    assert res.stdout == lines


async def test_output_open_after_process_exit(mocker, fake_async_popen, logger) -> None:
    """The execution does not wait for the output that stays open, and the incomplete result is logged."""

    class OpenForever:
        """Stream held open by a child of the process: it never reaches the end."""

        def __aiter__(self) -> OpenForever:
            return self

        async def __anext__(self) -> bytes:
            await asyncio.Event().wait()
            raise StopAsyncIteration

    mocker.patch("exec_helpers.async_api.subprocess._READERS_DRAIN_TIMEOUT", 0.01)
    fake_async_popen().stdout = OpenForever()

    res = await exec_helpers.async_api.Subprocess().execute(command)

    assert res.exit_code == 0
    assert any("may miss the output" in str(call) for call in logger.mock_calls if call[0] == "debug")
