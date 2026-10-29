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

"""Async Subprocess: execution of the commands."""

from __future__ import annotations

import asyncio
import logging
from unittest import mock

import pytest

import exec_helpers
from subprocess_cases import EXECUTE_ARGNAMES
from subprocess_cases import EXECUTE_CASES
from subprocess_cases import command
from subprocess_cases import make_result
from subprocess_cases import stdin_bytes

pytestmark = pytest.mark.asyncio

command_log = f"Executing command:\n{command.rstrip()!r}\n"


@pytest.fixture
def logger(mocker):
    """Mock the logger of the runner."""
    return mocker.patch("exec_helpers.async_api.subprocess.Subprocess.logger", autospec=True)


@pytest.mark.parametrize(
    "method",
    [exec_helpers.async_api.Subprocess.execute, exec_helpers.async_api.Subprocess.__call__],
    ids=["execute", "call"],
)
@pytest.mark.parametrize(EXECUTE_ARGNAMES, EXECUTE_CASES)
async def test_execute(
    fake_async_popen, logger, method, stdin, stdout, stderr, exit_code, open_stdout, open_stderr
) -> None:
    """The command result is built from the process streams and the exit code."""
    proc = fake_async_popen(
        stdout=stdout if open_stdout else None,
        stderr=stderr if open_stderr and stderr is not None else (() if open_stderr else None),
        wait=(exit_code,),
    )
    runner = exec_helpers.async_api.Subprocess()

    res = await method(runner, command, stdin=stdin, open_stdout=open_stdout, open_stderr=open_stderr)

    assert isinstance(res, exec_helpers.async_api.ExecResult)
    assert res == make_result(stdout=stdout or (), stderr=stderr or (), stdin=stdin, exit_code=exit_code)
    if stdin is None:
        proc.stdin.write.assert_not_called()
    else:
        proc.stdin.write.assert_called_once_with(stdin_bytes(stdin))
    assert logger.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=command_log)
    assert logger.mock_calls[-1] == mock.call.log(
        level=logging.DEBUG, msg=f"Command {res.cmd!r} exit code: {res.exit_code!s}"
    )


async def test_context_manager(fake_async_popen) -> None:
    """The runner is locked while the context is open and is released on exit."""
    fake_async_popen()
    runner = exec_helpers.async_api.Subprocess()

    async with runner:
        await runner.execute(command)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(runner.__aenter__(), timeout=0.01)

    await asyncio.wait_for(runner.__aenter__(), timeout=1)
    await runner.__aexit__(None, None, None)
