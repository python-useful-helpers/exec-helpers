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

"""Sync and async Subprocess: validators of the exit code and of the STDERR of the result."""

from __future__ import annotations

import inspect
from unittest import mock

import pytest

import exec_helpers
from exec_helpers import proc_enums
from subprocess_cases import CHECK_CALL_RESULTS
from subprocess_cases import CHECK_STDERR_RESULTS
from subprocess_cases import EXPECTED_CODE_ARGNAMES
from subprocess_cases import EXPECTED_CODE_CASES
from subprocess_cases import command

pytestmark = pytest.mark.asyncio


@pytest.fixture(params=["sync", "async"])
def kind(request) -> str:
    """Select the implementation under test."""
    return request.param


@pytest.fixture
def runner(kind):
    """Runner of the implementation."""
    return exec_helpers.Subprocess() if kind == "sync" else exec_helpers.async_api.Subprocess()


@pytest.fixture
def logger(mocker, kind) -> mock.MagicMock:
    """Mock the logger of the runner."""
    module = "subprocess" if kind == "sync" else "async_api.subprocess"
    return mocker.patch(f"exec_helpers.{module}.Subprocess.logger", autospec=True)


@pytest.fixture
def execute(mocker, kind, request) -> mock.MagicMock:
    """Replace the execution by the prepared result: only the validators are tested with it."""
    if kind == "sync":
        return mocker.patch("exec_helpers.subprocess.Subprocess.execute", return_value=request.param)
    return mocker.patch(
        "exec_helpers.async_api.subprocess.Subprocess.execute",
        new_callable=mocker.AsyncMock,
        return_value=request.param,
    )


async def call(func, *args, **kwargs):
    """Call the validator of the sync or the async runner."""
    result = func(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@pytest.mark.parametrize("raise_on_err", [True, False], ids=["raise", "no_raise"])
@pytest.mark.parametrize("execute", CHECK_CALL_RESULTS, indirect=True)
async def test_check_call(runner, execute, logger, raise_on_err) -> None:
    """The exit code is validated, and the failure is raised only on request."""
    result = execute.return_value
    failed = result.exit_code != exec_helpers.ExitCodes.EX_OK
    expected_log = (
        f"Command {result.cmd!r} returned exit code {result.exit_code!s} while expected {(proc_enums.EXPECTED,)!r}"
        f"\nBrief STDOUT:\n{result.stdout_brief}\n\nBrief STDERR:\n{result.stderr_brief}"
    )

    if failed and raise_on_err:
        with pytest.raises(exec_helpers.CalledProcessError) as exc_info:
            await call(runner.check_call, command, stdin=result.stdin, raise_on_err=raise_on_err)

        exc = exc_info.value
        assert exc.cmd == result.cmd
        assert exc.returncode == result.exit_code
        assert exc.stdout == result.stdout_str
        assert exc.stderr == result.stderr_str
        assert exc.result == result
        assert exc.expected == (proc_enums.EXPECTED,)
    else:
        assert await call(runner.check_call, command, stdin=result.stdin, raise_on_err=raise_on_err) == result

    if failed:
        assert logger.mock_calls[-1] == mock.call.error(msg=expected_log)
    else:
        assert not [log_call for log_call in logger.mock_calls if log_call[0] == "error"]


@pytest.mark.parametrize(EXPECTED_CODE_ARGNAMES, EXPECTED_CODE_CASES, indirect=["execute"])
async def test_check_call_expected(runner, execute, logger, expected, ok) -> None:
    """A custom list of the expected exit codes replaces the default one."""
    if ok:
        assert await call(runner.check_call, command, expected=expected) == execute.return_value
    else:
        with pytest.raises(exec_helpers.CalledProcessError):
            await call(runner.check_call, command, expected=expected)


@pytest.mark.parametrize("raise_on_err", [True, False], ids=["raise", "no_raise"])
@pytest.mark.parametrize("execute", CHECK_STDERR_RESULTS, indirect=True)
async def test_check_stderr(runner, execute, logger, raise_on_err) -> None:
    """The STDERR content is validated, and the failure is raised only on request."""
    result = execute.return_value
    kwargs = {"expected": [result.exit_code], "raise_on_err": raise_on_err}

    if result.stderr and raise_on_err:
        with pytest.raises(exec_helpers.CalledProcessError) as exc_info:
            await call(runner.check_stderr, command, **kwargs)

        exc = exc_info.value
        assert exc.result == result
        assert exc.cmd == result.cmd
        assert exc.returncode == result.exit_code
        assert exc.stdout == result.stdout_str
        assert exc.stderr == result.stderr_str
    else:
        assert await call(runner.check_stderr, command, **kwargs) == result

    if result.stderr:
        assert logger.mock_calls[-1] == mock.call.error(
            msg=f"Command {result.cmd!r} output contains STDERR while not expected\n\texit code: {result.exit_code!s}"
        )
