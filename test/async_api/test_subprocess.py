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

import asyncio
import logging
import random
from unittest import mock

import pytest

import exec_helpers
from exec_helpers import proc_enums

pytestmark = pytest.mark.skip("Rewrite whole execute tests.")

# All test coroutines will be treated as marked.
# pytestmark = pytest.mark.asyncio

command = "ls ~\nline 2\nline 3\nline c кирилицей"
command_log = f"Executing command:\n{command.rstrip()!r}\n"

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


class FakeFileStream:
    """Mock-like object for stream emulation."""

    def __init__(self, *args):
        self.__src = list(args)

    def __aiter__(self):
        """Normally we iter over source."""
        return self

    async def __anext__(self):
        """Use iterator due to python 3.5 limitations."""
        for _ in range(len(self.__src)):
            return self.__src.pop(0)
        raise StopAsyncIteration()

    def fileno(self):
        return hash(tuple(self.__src))


async def read_stream(stream: FakeFileStream):
    res = [line async for line in stream]
    return tuple(res)


configs = {
    "positive_simple": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": True,
    },
    "with_stderr": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (b" \n", b"0\n", b"1\n", b" \n"),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": True,
    },
    "negative": {
        "ec": 1,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (b" \n", b"0\n", b"1\n", b" \n"),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": True,
    },
    "with_stdin_str": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": "stdin",
        "open_stdout": True,
        "open_stderr": True,
    },
    "with_stdin_bytes": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": b"stdin",
        "open_stdout": True,
        "open_stderr": True,
    },
    "with_stdin_bytearray": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": bytearray(b"stdin"),
        "open_stdout": True,
        "open_stderr": True,
    },
    "no_stderr": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": False,
    },
    "no_stdout": {
        "ec": 0,
        "stdout": (),
        "stderr": (),
        "stdin": None,
        "open_stdout": False,
        "open_stderr": False,
    },
}


def pytest_generate_tests(metafunc):
    """Tests parametrization."""
    if "run_parameters" in metafunc.fixturenames:
        metafunc.parametrize(
            "run_parameters",
            [
                "positive_simple",
                "with_stderr",
                "negative",
                "with_stdin_str",
                "with_stdin_bytes",
                "with_stdin_bytearray",
                "no_stderr",
                "no_stdout",
            ],
            indirect=True,
        )


@pytest.fixture
def run_parameters(request):
    """Tests configuration apply."""
    return configs[request.param]


@pytest.fixture
def exec_result(run_parameters):
    return exec_helpers.ExecResult(
        cmd=command,
        stdin=run_parameters["stdin"],
        stdout=tuple(run_parameters["stdout"]) if run_parameters["stdout"] else None,
        stderr=tuple(run_parameters["stderr"]) if run_parameters["stderr"] else None,
        exit_code=run_parameters["ec"],
    )


@pytest.fixture
def execute(monkeypatch, exec_result):
    subprocess_execute = mock.AsyncMock(
        exec_helpers.async_api.subprocess.Subprocess.execute,
        name="execute",
        return_value=exec_result,
    )
    monkeypatch.setattr(exec_helpers.async_api.subprocess.Subprocess, "execute", subprocess_execute)
    return subprocess_execute


@pytest.fixture
def create_subprocess_shell(mocker, monkeypatch, run_parameters):
    mocker.patch("psutil.Process")

    def create_mock(
        ec: exec_helpers.ExitCodes | int = exec_helpers.ExitCodes.EX_OK,
        stdout: tuple | None = None,
        stderr: tuple | None = None,
        stdin: str | bytes | bytearray | None = None,
        **kwargs,
    ):
        """Parametrized code."""
        proc = mock.AsyncMock()

        run_shell = mock.AsyncMock(
            asyncio.create_subprocess_shell,
            name="create_subprocess_shell",
            return_value=proc,
        )

        proc.configure_mock(pid=random.randint(1025, 65536))

        if stdout is None:
            proc.configure_mock(stdout=None)
        else:
            proc.attach_mock(FakeFileStream(*stdout), "stdout")
        if stderr is None:
            proc.configure_mock(stderr=None)
        else:
            proc.attach_mock(FakeFileStream(*stderr), "stderr")
        if stdin is not None:
            stdin_mock = mock.AsyncMock()
            stdin_mock.attach_mock(mock.AsyncMock("drain"), "drain")
            proc.attach_mock(stdin_mock, "stdin")

        proc.attach_mock(mock.AsyncMock(return_value=int(ec)), "wait")
        proc.configure_mock(returncode=int(ec))

        monkeypatch.setattr(asyncio, "create_subprocess_shell", run_shell)
        return run_shell

    return create_mock(**run_parameters)


@pytest.fixture
def logger(mocker):
    """Simple mock of logger instance."""
    return mocker.patch("exec_helpers.async_api.subprocess.Subprocess.logger", autospec=True)


async def test_002_execute(create_subprocess_shell, logger, exec_result, run_parameters) -> None:
    """Test API without checkers."""
    runner = exec_helpers.async_api.Subprocess()
    res = await runner.execute(command, stdin=run_parameters["stdin"])
    assert isinstance(res, exec_helpers.async_api.ExecResult)
    assert res == exec_result
    assert logger.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=command_log)
    assert logger.mock_calls[-1] == mock.call.log(
        level=logging.DEBUG, msg=f"Command {res.cmd!r} exit code: {res.exit_code!s}"
    )


async def test_003_context_manager(monkeypatch, create_subprocess_shell, logger, exec_result, run_parameters) -> None:
    """Test context manager for threads synchronization."""
    lock = mock.AsyncMock()
    lock.attach_mock(mock.AsyncMock("acquire"), "acquire")
    lock.attach_mock(mock.Mock("release"), "release")
    lock_cls = mock.Mock(asyncio.Lock, name="lock", return_value=lock)
    monkeypatch.setattr(asyncio, "Lock", lock_cls)

    async with exec_helpers.async_api.Subprocess() as runner:
        res = await runner.execute(command, stdin=run_parameters["stdin"])

    lock.acquire.assert_awaited_once()
    lock.release.assert_called_once()
    assert isinstance(res, exec_helpers.async_api.ExecResult)
    assert res == exec_result


async def test_004_check_call(execute, exec_result, logger) -> None:
    """Test exit code validator."""
    runner = exec_helpers.async_api.Subprocess()
    if exec_result.exit_code == exec_helpers.ExitCodes.EX_OK:
        assert await runner.check_call(command, stdin=exec_result.stdin) == exec_result
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            await runner.check_call(command, stdin=exec_result.stdin)

        exc: exec_helpers.CalledProcessError = e.value
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result
        assert exc.expected == (proc_enums.EXPECTED,)

        assert logger.mock_calls[-1] == mock.call.error(
            msg=f"Command {exc.result.cmd!r} returned exit code {exc.result.exit_code!s}"
            f" while expected {exc.expected!r}"
        )


async def test_005_check_call_no_raise(execute, exec_result, logger) -> None:
    """Test exit code validator in permissive mode."""
    runner = exec_helpers.async_api.Subprocess()
    res = await runner.check_call(command, stdin=exec_result.stdin, raise_on_err=False)
    assert res == exec_result
    expected = (proc_enums.EXPECTED,)

    if exec_result.exit_code != exec_helpers.ExitCodes.EX_OK:
        assert logger.mock_calls[-1] == mock.call.error(
            msg=f"Command {res.cmd!r} returned exit code {res.exit_code!s} while expected {expected!r}"
        )


async def test_006_check_call_expect(execute, exec_result, logger) -> None:
    """Test exit code validator with custom return codes."""
    runner = exec_helpers.async_api.Subprocess()
    assert await runner.check_call(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result


async def test_007_check_stderr(execute, exec_result, logger) -> None:
    """Test STDERR content validator."""
    runner = exec_helpers.async_api.Subprocess()
    if not exec_result.stderr:
        assert (
            await runner.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result
        )
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            await runner.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code])

        exc: exec_helpers.CalledProcessError = e.value
        assert exc.result == exec_result
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result

        assert logger.mock_calls[-1] == mock.call.error(
            msg=f"Command {exc.result.cmd!r} output contains STDERR while not expected\n"
            f"\texit code: {exc.result.exit_code!s}"
        )


async def test_008_check_stderr_no_raise(execute, exec_result, logger) -> None:
    """Test STDERR content validator in permissive mode."""
    runner = exec_helpers.async_api.Subprocess()
    assert (
        await runner.check_stderr(
            command,
            stdin=exec_result.stdin,
            expected=[exec_result.exit_code],
            raise_on_err=False,
        )
        == exec_result
    )


async def test_009_call(create_subprocess_shell, logger, exec_result, run_parameters) -> None:
    """Test callable."""
    runner = exec_helpers.async_api.Subprocess()
    res = await runner(command, stdin=run_parameters["stdin"])
    assert isinstance(res, exec_helpers.async_api.ExecResult)
    assert res == exec_result
    assert logger.mock_calls[-1] == mock.call.log(
        level=logging.DEBUG, msg=f"Command {res.cmd!r} exit code: {res.exit_code!s}"
    )
