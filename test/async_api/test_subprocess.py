#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.
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

# Standard Library
import asyncio
import logging
import random
import sys
import typing
from unittest import mock

# External Dependencies
import asynctest
import pytest

# Exec-Helpers Implementation
import exec_helpers
from exec_helpers import _subprocess_helpers
from exec_helpers import proc_enums
from exec_helpers.async_api.subprocess import SubprocessExecuteAsyncResult

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio

command = "ls ~\nline 2\nline 3\nline с кирилицей"
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
    res = []
    async for line in stream:
        res.append(line)
    return tuple(res)


configs = {
    "positive_simple": dict(
        ec=0, stdout=(b" \n", b"2\n", b"3\n", b" \n"), stderr=(), stdin=None, open_stdout=True, open_stderr=True
    ),
    "with_stderr": dict(
        ec=0,
        stdout=(b" \n", b"2\n", b"3\n", b" \n"),
        stderr=(b" \n", b"0\n", b"1\n", b" \n"),
        stdin=None,
        open_stdout=True,
        open_stderr=True,
    ),
    "negative": dict(
        ec=1,
        stdout=(b" \n", b"2\n", b"3\n", b" \n"),
        stderr=(b" \n", b"0\n", b"1\n", b" \n"),
        stdin=None,
        open_stdout=True,
        open_stderr=True,
    ),
    "with_stdin_str": dict(
        ec=0, stdout=(b" \n", b"2\n", b"3\n", b" \n"), stderr=(), stdin="stdin", open_stdout=True, open_stderr=True
    ),
    "with_stdin_bytes": dict(
        ec=0, stdout=(b" \n", b"2\n", b"3\n", b" \n"), stderr=(), stdin=b"stdin", open_stdout=True, open_stderr=True
    ),
    "with_stdin_bytearray": dict(
        ec=0,
        stdout=(b" \n", b"2\n", b"3\n", b" \n"),
        stderr=(),
        stdin=bytearray(b"stdin"),
        open_stdout=True,
        open_stderr=True,
    ),
    "no_stderr": dict(
        ec=0, stdout=(b" \n", b"2\n", b"3\n", b" \n"), stderr=(), stdin=None, open_stdout=True, open_stderr=False
    ),
    "no_stdout": dict(ec=0, stdout=(), stderr=(), stdin=None, open_stdout=False, open_stderr=False),
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
        stdout=tuple([line for line in run_parameters["stdout"]]) if run_parameters["stdout"] else None,
        stderr=tuple([line for line in run_parameters["stderr"]]) if run_parameters["stderr"] else None,
        exit_code=run_parameters["ec"],
    )


@pytest.fixture
def execute(monkeypatch, exec_result):
    subprocess_execute = asynctest.CoroutineMock(
        exec_helpers.async_api.subprocess.Subprocess.execute, name="execute", return_value=exec_result
    )
    monkeypatch.setattr(exec_helpers.async_api.subprocess.Subprocess, "execute", subprocess_execute)
    return subprocess_execute


@pytest.fixture
def create_subprocess_shell(mocker, monkeypatch, run_parameters):
    mocker.patch("exec_helpers._subprocess_helpers.Process")

    def create_mock(
        ec: typing.Union[exec_helpers.ExitCodes, int] = exec_helpers.ExitCodes.EX_OK,
        stdout: typing.Optional[typing.Tuple] = None,
        stderr: typing.Optional[typing.Tuple] = None,
        stdin: typing.Optional[typing.Union[str, bytes, bytearray]] = None,
        **kwargs,
    ):
        """Parametrized code."""
        proc = asynctest.CoroutineMock()

        run_shell = asynctest.CoroutineMock(
            asyncio.create_subprocess_shell, name="create_subprocess_shell", return_value=proc
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
            stdin_mock = asynctest.CoroutineMock()
            stdin_mock.attach_mock(asynctest.CoroutineMock("drain"), "drain")
            proc.attach_mock(stdin_mock, "stdin")

        proc.attach_mock(asynctest.CoroutineMock(return_value=int(ec)), "wait")
        proc.configure_mock(returncode=int(ec))

        monkeypatch.setattr(asyncio, "create_subprocess_shell", run_shell)
        return run_shell

    return create_mock(**run_parameters)


@pytest.fixture
def logger(mocker):
    """Simple mock of logger instance."""
    return mocker.patch("exec_helpers.async_api.subprocess.Subprocess.logger", autospec=True)


@pytest.mark.skip(reason="Stuck if called from CI")
async def test_001_execute_async(create_subprocess_shell, logger, run_parameters) -> None:
    """Test low level API."""
    runner = exec_helpers.async_api.Subprocess()
    res = await runner._execute_async(
        command,
        stdin=run_parameters["stdin"],
        open_stdout=run_parameters["open_stdout"],
        open_stderr=run_parameters["open_stderr"],
    )
    assert isinstance(res, SubprocessExecuteAsyncResult)
    assert await res.interface.wait() == run_parameters["ec"]
    assert res.interface.returncode == run_parameters["ec"]

    stdout = run_parameters["stdout"]
    stderr = run_parameters["stderr"]

    if stdout is not None:
        assert await read_stream(res.stdout) == stdout
    else:
        assert res.stdout is stdout
    if stderr is not None:
        assert await read_stream(res.stderr) == stderr
    else:
        assert res.stderr is stderr

    if run_parameters["stdin"] is None:
        stdin = None
    elif isinstance(run_parameters["stdin"], bytes):
        stdin = run_parameters["stdin"]
    elif isinstance(run_parameters["stdin"], str):
        stdin = run_parameters["stdin"].encode(encoding="utf-8")
    else:
        stdin = bytes(run_parameters["stdin"])
    if stdin:
        assert res.stdin is None

    create_subprocess_shell.assert_awaited_once_with(
        cmd=command,
        stdout=asyncio.subprocess.PIPE if run_parameters["open_stdout"] else asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE if run_parameters["open_stderr"] else asyncio.subprocess.DEVNULL,
        stdin=asyncio.subprocess.PIPE,
        cwd=run_parameters.get("cwd", None),
        env=run_parameters.get("env", None),
        universal_newlines=False,
        **_subprocess_helpers.subprocess_kw,
    )

    if stdin is not None:
        res.interface.stdin.write.assert_called_once_with(stdin)
        res.interface.stdin.drain.assert_awaited_once()


@pytest.mark.skip(reason="Stuck if called from CI")
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


@pytest.mark.skip(reason="Stuck if called from CI")
async def test_003_context_manager(monkeypatch, create_subprocess_shell, logger, exec_result, run_parameters) -> None:
    """Test context manager for threads synchronization."""
    lock = asynctest.CoroutineMock()
    lock.attach_mock(asynctest.CoroutineMock("acquire"), "acquire")
    lock.attach_mock(mock.Mock("release"), "release")
    lock_cls = mock.Mock(asyncio.Lock, name="lock", return_value=lock)
    monkeypatch.setattr(asyncio, "Lock", lock_cls)

    async with exec_helpers.async_api.Subprocess() as runner:
        res = await runner.execute(command, stdin=run_parameters["stdin"])

    lock.acquire.assert_awaited_once()
    lock.release.assert_called_once()
    assert isinstance(res, exec_helpers.async_api.ExecResult)
    assert res == exec_result


@pytest.mark.skip(reason="Stuck if called from CI")
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


@pytest.mark.skip(reason="Stuck if called from CI")
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


@pytest.mark.skip(reason="Stuck if called from CI")
async def test_006_check_call_expect(execute, exec_result, logger) -> None:
    """Test exit code validator with custom return codes."""
    runner = exec_helpers.async_api.Subprocess()
    assert await runner.check_call(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result


@pytest.mark.skip(reason="Stuck if called from CI")
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


@pytest.mark.skip(reason="Stuck if called from CI")
async def test_008_check_stderr_no_raise(execute, exec_result, logger) -> None:
    """Test STDERR content validator in permissive mode."""
    runner = exec_helpers.async_api.Subprocess()
    assert (
        await runner.check_stderr(
            command, stdin=exec_result.stdin, expected=[exec_result.exit_code], raise_on_err=False
        )
        == exec_result
    )


@pytest.mark.skip(reason="Stuck if called from CI")
async def test_009_call(create_subprocess_shell, logger, exec_result, run_parameters) -> None:
    """Test callable."""
    runner = exec_helpers.async_api.Subprocess()
    res = await runner(command, stdin=run_parameters["stdin"])
    assert isinstance(res, exec_helpers.async_api.ExecResult)
    assert res == exec_result
    assert logger.mock_calls[-1] == mock.call.log(
        level=logging.DEBUG, msg=f"Command {res.cmd!r} exit code: {res.exit_code!s}"
    )
