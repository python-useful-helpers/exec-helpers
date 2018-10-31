# coding=utf-8

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

from __future__ import absolute_import
from __future__ import unicode_literals

import logging
import random
import subprocess
import typing  # noqa: F401

import mock
import pytest

import exec_helpers
from exec_helpers import subprocess_runner
from exec_helpers import _subprocess_helpers

# All test coroutines will be treated as marked.

command = "ls ~\nline 2\nline 3\nline с кирилицей"
command_log = "Executing command:\n{!r}\n".format(command.rstrip())

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


class FakeFileStream(object):
    """Mock-like object for stream emulation."""

    def __init__(self, *args):
        self.__src = list(args)
        self.closed = False

    def __iter__(self):
        """Normally we iter over source."""
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)

    def fileno(self):
        return hash(tuple(self.__src))

    def close(self):
        """We enforce close."""
        self.closed = True


def read_stream(stream):  # type: (FakeFileStream) -> typing.Tuple[bytes]
    return tuple([line for line in stream])


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
def execute(mocker, exec_result):
    return mocker.patch("exec_helpers.subprocess_runner.Subprocess.execute", name="execute", return_value=exec_result)


@pytest.fixture
def popen(mocker, run_parameters):
    mocker.patch("psutil.Process")

    def create_mock(
        ec=exec_helpers.ExitCodes.EX_OK,  # type: typing.Union[exec_helpers.ExitCodes, int]
        stdout=None,  # type: typing.Optional[typing.Tuple]
        stderr=None,  # type: typing.Optional[typing.Tuple]
        **kwargs
    ):
        """Parametrized code."""
        proc = mock.Mock()
        proc.configure_mock(pid=random.randint(1025, 65536))

        if stdout is None:
            proc.configure_mock(stdout=None)
        else:
            proc.attach_mock(FakeFileStream(*stdout), "stdout")
        if stderr is None:
            proc.configure_mock(stderr=None)
        else:
            proc.attach_mock(FakeFileStream(*stderr), "stderr")

        proc.attach_mock(mock.Mock(return_value=int(ec)), "wait")
        proc.attach_mock(mock.Mock(return_value=int(ec)), "poll")
        proc.configure_mock(returncode=int(ec))

        run_shell = mocker.patch("subprocess.Popen", name="popen", return_value=proc)
        return run_shell

    return create_mock(**run_parameters)


@pytest.fixture
def logger(mocker):
    return mocker.patch("exec_helpers.subprocess_runner.Subprocess.logger", autospec=True)


def test_001_execute_async(popen, logger, run_parameters):
    runner = exec_helpers.Subprocess()
    res = runner.execute_async(
        command,
        stdin=run_parameters["stdin"],
        open_stdout=run_parameters["open_stdout"],
        open_stderr=run_parameters["open_stderr"],
    )
    assert isinstance(res, exec_helpers.SubprocessExecuteAsyncResult)
    assert res.interface.wait() == run_parameters["ec"]
    assert res.interface.returncode == run_parameters["ec"]

    stdout = run_parameters["stdout"]
    stderr = run_parameters["stderr"]

    if stdout is not None:
        assert read_stream(res.stdout) == stdout
    else:
        assert res.stdout is stdout
    if stderr is not None:
        assert read_stream(res.stderr) == stderr
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

    popen.assert_called_once_with(
        args=[command],
        stdout=subprocess.PIPE if run_parameters["open_stdout"] else subprocess_runner.devnull,
        stderr=subprocess.PIPE if run_parameters["open_stderr"] else subprocess_runner.devnull,
        stdin=subprocess.PIPE,
        shell=True,
        cwd=run_parameters.get("cwd", None),
        env=run_parameters.get("env", None),
        universal_newlines=False,
        **_subprocess_helpers.subprocess_kw
    )

    if stdin is not None:
        res.interface.stdin.write.assert_called_once_with(stdin)
        res.interface.stdin.close.assert_called_once()
    logger.log.assert_called_once_with(level=logging.DEBUG, msg=command_log)


def test_002_execute(popen, logger, exec_result, run_parameters):
    runner = exec_helpers.Subprocess()
    res = runner.execute(
        command,
        stdin=run_parameters["stdin"],
        open_stdout=run_parameters["open_stdout"],
        open_stderr=run_parameters["open_stderr"],
    )
    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result
    popen().wait.assert_called_once_with()
    popen().poll.assert_called_once_with()


def test_003_context_manager(mocker, popen, logger, exec_result, run_parameters):
    with mocker.patch("threading.RLock") as lock:
        with exec_helpers.Subprocess() as runner:
            res = runner.execute(command, stdin=run_parameters["stdin"])
        lock.acquire_assert_called_once()
        lock.release_assert_called_once()
    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result


def test_004_check_call(execute, exec_result, logger):
    runner = exec_helpers.Subprocess()
    if exec_result.exit_code == exec_helpers.ExitCodes.EX_OK:
        assert runner.check_call(command, stdin=exec_result.stdin) == exec_result
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            runner.check_call(command, stdin=exec_result.stdin)

        exc = e.value  # type: exec_helpers.CalledProcessError
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result
        assert exc.expected == [exec_helpers.ExitCodes.EX_OK]

        assert logger.mock_calls[-1] == mock.call.error(
            msg="Command {result.cmd!r} returned exit code {result.exit_code!s} while expected {expected!r}".format(
                result=exc.result, expected=exc.expected
            )
        )


def test_005_check_call_no_raise(execute, exec_result, logger):
    runner = exec_helpers.Subprocess()
    res = runner.check_call(command, stdin=exec_result.stdin, raise_on_err=False)
    assert res == exec_result

    if exec_result.exit_code != exec_helpers.ExitCodes.EX_OK:
        assert logger.mock_calls[-1] == mock.call.error(
            msg="Command {result.cmd!r} returned exit code {result.exit_code!s} while expected {expected!r}".format(
                result=res, expected=[exec_helpers.ExitCodes.EX_OK]
            )
        )


def test_006_check_call_expect(execute, exec_result, logger):
    runner = exec_helpers.Subprocess()
    assert runner.check_call(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result


def test_007_check_stderr(execute, exec_result, logger):
    runner = exec_helpers.Subprocess()
    if not exec_result.stderr:
        assert runner.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            runner.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code])
        exc = e.value  # type: exec_helpers.CalledProcessError
        assert exc.result == exec_result
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result

        assert logger.mock_calls[-1] == mock.call.error(
            msg="Command {result.cmd!r} output contains STDERR while not expected\n"
            "\texit code: {result.exit_code!s}".format(result=exc.result)
        )


def test_008_check_stderr_no_raise(execute, exec_result, logger):
    runner = exec_helpers.Subprocess()
    assert (
        runner.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code], raise_on_err=False)
        == exec_result
    )
