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

import asyncio
import errno
import logging
import random
import typing

import asynctest
import mock
import pytest

import exec_helpers

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio

command = "ls ~\nline 2\nline 3\nline с кирилицей"
command_log = "Executing command:\n{!r}\n".format(command.rstrip())

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
            val = self.__src.pop(0)
            if isinstance(val, bytes):
                return val
            elif isinstance(val, BaseException):
                raise val
            else:
                raise TypeError(val)
        raise StopAsyncIteration()

    def fileno(self):
        return hash(tuple(self.__src))


async def read_stream(stream: FakeFileStream):
    res = []
    async for line in stream:
        res.append(line)
    return tuple(res)


einval_exc = OSError()
einval_exc.errno = errno.EINVAL
epipe_exc = OSError()
epipe_exc.errno = errno.EPIPE
eshutdown_exc = OSError()
eshutdown_exc.errno = errno.ESHUTDOWN


configs = {
    "positive_simple": dict(stdout=(b" \n", b"2\n", b"3\n", b" \n")),
    "positive_verbose": dict(stdout=(b" \n", b"2\n", b"3\n", b" \n"), verbose=True),
    "no_stdout": dict(),
    "IOError_on_stdout_read": dict(stdout=(b" \n", b"2\n", IOError())),
    "TimeoutError": dict(ec=(asyncio.TimeoutError(), None), stdout=(), expect_exc=exec_helpers.ExecHelperTimeoutError),
    "TimeoutError_no_kill": dict(ec=(asyncio.TimeoutError(), None), stdout=(), kill=(OSError(),), expect_exc=OSError),
    "stdin_closed_PIPE_windows": dict(stdout=(b" \n", b"2\n", b"3\n", b" \n"), stdin="Warning", write=einval_exc),
    "stdin_broken_PIPE": dict(stdout=(b" \n", b"2\n", b"3\n", b" \n"), stdin="Warning", write=epipe_exc),
    "stdin_closed_PIPE": dict(stdout=(b" \n", b"2\n", b"3\n", b" \n"), stdin="Warning", write=eshutdown_exc),
    "stdin_error": dict(ec=(0xDEADBEEF,), stdout=(), stdin="Failed", write=OSError(), expect_exc=OSError),
    "stdin_close_closed": dict(stdout=(b" \n", b"2\n", b"3\n", b" \n"), stdin="Stdin", stdin_close=eshutdown_exc),
    "stdin_close_fail": dict(ec=(0xDEADBEEF,), stdout=(), stdin="Failed", stdin_close=OSError(), expect_exc=OSError),
    "mask_global": dict(
        command="USE='secret=secret_pass' do task",
        init_log_mask_re=r"secret\s*=\s*([A-Z-a-z0-9_\-]+)",
        masked_cmd="USE='secret=<*masked*>' do task",
    ),
    "mask_local": dict(
        command="USE='secret=secret_pass' do task",
        log_mask_re=r"secret\s*=\s*([A-Z-a-z0-9_\-]+)",
        masked_cmd="USE='secret=<*masked*>' do task",
    ),
}


def pytest_generate_tests(metafunc):
    if "run_parameters" in metafunc.fixturenames:
        metafunc.parametrize(
            "run_parameters",
            [
                "positive_simple",
                "positive_verbose",
                "no_stdout",
                "IOError_on_stdout_read",
                "TimeoutError",
                "TimeoutError_no_kill",
                "stdin_closed_PIPE_windows",
                "stdin_broken_PIPE",
                "stdin_closed_PIPE",
                "stdin_error",
                "stdin_close_closed",
                "stdin_close_fail",
                "mask_global",
                "mask_local",
            ],
            indirect=True,
        )


@pytest.fixture
def run_parameters(request):
    return configs[request.param]


@pytest.fixture
def exec_result(run_parameters):
    stdout = run_parameters.get("stdout", None)
    if stdout is None:
        stdout_res = None
    else:
        stdout_res = tuple([elem for elem in run_parameters["stdout"] if isinstance(elem, bytes)])

    return exec_helpers.ExecResult(
        cmd=run_parameters.get("masked_cmd", command),
        stdin=run_parameters.get("stdin", None),
        stdout=stdout_res,
        stderr=(),
        exit_code=0 if 0 in run_parameters.get("ec", [0]) else exec_helpers.ExitCodes.EX_INVALID,
    )


@pytest.fixture
def create_subprocess_shell(mocker, monkeypatch, run_parameters):
    mocker.patch("psutil.Process")

    def create_mock(
        stdout: typing.Optional[typing.Tuple] = None,
        stdin: typing.Optional[typing.Union[str, bytes, bytearray]] = None,
        **kwargs
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

        proc.configure_mock(stderr=None)

        if stdin is not None:
            stdin_mock = asynctest.CoroutineMock()

            stdin_mock.attach_mock(mock.Mock("write", side_effect=run_parameters.get("write", None)), "write")
            stdin_mock.attach_mock(asynctest.CoroutineMock("drain"), "drain")
            stdin_mock.attach_mock(mock.Mock(side_effect=run_parameters.get("stdin_close", None)), "close")

            proc.attach_mock(stdin_mock, "stdin")

        proc.attach_mock(asynctest.CoroutineMock(side_effect=run_parameters.get("ec", (0,))), "wait")
        proc.configure_mock(returncode=(0,))

        proc.attach_mock(mock.Mock(side_effect=run_parameters.get("kill", None)), "kill")

        monkeypatch.setattr(asyncio, "create_subprocess_shell", run_shell)
        return run_shell

    return create_mock(**run_parameters)


@pytest.fixture
def logger(mocker):
    return mocker.patch("exec_helpers.async_api.subprocess_runner.Subprocess.logger", autospec=True)


async def test_special_cases(create_subprocess_shell, exec_result, logger, run_parameters) -> None:
    runner = exec_helpers.async_api.Subprocess(log_mask_re=run_parameters.get("init_log_mask_re", None))
    if "expect_exc" not in run_parameters:
        res = await runner.execute(
            command=run_parameters.get("command", command),
            stdin=run_parameters.get("stdin", None),
            verbose=run_parameters.get("verbose", None),
            log_mask_re=run_parameters.get("log_mask_re", None),
        )
        level = logging.INFO if run_parameters.get("verbose", False) else logging.DEBUG

        command_for_log = run_parameters.get("masked_cmd", command)
        command_log = "Executing command:\n{!r}\n".format(command_for_log.rstrip())
        result_log = "Command {command!r} exit code: {result.exit_code!s}".format(
            command=command_for_log.rstrip(), result=res
        )

        assert logger.mock_calls[0] == mock.call.log(level=level, msg=command_log)
        assert logger.mock_calls[-1] == mock.call.log(level=level, msg=result_log)
        assert res == exec_result
    else:
        with pytest.raises(run_parameters["expect_exc"]):
            await runner.execute(
                command, stdin=run_parameters.get("stdin", None), verbose=run_parameters.get("verbose", None)
            )
