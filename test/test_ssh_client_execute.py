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

import datetime
import logging
from unittest import mock

import pytest

import exec_helpers
from exec_helpers import proc_enums
from exec_helpers._ssh_base import SshExecuteAsyncResult

pytestmark = pytest.mark.skip("Rewrite whole execute tests.")


class FakeFileStream:
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


def read_stream(stream: FakeFileStream) -> tuple[bytes, ...]:
    return tuple(stream)


host = "127.0.0.1"
host2 = "127.0.0.2"
port = 22
username = "user"
password = "pass"

command = "ls ~\nline 2\nline 3\nline c кирилицей"
command_log = f"Executing command:\n{command.rstrip()!r}\n"

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


configs = {
    "positive_simple": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": True,
    },
    "with_pty": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": True,
        "get_pty": True,
    },
    "with_pty_nonstandard": {
        "ec": 0,
        "stdout": (b" \n", b"2\n", b"3\n", b" \n"),
        "stderr": (),
        "stdin": None,
        "open_stdout": True,
        "open_stderr": True,
        "get_pty": True,
        "width": 120,
        "height": 100,
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
                "with_pty",
                "with_pty_nonstandard",
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
def chan_makefile(run_parameters):
    class MkFile:
        def __init__(self):
            self.stdin = None
            self.stdout = None
            self.channel = None

        def __call__(self, flags: str):
            if flags == "wb":
                self.stdin = mock.Mock()
                self.stdin.channel = self.channel
                return self.stdin
            if flags == "rb":
                self.stdout = FakeFileStream(*run_parameters["stdout"])
                return self.stdout
            raise ValueError(f"Unexpected flags: {flags!r}")

    return MkFile()


@pytest.fixture
def ssh_transport_channel(paramiko_ssh_client, chan_makefile, run_parameters):
    chan = mock.Mock(makefile=chan_makefile, closed=False)
    chan_makefile.channel = chan
    if run_parameters["open_stderr"]:
        chan.attach_mock(
            mock.Mock(return_value=FakeFileStream(*run_parameters["stderr"])),
            "makefile_stderr",
        )
    chan.configure_mock(exit_status=run_parameters["ec"])
    chan.attach_mock(mock.Mock(return_value=run_parameters["ec"]), "recv_exit_status")
    chan.status_event.attach_mock(mock.Mock(return_value=True), "is_set")
    open_session = mock.Mock(return_value=chan)
    transport = mock.Mock()
    transport.attach_mock(open_session, "open_session")
    get_transport = mock.Mock(return_value=transport)
    ssh_ = mock.Mock()
    ssh_.attach_mock(get_transport, "get_transport")
    paramiko_ssh_client.return_value = ssh_
    return chan


@pytest.fixture
def ssh(
    paramiko_ssh_client,
    ssh_transport_channel,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    return exec_helpers.SSHClient(
        host=host,
        port=port,
        auth=exec_helpers.SSHAuth(username=username, password=password),
    )


@pytest.fixture
def ssh2(
    paramiko_ssh_client,
    ssh_transport_channel,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    return exec_helpers.SSHClient(
        host=host2,
        port=port,
        auth=exec_helpers.SSHAuth(username=username, password=password),
    )


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
def execute_async(mocker, run_parameters):
    def get_patched_execute_async_retval(
        ec=0, stdout=(), stderr=(), open_stdout=True, open_stderr=True, **kwargs
    ) -> SshExecuteAsyncResult:
        stdout_part = FakeFileStream(*stdout) if open_stdout else None
        stderr_part = FakeFileStream(*stderr) if open_stderr else None

        exit_code = ec
        chan = mock.Mock()
        chan.attach_mock(mock.Mock(return_value=exit_code), "recv_exit_status")

        status_event = mock.Mock()
        status_event.attach_mock(mock.Mock(), "wait")
        chan.attach_mock(status_event, "status_event")
        chan.configure_mock(exit_status=exit_code)
        return SshExecuteAsyncResult(
            interface=chan,
            stdin=mock.Mock,
            stdout=stdout_part,
            stderr=stderr_part,
            started=datetime.datetime.now(tz=datetime.timezone.utc),
        )

    return mocker.patch(
        "exec_helpers.ssh.SSHClient._execute_async",
        side_effect=[
            get_patched_execute_async_retval(**run_parameters),
            get_patched_execute_async_retval(**run_parameters),
        ],
    )


@pytest.fixture
def execute(mocker, exec_result):
    return mocker.patch(
        "exec_helpers.ssh.SSHClient.execute",
        name="execute",
        return_value=exec_result,
    )


def test_002_execute(
    ssh,
    ssh_transport_channel,
    exec_result,
    run_parameters,
    get_logger,
) -> None:
    kwargs = {}
    if "get_pty" in run_parameters:
        kwargs["get_pty"] = run_parameters["get_pty"]
    if "width" in run_parameters:
        kwargs["width"] = run_parameters["width"]
    if "height" in run_parameters:
        kwargs["height"] = run_parameters["height"]

    res = ssh.execute(
        command,
        stdin=run_parameters["stdin"],
        open_stdout=run_parameters["open_stdout"],
        open_stderr=run_parameters["open_stderr"],
        **kwargs,
    )
    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result
    ssh_transport_channel.assert_has_calls((mock.call.status_event.is_set(),))
    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:22")
    assert log.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=command_log)


def test_003_context_manager(ssh, exec_result, run_parameters, mocker) -> None:
    kwargs = {}
    if "get_pty" in run_parameters:
        kwargs["get_pty"] = run_parameters["get_pty"]
    if "width" in run_parameters:
        kwargs["width"] = run_parameters["width"]
    if "height" in run_parameters:
        kwargs["height"] = run_parameters["height"]

    lock_mock = mocker.patch("threading.RLock")

    with ssh:
        res = ssh.execute(
            command,
            stdin=run_parameters["stdin"],
            open_stdout=run_parameters["open_stdout"],
            open_stderr=run_parameters["open_stderr"],
            **kwargs,
        )
    lock_mock.acquire_assert_called_once()
    lock_mock.release_assert_called_once()

    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result


def test_004_check_call(ssh, exec_result, get_logger, mocker) -> None:
    mocker.patch("exec_helpers.ssh.SSHClient.execute", return_value=exec_result)
    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild(f"{host}:{port}")

    if exec_result.exit_code == exec_helpers.ExitCodes.EX_OK:
        assert ssh.check_call(command, stdin=exec_result.stdin) == exec_result
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            ssh.check_call(command, stdin=exec_result.stdin)

        exc: exec_helpers.CalledProcessError = e.value
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result
        assert exc.expected == (proc_enums.EXPECTED,)

        assert log.mock_calls[-1] == mock.call.error(
            msg=f"Command {exc.result.cmd!r} returned exit code {exc.result.exit_code!s} "
            f"while expected {exc.expected!r}"
        )


def test_005_check_call_no_raise(ssh, exec_result, get_logger, mocker) -> None:
    mocker.patch("exec_helpers.ssh.SSHClient.execute", return_value=exec_result)
    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild(f"{host}:{port}")

    res = ssh.check_call(command, stdin=exec_result.stdin, raise_on_err=False)
    assert res == exec_result
    expected = (proc_enums.EXPECTED,)

    if exec_result.exit_code != exec_helpers.ExitCodes.EX_OK:
        assert log.mock_calls[-1] == mock.call.error(
            msg=f"Command {res.cmd!r} returned exit code {res.exit_code!s} while expected {expected!r}"
        )


def test_006_check_call_expect(ssh, exec_result, mocker) -> None:
    mocker.patch("exec_helpers.ssh.SSHClient.execute", return_value=exec_result)
    assert ssh.check_call(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result


def test_007_check_stderr(ssh, exec_result, get_logger, mocker) -> None:
    mocker.patch("exec_helpers.ssh.SSHClient.check_call", return_value=exec_result)
    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild(f"{host}:{port}")

    if not exec_result.stderr:
        assert (
            ssh.check_stderr(
                command,
                stdin=exec_result.stdin,
                expected=[exec_result.exit_code],
            )
            == exec_result
        )
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            ssh.check_stderr(
                command,
                stdin=exec_result.stdin,
                expected=[exec_result.exit_code],
            )
        exc: exec_helpers.CalledProcessError = e.value
        assert exc.result == exec_result
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result

        assert log.mock_calls[-1] == mock.call.error(
            msg=f"Command {exc.result.cmd!r} output contains STDERR while not expected\n"
            f"\texit code: {exc.result.exit_code!s}"
        )


def test_008_check_stderr_no_raise(ssh, exec_result, mocker) -> None:
    mocker.patch("exec_helpers.ssh.SSHClient.check_call", return_value=exec_result)
    assert (
        ssh.check_stderr(
            command,
            stdin=exec_result.stdin,
            expected=[exec_result.exit_code],
            raise_on_err=False,
        )
        == exec_result
    )


def test_009_execute_together(ssh, ssh2, execute_async, exec_result, run_parameters):
    remotes = [ssh, ssh2]

    if run_parameters["ec"] == 0:
        results = exec_helpers.SSHClient.execute_together(
            remotes=remotes,
            command=command,
            stdin=run_parameters["stdin"],
            open_stdout=run_parameters["open_stdout"],
            open_stderr=run_parameters["open_stderr"],
        )
        execute_async.assert_has_calls(
            (
                mock.call(
                    command,
                    stdin=run_parameters["stdin"],
                    log_mask_re=None,
                    open_stdout=run_parameters["open_stdout"],
                    open_stderr=run_parameters["open_stderr"],
                    timeout=default_timeout,
                ),
                mock.call(
                    command,
                    stdin=run_parameters["stdin"],
                    log_mask_re=None,
                    open_stdout=run_parameters["open_stdout"],
                    open_stderr=run_parameters["open_stderr"],
                    timeout=default_timeout,
                ),
            )
        )
        assert results == {(host, port): exec_result, (host2, port): exec_result}
    else:
        with pytest.raises(exec_helpers.ParallelCallProcessError) as e:
            exec_helpers.SSHClient.execute_together(remotes=remotes, command=command)
        exc: exec_helpers.ParallelCallProcessError = e.value
        assert exc.cmd == command
        assert exc.expected == (proc_enums.EXPECTED,)
        assert exc.results == {(host, port): exec_result, (host2, port): exec_result}


def test_010_execute_together_expected(
    ssh,
    ssh2,
    execute_async,
    exec_result,
    run_parameters,
):
    remotes = [ssh, ssh2]

    results = exec_helpers.SSHClient.execute_together(
        remotes=remotes,
        command=command,
        stdin=run_parameters["stdin"],
        open_stdout=run_parameters["open_stdout"],
        open_stderr=run_parameters["open_stderr"],
        expected=[run_parameters["ec"]],
    )
    execute_async.assert_has_calls(
        (
            mock.call(
                command,
                stdin=run_parameters.get("stdin", None),
                log_mask_re=None,
                open_stdout=run_parameters["open_stdout"],
                open_stderr=run_parameters["open_stderr"],
                timeout=default_timeout,
            ),
            mock.call(
                command,
                stdin=run_parameters.get("stdin", None),
                log_mask_re=None,
                open_stdout=run_parameters["open_stdout"],
                open_stderr=run_parameters["open_stderr"],
                timeout=default_timeout,
            ),
        )
    )
    assert results == {(host, port): exec_result, (host2, port): exec_result}


def test_011_call(ssh, ssh_transport_channel, exec_result, run_parameters) -> None:
    kwargs = {}
    if "get_pty" in run_parameters:
        kwargs["get_pty"] = run_parameters["get_pty"]
    if "width" in run_parameters:
        kwargs["width"] = run_parameters["width"]
    if "height" in run_parameters:
        kwargs["height"] = run_parameters["height"]

    res = ssh(
        command,
        stdin=run_parameters["stdin"],
        open_stdout=run_parameters["open_stdout"],
        open_stderr=run_parameters["open_stderr"],
        **kwargs,
    )
    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result
    ssh_transport_channel.assert_has_calls((mock.call.status_event.is_set(),))
