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

import logging
import typing

import mock
import pytest

import exec_helpers


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


def read_stream(stream: FakeFileStream) -> typing.Tuple[bytes, ...]:
    return tuple([line for line in stream])


host = "127.0.0.1"
host2 = "127.0.0.2"
port = 22
username = "user"
password = "pass"

command = "ls ~\nline 2\nline 3\nline с кирилицей"
command_log = "Executing command:\n{!r}\n".format(command.rstrip())

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


configs = {
    "positive_simple": dict(
        ec=0, stdout=(b" \n", b"2\n", b"3\n", b" \n"), stderr=(), stdin=None, open_stdout=True, open_stderr=True
    ),
    "with_pty": dict(
        ec=0,
        stdout=(b" \n", b"2\n", b"3\n", b" \n"),
        stderr=(),
        stdin=None,
        open_stdout=True,
        open_stderr=True,
        get_pty=True,
    ),
    "with_pty_nonstandard": dict(
        ec=0,
        stdout=(b" \n", b"2\n", b"3\n", b" \n"),
        stderr=(),
        stdin=None,
        open_stdout=True,
        open_stderr=True,
        get_pty=True,
        width=120,
        height=100,
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
    return configs[request.param]


@pytest.fixture
def auto_add_policy(mocker):
    return mocker.patch("paramiko.AutoAddPolicy", return_value="AutoAddPolicy")


@pytest.fixture
def paramiko_ssh_client(mocker):
    mocker.patch("time.sleep")
    return mocker.patch("paramiko.SSHClient")


@pytest.fixture
def chan_makefile(run_parameters):
    class MkFile:
        def __init__(self):
            self.stdin = None
            self.stdout = None
            self.channel = None

        def __call__(self, flags: str):
            if "wb" == flags:
                self.stdin = mock.Mock()
                self.stdin.channel = self.channel
                return self.stdin
            elif "rb" == flags:
                self.stdout = FakeFileStream(*run_parameters["stdout"])
                return self.stdout
            raise ValueError("Unexpected flags: {!r}".format(flags))

    return MkFile()


@pytest.fixture
def ssh_transport_channel(paramiko_ssh_client, chan_makefile, run_parameters):
    chan = mock.Mock(makefile=chan_makefile, closed=False)
    chan_makefile.channel = chan
    if run_parameters["open_stderr"]:
        chan.attach_mock(mock.Mock(return_value=FakeFileStream(*run_parameters["stderr"])), "makefile_stderr")
    chan.configure_mock(exit_status=run_parameters["ec"])
    chan.attach_mock(mock.Mock(return_value=run_parameters["ec"]), "recv_exit_status")
    chan.status_event.attach_mock(mock.Mock(return_value=True), "is_set")
    open_session = mock.Mock(return_value=chan)
    transport = mock.Mock()
    transport.attach_mock(open_session, "open_session")
    get_transport = mock.Mock(return_value=transport)
    _ssh = mock.Mock()
    _ssh.attach_mock(get_transport, "get_transport")
    paramiko_ssh_client.return_value = _ssh
    return chan


@pytest.fixture
def ssh_auth_logger(mocker):
    return mocker.patch("exec_helpers.ssh_auth.logger")


@pytest.fixture
def get_logger(mocker):
    return mocker.patch("logging.getLogger")


@pytest.fixture
def ssh(paramiko_ssh_client, ssh_transport_channel, auto_add_policy, ssh_auth_logger, get_logger):
    return exec_helpers.SSHClient(host=host, port=port, auth=exec_helpers.SSHAuth(username=username, password=password))


@pytest.fixture
def ssh2(paramiko_ssh_client, ssh_transport_channel, auto_add_policy, ssh_auth_logger, get_logger):
    return exec_helpers.SSHClient(
        host=host2, port=port, auth=exec_helpers.SSHAuth(username=username, password=password)
    )


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
def execute_async(mocker, run_parameters):
    def get_patched_execute_async_retval(
        ec=0, stdout=(), stderr=(), open_stdout=True, open_stderr=True, **kwargs
    ) -> exec_helpers.SshExecuteAsyncResult:
        stdout_part = FakeFileStream(*stdout) if open_stdout else None
        stderr_part = FakeFileStream(*stderr) if open_stderr else None

        exit_code = ec
        chan = mock.Mock()
        chan.attach_mock(mock.Mock(return_value=exit_code), "recv_exit_status")

        status_event = mock.Mock()
        status_event.attach_mock(mock.Mock(), "wait")
        chan.attach_mock(status_event, "status_event")
        chan.configure_mock(exit_status=exit_code)
        return exec_helpers.SshExecuteAsyncResult(
            interface=chan, stdin=mock.Mock, stdout=stdout_part, stderr=stderr_part
        )

    return mocker.patch(
        "exec_helpers.ssh_client.SSHClient.execute_async",
        side_effect=[
            get_patched_execute_async_retval(**run_parameters),
            get_patched_execute_async_retval(**run_parameters),
        ],
    )


@pytest.fixture
def execute(mocker, exec_result):
    return mocker.patch("exec_helpers.ssh_client.SSHClient.execute", name="execute", return_value=exec_result)


def teardown_function(function):
    """Clean-up after tests."""
    with mock.patch("warnings.warn"):
        exec_helpers.SSHClient._clear_cache()


def test_001_execute_async(ssh, paramiko_ssh_client, ssh_transport_channel, chan_makefile, run_parameters, get_logger):
    open_stdout = run_parameters["open_stdout"]
    open_stderr = run_parameters["open_stderr"]
    get_pty = run_parameters.get("get_pty", False)

    kwargs = {}
    if "get_pty" in run_parameters:
        kwargs["get_pty"] = get_pty
    if "width" in run_parameters:
        kwargs["width"] = run_parameters["width"]
    if "height" in run_parameters:
        kwargs["height"] = run_parameters["height"]

    res = ssh.execute_async(
        command, stdin=run_parameters["stdin"], open_stdout=open_stdout, open_stderr=open_stderr, **kwargs
    )
    assert isinstance(res, exec_helpers.SshExecuteAsyncResult)
    assert res.interface is ssh_transport_channel
    assert res.stdin is chan_makefile.stdin
    assert res.stdout is chan_makefile.stdout

    paramiko_ssh_client.assert_has_calls(
        (
            mock.call(),
            mock.call().set_missing_host_key_policy("AutoAddPolicy"),
            mock.call().connect(hostname="127.0.0.1", password="pass", pkey=None, port=22, username="user"),
            mock.call().get_transport(),
        )
    )

    transport_calls = []
    if get_pty:
        transport_calls.append(
            mock.call.get_pty(
                term="vt100",
                width=run_parameters.get("width", 80),
                height=run_parameters.get("height", 24),
                width_pixels=0,
                height_pixels=0,
            )
        )
    if open_stderr:
        transport_calls.append(mock.call.makefile_stderr("rb"))
    transport_calls.append(mock.call.exec_command("{}\n".format(command)))

    ssh_transport_channel.assert_has_calls(transport_calls)

    stdout = run_parameters["stdout"]
    stderr = run_parameters["stderr"]

    if open_stdout:
        assert read_stream(res.stdout) == stdout
    else:
        assert res.stdout is None
    if open_stderr:
        assert read_stream(res.stderr) == stderr
    else:
        assert res.stderr is None

    if run_parameters["stdin"] is None:
        stdin = None
    elif isinstance(run_parameters["stdin"], bytes):
        stdin = run_parameters["stdin"].decode("utf-8")
    elif isinstance(run_parameters["stdin"], str):
        stdin = run_parameters["stdin"]
    else:
        stdin = bytes(run_parameters["stdin"]).decode("utf-8")

    assert res.stdin.channel == res.interface

    if stdin:
        res.stdin.write.assert_called_with(stdin.encode("utf-8"))
        res.stdin.flush.assert_called_once()
    log = get_logger(ssh.__class__.__name__).getChild("{host}:{port}".format(host=host, port=port))
    log.log.assert_called_once_with(level=logging.DEBUG, msg=command_log)


def test_002_execute(ssh, ssh_transport_channel, exec_result, run_parameters) -> None:
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
        **kwargs
    )
    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result
    ssh_transport_channel.assert_has_calls((mock.call.status_event.is_set(),))


def test_003_context_manager(ssh, exec_result, run_parameters, mocker) -> None:
    kwargs = {}
    if "get_pty" in run_parameters:
        kwargs["get_pty"] = run_parameters["get_pty"]
    if "width" in run_parameters:
        kwargs["width"] = run_parameters["width"]
    if "height" in run_parameters:
        kwargs["height"] = run_parameters["height"]

    with mocker.patch("threading.RLock") as lock:
        with ssh:
            res = ssh.execute(
                command,
                stdin=run_parameters["stdin"],
                open_stdout=run_parameters["open_stdout"],
                open_stderr=run_parameters["open_stderr"],
                **kwargs
            )
        lock.acquire_assert_called_once()
        lock.release_assert_called_once()
    assert isinstance(res, exec_helpers.ExecResult)
    assert res == exec_result


def test_004_check_call(ssh, exec_result, get_logger, mocker) -> None:
    mocker.patch("exec_helpers.ssh_client.SSHClient.execute", return_value=exec_result)
    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild("{host}:{port}".format(host=host, port=port))

    if exec_result.exit_code == exec_helpers.ExitCodes.EX_OK:
        assert ssh.check_call(command, stdin=exec_result.stdin) == exec_result
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            ssh.check_call(command, stdin=exec_result.stdin)

        exc = e.value  # type: exec_helpers.CalledProcessError
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result
        assert exc.expected == [exec_helpers.ExitCodes.EX_OK]

        assert log.mock_calls[-1] == mock.call.error(
            msg="Command {result.cmd!r} returned exit code {result.exit_code!s} while expected {expected!r}".format(
                result=exc.result, expected=exc.expected
            )
        )


def test_005_check_call_no_raise(ssh, exec_result, get_logger, mocker) -> None:
    mocker.patch("exec_helpers.ssh_client.SSHClient.execute", return_value=exec_result)
    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild("{host}:{port}".format(host=host, port=port))

    res = ssh.check_call(command, stdin=exec_result.stdin, raise_on_err=False)
    assert res == exec_result

    if exec_result.exit_code != exec_helpers.ExitCodes.EX_OK:
        assert log.mock_calls[-1] == mock.call.error(
            msg="Command {result.cmd!r} returned exit code {result.exit_code!s} while expected {expected!r}".format(
                result=res, expected=[exec_helpers.ExitCodes.EX_OK]
            )
        )


def test_006_check_call_expect(ssh, exec_result, mocker) -> None:
    mocker.patch("exec_helpers.ssh_client.SSHClient.execute", return_value=exec_result)
    assert ssh.check_call(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result


def test_007_check_stderr(ssh, exec_result, get_logger, mocker) -> None:
    mocker.patch("exec_helpers.ssh_client.SSHClient.check_call", return_value=exec_result)
    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild("{host}:{port}".format(host=host, port=port))

    if not exec_result.stderr:
        assert ssh.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code]) == exec_result
    else:
        with pytest.raises(exec_helpers.CalledProcessError) as e:
            ssh.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code])
        exc = e.value  # type: exec_helpers.CalledProcessError
        assert exc.result == exec_result
        assert exc.cmd == exec_result.cmd
        assert exc.returncode == exec_result.exit_code
        assert exc.stdout == exec_result.stdout_str
        assert exc.stderr == exec_result.stderr_str
        assert exc.result == exec_result

        assert log.mock_calls[-1] == mock.call.error(
            msg="Command {result.cmd!r} output contains STDERR while not expected\n"
            "\texit code: {result.exit_code!s}".format(result=exc.result)
        )


def test_008_check_stderr_no_raise(ssh, exec_result, mocker) -> None:
    mocker.patch("exec_helpers.ssh_client.SSHClient.check_call", return_value=exec_result)
    assert (
        ssh.check_stderr(command, stdin=exec_result.stdin, expected=[exec_result.exit_code], raise_on_err=False)
        == exec_result
    )


def test_009_execute_together(ssh, ssh2, execute_async, exec_result, run_parameters):

    remotes = [ssh, ssh2]

    if 0 == run_parameters["ec"]:
        results = exec_helpers.SSHClient.execute_together(
            remotes=remotes, command=command, stdin=run_parameters.get("stdin", None)
        )
        execute_async.assert_has_calls(
            (
                mock.call(command, stdin=run_parameters.get("stdin", None)),
                mock.call(command, stdin=run_parameters.get("stdin", None)),
            )
        )
        assert results == {(host, port): exec_result, (host2, port): exec_result}
    else:
        with pytest.raises(exec_helpers.ParallelCallProcessError) as e:
            exec_helpers.SSHClient.execute_together(remotes=remotes, command=command)
        exc = e.value  # type: exec_helpers.ParallelCallProcessError
        assert exc.cmd == command
        assert exc.expected == [exec_helpers.ExitCodes.EX_OK]
        assert exc.results == {(host, port): exec_result, (host2, port): exec_result}


def test_010_execute_together_expected(ssh, ssh2, execute_async, exec_result, run_parameters):
    remotes = [ssh, ssh2]

    results = exec_helpers.SSHClient.execute_together(
        remotes=remotes, command=command, stdin=run_parameters.get("stdin", None), expected=[run_parameters["ec"]]
    )
    execute_async.assert_has_calls(
        (
            mock.call(command, stdin=run_parameters.get("stdin", None)),
            mock.call(command, stdin=run_parameters.get("stdin", None)),
        )
    )
    assert results == {(host, port): exec_result, (host2, port): exec_result}
