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

# Standard Library
import pathlib
import shlex
import typing
from unittest import mock

# External Dependencies
import pytest

# Exec-Helpers Implementation
import exec_helpers


class FakeFileStream:
    """Mock-like object for stream emulation."""

    def __init__(self, *args):
        self.__src = list(args)
        self.closed = False
        self.channel = None

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
port = 22
username = "user"
password = "pass"

command = "ls ~\nline 2\nline 3\nline с кирилицей"
cmd_execute = f"{command}\n"
quoted_command = shlex.quote(command)
command_log = f"Executing command:\n{command.rstrip()!r}\n"
stdout_src = (b" \n", b"2\n", b"3\n", b" \n")
stderr_src = (b" \n", b"0\n", b"1\n", b" \n")

print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


@pytest.fixture
def chan_makefile():
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
            elif "rb" == flags:
                self.stdout = FakeFileStream(*stdout_src)
                self.stdout.channel = self.channel
                return self.stdout
            raise ValueError(f"Unexpected flags: {flags!r}")

    return MkFile()


@pytest.fixture
def ssh_transport_channel(paramiko_ssh_client, chan_makefile):
    chan = mock.Mock(makefile=chan_makefile, closed=False)
    chan_makefile.channel = chan
    chan.attach_mock(mock.Mock(return_value=FakeFileStream(*stderr_src)), "makefile_stderr")
    chan.configure_mock(exit_status=0)
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
def ssh(paramiko_ssh_client, ssh_transport_channel, auto_add_policy, ssh_auth_logger, get_logger):
    return exec_helpers.SSHClient(host=host, port=port, auth=exec_helpers.SSHAuth(username=username, password=password))


@pytest.fixture
def exec_result():
    return exec_helpers.ExecResult(cmd=command, stdin=None, stdout=stdout_src, stderr=stderr_src, exit_code=0)


def test_001_execute_async_sudo(ssh, ssh_transport_channel):
    ssh.sudo_mode = True

    ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls(
        (
            mock.call.makefile_stderr("rb"),
            mock.call.exec_command(f'sudo -S sh -c {shlex.quote(f"eval {quoted_command}")}\n'),
        )
    )


def test_002_execute_async_with_sudo_enforce(ssh, ssh_transport_channel):
    assert ssh.sudo_mode is False

    with ssh.sudo(enforce=True):
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls(
        (
            mock.call.makefile_stderr("rb"),
            mock.call.exec_command(f'sudo -S sh -c {shlex.quote(f"eval {quoted_command}")}\n'),
        )
    )


def test_003_execute_async_with_no_sudo_enforce(ssh, ssh_transport_channel):
    ssh.sudo_mode = True

    with ssh.sudo(enforce=False):
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls((mock.call.makefile_stderr("rb"), mock.call.exec_command(f"{command}\n")))


def test_004_execute_async_with_sudo_none_enforce(ssh, ssh_transport_channel):
    ssh.sudo_mode = False

    with ssh.sudo():
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls((mock.call.makefile_stderr("rb"), mock.call.exec_command(f"{command}\n")))


def test_005_execute_async_sudo_password(ssh, ssh_transport_channel):
    ssh.sudo_mode = True

    ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls(
        (
            mock.call.makefile_stderr("rb"),
            mock.call.exec_command(f'sudo -S sh -c {shlex.quote(f"eval {quoted_command}")}\n'),
        )
    )


def test_006_keepalive(ssh, paramiko_ssh_client):
    with ssh:
        pass  # NOSONAR

    paramiko_ssh_client().close.assert_not_called()


def test_007_no_keepalive(ssh, paramiko_ssh_client):
    ssh.keepalive_period = False

    with ssh:
        pass  # NOSONAR

    paramiko_ssh_client().close.assert_called_once()


def test_008_keepalive_enforced(ssh, paramiko_ssh_client):
    ssh.keepalive_period = False

    with ssh.keepalive():
        assert ssh.keepalive_period == 1

    paramiko_ssh_client().close.assert_not_called()


def test_009_no_keepalive_enforced(ssh, paramiko_ssh_client):
    assert ssh.keepalive_period == 1

    with ssh.keepalive(enforce=False):
        pass  # NOSONAR

    paramiko_ssh_client().close.assert_called_once()


def test_010_check_stdin_closed(paramiko_ssh_client, chan_makefile, auto_add_policy, get_logger):
    chan = mock.Mock(makefile=chan_makefile, closed=True)
    chan_makefile.channel = chan
    chan.attach_mock(mock.Mock(return_value=FakeFileStream(*stderr_src)), "makefile_stderr")
    chan.configure_mock(exit_status=0)
    chan.status_event.attach_mock(mock.Mock(return_value=True), "is_set")
    open_session = mock.Mock(return_value=chan)
    transport = mock.Mock()
    transport.attach_mock(open_session, "open_session")
    get_transport = mock.Mock(return_value=transport)
    _ssh = mock.Mock()
    _ssh.attach_mock(get_transport, "get_transport")
    paramiko_ssh_client.return_value = _ssh

    stdin_val = "this is a line"

    ssh = exec_helpers.SSHClient(host=host, port=port, auth=exec_helpers.SSHAuth(username=username, password=password))
    ssh._execute_async(command=print_stdin, stdin=stdin_val)

    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    log.warning.assert_called_once_with("STDIN Send failed: closed channel")


def test_011_execute_async_chroot_cmd(ssh, ssh_transport_channel):
    """Command-only chroot path."""
    ssh._execute_async(command, chroot_path="/mnt")
    ssh_transport_channel.assert_has_calls(
        (
            mock.call.makefile_stderr("rb"),
            mock.call.exec_command(f'chroot /mnt sh -c {shlex.quote(f"eval {quoted_command}")}\n'),
        )
    )


def test_012_execute_async_chroot_context(ssh, ssh_transport_channel):
    """Context-managed chroot path."""
    with ssh.chroot("/mnt"):
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls(
        (
            mock.call.makefile_stderr("rb"),
            mock.call.exec_command(f'chroot /mnt sh -c {shlex.quote(f"eval {quoted_command}")}\n'),
        )
    )


def test_013_execute_async_no_chroot_context(ssh, ssh_transport_channel):
    """Context-managed chroot path override."""
    ssh._chroot_path = "/mnt"

    with ssh.chroot(None):
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls((mock.call.makefile_stderr("rb"), mock.call.exec_command(f"{command}\n")))


def test_012_execute_async_chroot_path(ssh, ssh_transport_channel):
    """Command-only chroot path."""
    with ssh.chroot(pathlib.Path("/mnt")):
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls(
        (
            mock.call.makefile_stderr("rb"),
            mock.call.exec_command(f'chroot /mnt sh -c {shlex.quote(f"eval {quoted_command}")}\n'),
        )
    )


def test_013_execute_async_chroot_path_invalid_type(ssh, ssh_transport_channel):
    """Command-only chroot path."""
    with pytest.raises(TypeError) as exc:
        with ssh.chroot(...):
            ssh._execute_async(command)
        assert str(exc.value) == f"path={...!r} is not instance of Optional[Union[str, pathlib.Path]]"


def test_014_execute_async_no_chroot_root(ssh, ssh_transport_channel):
    """Context-managed chroot path override."""
    ssh._chroot_path = "/mnt"

    with ssh.chroot("/"):
        ssh._execute_async(command)
    ssh_transport_channel.assert_has_calls((mock.call.makefile_stderr("rb"), mock.call.exec_command(f"{command}\n")))
