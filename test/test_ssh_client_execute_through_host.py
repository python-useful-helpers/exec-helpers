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

# Standard Library
import base64
import typing
from unittest import mock

# External Dependencies
import paramiko
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
command_log = f"Executing command:\n{command.rstrip()!r}\n"
stdout_src = (b" \n", b"2\n", b"3\n", b" \n")
stderr_src = (b" \n", b"0\n", b"1\n", b" \n")
encoded_cmd = base64.b64encode(f"{command}\n".encode("utf-8")).decode("utf-8")

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
                self.stdin = mock.MagicMock()
                self.stdin.channel = self.channel
                return self.stdin
            elif "rb" == flags:
                self.stdout = FakeFileStream(*stdout_src)
                self.stdout.channel = self.channel
                return self.stdout
            raise ValueError(f"Unexpected flags: {flags!r}")

    return MkFile()


@pytest.fixture
def ssh_intermediate_channel(paramiko_ssh_client):
    chan = mock.MagicMock(name="intermediate_channel", spec=paramiko.Channel)
    transport = mock.MagicMock(spec=paramiko.Transport)
    transport.attach_mock(chan, "open_channel")
    get_transport = mock.MagicMock(return_value=transport)
    _ssh = mock.MagicMock(spec=paramiko.SSHClient)
    _ssh.attach_mock(get_transport, "get_transport")
    paramiko_ssh_client.return_value = _ssh
    return chan


@pytest.fixture
def ssh_transport(mocker):
    transport = mock.MagicMock(name="transport")
    mocker.patch("paramiko.Transport", return_value=transport)
    return transport


@pytest.fixture
def ssh_transport_channel(chan_makefile, ssh_transport):
    chan = mock.MagicMock(makefile=chan_makefile, closed=False)
    chan_makefile.channel = chan
    chan.attach_mock(mock.MagicMock(return_value=FakeFileStream(*stderr_src)), "makefile_stderr")

    chan.configure_mock(exit_status=0)

    chan.status_event.attach_mock(mock.MagicMock(return_value=True), "is_set")
    open_session = mock.MagicMock(return_value=chan)
    ssh_transport.attach_mock(open_session, "open_session")
    return chan


@pytest.fixture
def ssh(
    paramiko_ssh_client, ssh_intermediate_channel, ssh_transport_channel, auto_add_policy, ssh_auth_logger, get_logger
):
    return exec_helpers.SSHClient(host=host, port=port, auth=exec_helpers.SSHAuth(username=username, password=password))


def test_01_execute_through_host_no_creds(
    ssh: exec_helpers.SSHClient, paramiko_ssh_client: mock.MagicMock, ssh_intermediate_channel: mock.MagicMock
) -> None:
    target = "127.0.0.2"
    ssh.execute_through_host(target, command)
    connect: mock.MagicMock = paramiko_ssh_client().connect
    assert ssh_intermediate_channel.mock_calls == [
        mock.call(dest_addr=(target, port), kind="direct-tcpip", src_addr=(host, 0))
    ]
    connect.assert_has_calls(
        [
            mock.call(hostname=host, password=password, pkey=None, port=port, username=username, key_filename=()),
            mock.call(
                hostname=target,
                port=port,
                username=username,
                password=password,
                pkey=None,
                sock=ssh_intermediate_channel(),
                key_filename=(),
            ),
        ]
    )


def test_02_execute_through_host_with_creds(
    ssh: exec_helpers.SSHClient, paramiko_ssh_client: mock.MagicMock, ssh_intermediate_channel: mock.MagicMock
) -> None:
    target = "127.0.0.2"
    username_2 = "user2"
    password_2 = "pass2"
    ssh.execute_through_host(target, command, auth=exec_helpers.SSHAuth(username=username_2, password=password_2))
    connect: mock.MagicMock = paramiko_ssh_client().connect
    assert ssh_intermediate_channel.mock_calls == [
        mock.call(dest_addr=(target, port), kind="direct-tcpip", src_addr=(host, 0))
    ]
    connect.assert_has_calls(
        [
            mock.call(hostname=host, password=password, pkey=None, port=port, username=username, key_filename=()),
            mock.call(
                hostname=target,
                port=port,
                username=username_2,
                password=password_2,
                pkey=None,
                sock=ssh_intermediate_channel(),
                key_filename=(),
            ),
        ]
    )


def test_03_execute_get_pty(ssh, mocker) -> None:
    conn = mocker.patch("paramiko.SSHClient")
    target = "127.0.0.2"
    ssh.execute_through_host(target, command, get_pty=True)
    final_client = conn()
    session = final_client.get_transport().open_session()
    session.get_pty.assert_called_with(term="vt100", width=80, height=24, width_pixels=0, height_pixels=0)


def test_04_execute_use_stdin(ssh, mocker, chan_makefile) -> None:
    conn = mocker.patch("paramiko.SSHClient")
    conn().get_transport().open_session().makefile = chan_makefile
    target = "127.0.0.2"
    cmd = print_stdin
    stdin = "test"
    res = ssh.execute_through_host(target, cmd, stdin=stdin, get_pty=True)
    assert res.stdin == stdin
    chan_makefile.stdin.write.assert_called_once_with(stdin.encode("utf-8"))
    chan_makefile.stdin.flush.assert_called_once()


def test_05_execute_closed_stdin(ssh, ssh_transport_channel, get_logger) -> None:
    target = "127.0.0.2"
    cmd = print_stdin
    stdin = "test"
    ssh_transport_channel.closed = True

    ssh.execute_through_host(target, cmd, stdin=stdin, get_pty=True)
    log = get_logger(ssh.__class__.__name__).getChild(f"{host}:{port}")
    log.warning.assert_called_once_with("STDIN Send failed: closed channel")
