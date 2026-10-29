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

"""SSHClient: execution of the commands on a host reached through the connected host."""

from __future__ import annotations

from unittest import mock

import pytest

import exec_helpers
from fakes import fake_channel
from fakes import host
from fakes import port
from subprocess_cases import command

target = "127.0.0.2"
auth_other = exec_helpers.SSHAuth(username="user2", password="pass2")


@pytest.mark.parametrize(
    ("auth", "username", "password"),
    [
        pytest.param(None, "user", "pass", id="client_credentials"),
        pytest.param(auth_other, "user2", "pass2", id="own_credentials"),
    ],
)
def test_execute_through_host_connection(paramiko_ssh_client, make_ssh, auth, username, password) -> None:
    """The target is reached by a channel of the connected host, with the credentials of the client or given ones."""
    ssh = make_ssh(fake_channel())
    paramiko_client = paramiko_ssh_client.return_value
    open_channel = paramiko_client.get_transport.return_value.open_channel

    ssh.execute_through_host(target, command, auth=auth)

    open_channel.assert_called_once_with(dest_addr=(target, port), kind="direct-tcpip", src_addr=(host, 0))
    assert paramiko_client.connect.call_args_list == [
        mock.call(
            hostname=host, port=port, username="user", password="pass", pkey=None, key_filename=(), allow_agent=True
        ),
        mock.call(
            hostname=target,
            port=port,
            username=username,
            password=password,
            pkey=None,
            sock=open_channel.return_value,
            key_filename=(),
            allow_agent=True,
        ),
    ]


def test_execute_through_host_arguments(make_ssh) -> None:
    """The execution arguments reach the channel of the target."""
    chan = fake_channel(stdout=(b"test\n",))
    ssh = make_ssh(chan)

    res = ssh.execute_through_host(target, command, stdin="test", get_pty=True, width=120, height=100)

    assert res.stdin == "test"
    chan.stdin_file.write.assert_called_once_with(b"test")
    chan.get_pty.assert_called_once_with(term="vt100", width=120, height=100, width_pixels=0, height_pixels=0)
