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
import typing
from unittest import mock

# External Dependencies
import paramiko
import pytest

# Package Implementation
import exec_helpers


def gen_private_keys(amount: int = 1) -> typing.List[paramiko.RSAKey]:
    keys = [paramiko.RSAKey.generate(1024) for _ in range(amount)]
    return keys


def gen_public_key(private_key: typing.Optional[paramiko.RSAKey] = None) -> str:
    if private_key is None:
        private_key = paramiko.RSAKey.generate(1024)
    return f"{private_key.get_name()} {private_key.get_base64()}"


class FakeStream:
    """Stream-like object for usage in tests."""

    def __init__(self, *args: bytes):
        self.__src = list(args)

    def __iter__(self):
        if len(self.__src) == 0:
            raise OSError()
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)


host = "127.0.0.1"


configs = {
    "host_only": {"host": host},
    "alternate_port": {"host": host, "port": 2222},
    "username": {"host": host, "username": "user"},
    "username_password": {"host": host, "username": "user", "password": "password"},
    "auth": {
        "host": host,
        "auth": exec_helpers.SSHAuth(username="user", password="password", key=gen_private_keys(1).pop()),
    },
    "auth_break": {
        "host": host,
        "username": "Invalid",
        "password": "Invalid",
        "auth": exec_helpers.SSHAuth(username="user", password="password", key=gen_private_keys(1).pop()),
    },
}


def pytest_generate_tests(metafunc):
    """Tests parametrization."""
    if "run_parameters" in metafunc.fixturenames:
        metafunc.parametrize(
            "run_parameters",
            ["host_only", "alternate_port", "username", "username_password", "auth", "auth_break"],
            indirect=True,
        )


@pytest.fixture
def run_parameters(request):
    """Tests configuration apply."""
    return configs[request.param]


def test_init_base(paramiko_ssh_client, auto_add_policy, run_parameters, ssh_auth_logger):
    """Parametrized validation of SSH client initialization."""
    # Helper code
    _ssh = mock.call
    port = run_parameters.get("port", 22)

    username = run_parameters.get("username", None)
    password = run_parameters.get("password", None)

    auth = run_parameters.get("auth", None)

    # Test
    ssh = exec_helpers.SSHClient(**run_parameters)

    paramiko_ssh_client.assert_called_once()
    auto_add_policy.assert_called_once()

    if auth is None:
        expected_calls = [
            _ssh.set_missing_host_key_policy("AutoAddPolicy"),
            _ssh.connect(hostname=host, password=password, pkey=None, port=port, username=username, key_filename=()),
            _ssh.get_transport(),
            _ssh.get_transport().set_keepalive(1),
        ]

        assert expected_calls == paramiko_ssh_client().mock_calls

        assert ssh.auth == exec_helpers.SSHAuth(username=username, password=password)
    else:
        ssh_auth_logger.assert_not_called()

    sftp = ssh._sftp
    assert sftp == paramiko_ssh_client().open_sftp()
    assert ssh._ssh == paramiko_ssh_client()
    assert ssh.hostname == host
    assert ssh.port == port
    assert repr(ssh) == "{cls}(host={host}, port={port}, auth={auth!r})".format(
        cls=ssh.__class__.__name__, host=ssh.hostname, port=ssh.port, auth=ssh.auth
    )
    # ssh config for main connection is synchronised with connection parameters
    expected_config_dict = {host: {"hostname": host, "port": ssh.port}}
    if ssh.auth.username:
        expected_config_dict[host]["user"] = ssh.auth.username

    assert ssh.ssh_config[host] == expected_config_dict[host]
    assert ssh.ssh_config == expected_config_dict
    assert ssh.ssh_config[host].hostname == host
