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

from unittest import mock

import paramiko
import pytest

import exec_helpers


def gen_private_keys(amount: int = 1) -> list[paramiko.RSAKey]:
    keys = [paramiko.RSAKey.generate(1024) for _ in range(amount)]
    return keys


def gen_public_key(private_key: paramiko.RSAKey | None = None) -> str:
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
        "auth": exec_helpers.SSHAuth(
            username="user",
            password="password",
            key=gen_private_keys(1).pop(),
        ),
    },
    "auth_break": {
        "host": host,
        "username": "Invalid",
        "password": "Invalid",
        "auth": exec_helpers.SSHAuth(
            username="user",
            password="password",
            key=gen_private_keys(1).pop(),
        ),
    },
}


def pytest_generate_tests(metafunc):
    """Test parametrization."""
    if "run_parameters" in metafunc.fixturenames:
        metafunc.parametrize(
            "run_parameters",
            [
                "host_only",
                "alternate_port",
                "username",
                "username_password",
                "auth",
                "auth_break",
            ],
            indirect=True,
        )


@pytest.fixture
def run_parameters(request):
    """Test configuration apply."""
    return configs[request.param]


def test_init_base(
    paramiko_ssh_client,
    run_parameters,
    ssh_auth_logger,
):
    """Parametrized validation of SSH client initialization."""
    # Helper code
    ssh_ = mock.call
    port = run_parameters.get("port", 22)

    username = run_parameters.get("username", None)
    password = run_parameters.get("password", None)

    auth = run_parameters.get("auth", None)

    # Test
    ssh = exec_helpers.SSHClient(**run_parameters)

    paramiko_ssh_client.assert_called_once()

    if auth is None:
        expected_calls = [
            ssh_.load_system_host_keys(),
            ssh_.set_missing_host_key_policy(paramiko.WarningPolicy),
            ssh_.connect(
                hostname=host,
                password=password,
                pkey=None,
                port=port,
                username=username,
                key_filename=(),
                allow_agent=True,
            ),
            ssh_.get_transport(),
            ssh_.get_transport().set_keepalive(1),
        ]

        assert expected_calls == paramiko_ssh_client().mock_calls

        assert ssh.auth == exec_helpers.SSHAuth(username=username, password=password)
    else:
        ssh_auth_logger.assert_not_called()

    sftp = ssh._sftp
    assert sftp == paramiko_ssh_client().get_transport().open_sftp_client()
    assert ssh._ssh == paramiko_ssh_client()
    assert ssh.hostname == host
    assert ssh.port == port
    assert repr(ssh) == f"{ssh.__class__.__name__}(host={ssh.hostname}, port={ssh.port}, auth={ssh.auth!r})"
    # ssh config for main connection is synchronised with connection parameters
    expected_config_dict = {host: {"hostname": host, "port": ssh.port}}
    if ssh.auth.username:
        expected_config_dict[host]["user"] = ssh.auth.username

    assert ssh.ssh_config[host] == expected_config_dict[host]
    assert ssh.ssh_config == expected_config_dict
    assert ssh.ssh_config[host].hostname == host


@pytest.mark.parametrize("through", ("direct", "sock", "proxyjump", "proxy_to"))
def test_connect_timeout_every_step(paramiko_ssh_client, ssh_auth_logger, through):
    """The connect timeout is applied to every connection step."""
    kwargs = {}
    if through == "sock":
        kwargs["sock"] = mock.Mock()
    elif through == "proxyjump":
        kwargs["ssh_config"] = {
            "jump": {"hostname": "192.0.2.1"},
            host: {"hostname": host, "proxyjump": "jump"},
        }
        kwargs["ssh_auth_map"] = {"192.0.2.1": exec_helpers.SSHAuth(), host: exec_helpers.SSHAuth()}

    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(), connect_timeout=7, **kwargs)
    if through == "proxy_to":
        ssh.proxy_to("192.0.2.2", auth=exec_helpers.SSHAuth())

    connects = [call for call in paramiko_ssh_client.return_value.mock_calls if call[0] == "connect"]
    assert len(connects) >= (2 if through in {"proxyjump", "proxy_to"} else 1)
    for call in connects:
        assert (call.kwargs["timeout"], call.kwargs["banner_timeout"], call.kwargs["auth_timeout"]) == (7, 7, 7)


@pytest.mark.parametrize("value", (0, -1))
def test_connect_timeout_not_positive(paramiko_ssh_client, value):
    """A timeout that disables waiting is rejected."""
    with pytest.raises(ValueError, match="connect_timeout"):
        exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(), connect_timeout=value)


def test_failed_chain_closes_every_reached_host(paramiko_ssh_client, ssh_auth_logger):
    """A failure on a jump host chain closes the clients of all the hosts created so far."""
    first = mock.Mock()
    second = mock.Mock()
    second.connect.side_effect = TimeoutError
    paramiko_ssh_client.side_effect = [first, second]
    config = {
        "jump": {"hostname": "192.0.2.1"},
        host: {"hostname": host, "proxyjump": "jump"},
    }

    with pytest.raises(TimeoutError):
        exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(),
            ssh_config=config,
            ssh_auth_map={"192.0.2.1": exec_helpers.SSHAuth(), host: exec_helpers.SSHAuth()},
        )

    first.close.assert_called()
    second.close.assert_called()


@pytest.mark.parametrize(("supplied_sock", "attempts"), ((False, 3), (True, 1)))
def test_connect_retries(paramiko_ssh_client, ssh_auth_logger, supplied_sock, attempts):
    """A failed connection is retried, except on a supplied socket: the failed attempt has closed it."""
    paramiko_ssh_client.return_value.connect.side_effect = paramiko.SSHException("banner")
    kwargs = {"sock": mock.Mock()} if supplied_sock else {}

    with pytest.raises(paramiko.SSHException, match="banner"):
        exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(), **kwargs)

    assert paramiko_ssh_client.return_value.connect.call_count == attempts
