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

import socket
import typing
import warnings
from unittest import mock

import paramiko
import pytest

import exec_helpers
from exec_helpers import _ssh_helpers  # noqa: F401  # the module is used as exec_helpers._ssh_helpers


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


REAL_LOCAL_HOST_KEYS = exec_helpers._ssh_helpers.local_host_keys  # the autouse fixture replaces the module attribute
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


@pytest.mark.parametrize(
    ("hostname", "expected"),
    (
        ("127.0.0.1", True),
        ("127.1.2.3", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("192.0.2.1", False),
        ("remote.example.com", False),
    ),
)
def test_is_local_host(hostname, expected):
    """Local host detection does not depend on name resolution."""
    assert exec_helpers._ssh_helpers.is_local_host(hostname) is expected


def test_is_local_host_own_names_and_interfaces(mocker):
    """Own host name, its short form and own interface addresses are local."""
    mocker.patch("socket.gethostname", return_value="Node001.cluster.local")
    mocker.patch(
        "psutil.net_if_addrs",
        return_value={
            "eth0": [
                mock.Mock(family=socket.AF_INET, address="192.0.2.10"),
                mock.Mock(family=socket.AF_INET6, address="2001:db8::10%eth0"),
                mock.Mock(family=socket.AF_INET6, address="fe80::10%eth0"),
                mock.Mock(family=socket.AF_PACKET, address="aa:bb:cc:dd:ee:ff"),
            ]
        },
    )

    for local in ("node001", "node001.cluster.local", "192.0.2.10", "2001:db8::10", "fe80::10%eth0"):
        assert exec_helpers._ssh_helpers.is_local_host(local)
    for remote in ("node002", "node001.example.com", "192.0.2.11", "fe80::10"):
        assert not exec_helpers._ssh_helpers.is_local_host(remote)


def test_is_local_host_interface_enumeration_failed(mocker):
    """No verdict about interfaces means the host is not local."""
    mocker.patch("psutil.net_if_addrs", side_effect=OSError)
    assert not exec_helpers._ssh_helpers.is_local_host("192.0.2.10")


def test_unknown_host_key_policy(paramiko_ssh_client, ssh_auth_logger):
    """Warning policy stays by default and a custom policy is never replaced."""
    ssh_ = mock.call

    exec_helpers.SSHClient(host="192.0.2.1", auth=exec_helpers.SSHAuth())
    assert ssh_.set_missing_host_key_policy(paramiko.WarningPolicy) in paramiko_ssh_client.return_value.mock_calls

    paramiko_ssh_client.reset_mock()
    exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(), missing_host_key_policy=paramiko.RejectPolicy)
    assert ssh_.set_missing_host_key_policy(paramiko.RejectPolicy) in paramiko_ssh_client.return_value.mock_calls


@pytest.mark.parametrize("local_host", ("127.0.0.1", "127.0.0.2", "127.0.0.254", "localhost"))
@pytest.mark.parametrize("port", (22, 2222))
def test_local_host_policy_selected(mocker, paramiko_ssh_client, ssh_auth_logger, local_host, port):
    """Any local address and port gets the policy, which accepts the keys of this machine."""
    mocker.patch("exec_helpers._ssh_helpers.local_host_keys", return_value=(mock.Mock(),))

    exec_helpers.SSHClient(host=local_host, port=port, auth=exec_helpers.SSHAuth())

    (policy,) = paramiko_ssh_client.return_value.set_missing_host_key_policy.call_args.args
    assert isinstance(policy, exec_helpers._ssh_helpers.LocalHostKeyPolicy)


@pytest.mark.parametrize("keys", ((), (mock.Mock(),)))
def test_local_host_policy_not_selected(mocker, paramiko_ssh_client, ssh_auth_logger, keys):
    """A remote host and a local host without readable keys keep the configured policy."""
    mocker.patch("exec_helpers._ssh_helpers.local_host_keys", return_value=keys)

    for name in ("192.0.2.1", "remote.example.com") + (() if keys else (host,)):
        paramiko_ssh_client.reset_mock()
        exec_helpers.SSHClient(host=name, auth=exec_helpers.SSHAuth(), missing_host_key_policy=paramiko.RejectPolicy)
        assert (
            mock.call.set_missing_host_key_policy(paramiko.RejectPolicy) in paramiko_ssh_client.return_value.mock_calls
        )


def test_local_host_keys_file_reading(mocker, tmp_path):
    """Public keys of the SSH server are read, unreadable and broken files are skipped."""
    keys = [paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)]
    for number, key in enumerate(keys):
        (tmp_path / f"ssh_host_rsa{number}_key.pub").write_text(f"{key.get_name()} {key.get_base64()} comment\n")
    (tmp_path / "ssh_host_broken_key.pub").write_text("not a key\n")
    (tmp_path / "ssh_host_truncated_key.pub").write_text("ssh-ed25519 AAAA\n")
    (tmp_path / "ssh_host_directory_key.pub").mkdir()
    mocker.patch("exec_helpers._ssh_helpers.LOCAL_HOST_KEYS_DIR", tmp_path)

    assert [key.get_base64() for key in REAL_LOCAL_HOST_KEYS()] == [key.get_base64() for key in keys]


@pytest.mark.parametrize("through", ("proxycommand", "proxyjump", "sock"))
def test_unknown_host_key_policy_behind_proxy(mocker, paramiko_ssh_client, ssh_auth_logger, through):
    """The local host name behind a proxy or jump host is resolved elsewhere, so the warning stays."""
    mocker.patch("exec_helpers._ssh_helpers.local_host_keys", return_value=(mock.Mock(),))
    ssh_ = mock.call
    kwargs: dict[str, typing.Any] = {}
    config: dict[str, typing.Any] = {host: {"hostname": host}}
    if through == "proxycommand":
        config = {host: {"hostname": host, "proxycommand": "nc far-host 22"}}
    elif through == "proxyjump":
        config = {
            "jump": {"hostname": "192.0.2.1"},
            host: {"hostname": host, "proxyjump": "jump"},
        }
        kwargs["ssh_auth_map"] = {"192.0.2.1": exec_helpers.SSHAuth(), host: exec_helpers.SSHAuth()}
    else:
        kwargs["sock"] = mock.Mock()

    if through != "sock":
        kwargs["ssh_config"] = config
    exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(), **kwargs)

    calls = paramiko_ssh_client.return_value.mock_calls
    assert ssh_.set_missing_host_key_policy(paramiko.WarningPolicy) in calls
    assert not any(
        isinstance(call.args[0], exec_helpers._ssh_helpers.LocalHostKeyPolicy)
        for call in paramiko_ssh_client.return_value.set_missing_host_key_policy.call_args_list
    )


@pytest.mark.parametrize("through", ("direct", "sock", "proxyjump", "proxy_to"))
def test_connect_timeout_every_step(paramiko_ssh_client, ssh_auth_logger, through):
    """The connect timeout is applied to every connection step."""
    kwargs: dict[str, typing.Any] = {}
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


def test_local_host_key_policy():
    """The key of this machine is accepted, any other key goes to the fallback policy as it was before."""
    key = paramiko.RSAKey.generate(1024)
    other = paramiko.RSAKey.generate(1024)
    client = mock.Mock()
    fallback = mock.Mock()

    policy = exec_helpers._ssh_helpers.LocalHostKeyPolicy((key,), fallback=fallback)
    policy.missing_host_key(client, host, key)
    fallback.missing_host_key.assert_not_called()

    policy.missing_host_key(client, host, other)
    fallback.missing_host_key.assert_called_once_with(client, host, other)


def test_local_host_key_policy_fallback_class():
    """A fallback policy class is instantiated and still decides about the keys of other servers."""
    key = paramiko.RSAKey.generate(1024)
    other = paramiko.RSAKey.generate(1024)
    policy = exec_helpers._ssh_helpers.LocalHostKeyPolicy((key,), fallback=paramiko.RejectPolicy)

    client = mock.Mock()

    policy.missing_host_key(client, host, key)
    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, host, other)


def test_failed_chain_closes_every_reached_host(paramiko_ssh_client, ssh_auth_logger):
    """A failure on a jump host chain closes the clients of all the hosts created so far."""
    first = mock.Mock()
    second = mock.Mock()
    second.connect.side_effect = TimeoutError
    paramiko_ssh_client.side_effect = [first, second]
    config: dict[str, typing.Any] = {
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


def test_local_host_key_policy_warns_about_other_keys():
    """The default policy still warns about a key which is not a key of this machine, and not about the own one."""
    key = paramiko.RSAKey.generate(1024)
    other = paramiko.RSAKey.generate(1024)
    client = mock.Mock()
    policy = exec_helpers._ssh_helpers.LocalHostKeyPolicy((key,), fallback=paramiko.WarningPolicy)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        policy.missing_host_key(client, host, key)

    with pytest.warns(UserWarning, match="Unknown"):
        policy.missing_host_key(client, host, other)


@pytest.mark.parametrize("failing", ("is_local_host", "local_host_keys"))
def test_local_host_lookup_failure_is_not_a_connection_failure(mocker, paramiko_ssh_client, ssh_auth_logger, failing):
    """A failed lookup of the local host keys leaves the configured policy, the connection is made as before."""
    mocker.patch("exec_helpers._ssh_helpers.is_local_host", return_value=True)
    mocker.patch("exec_helpers._ssh_helpers.local_host_keys", return_value=(mock.Mock(),))
    mocker.patch(f"exec_helpers._ssh_helpers.{failing}", side_effect=OSError)

    exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())

    assert mock.call.set_missing_host_key_policy(paramiko.WarningPolicy) in paramiko_ssh_client.return_value.mock_calls
