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
port = 22
username = "user"
password = "pass"


def test_001_require_key(paramiko_ssh_client, paramiko_keys_policy, ssh_auth_logger):
    """Reject key and allow to connect without key."""
    # Helper code
    ssh_ = mock.call

    connect = mock.Mock(side_effect=[paramiko.AuthenticationException, mock.Mock()])
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    private_keys = gen_private_keys(1)

    # Test
    ssh = exec_helpers.SSHClient(
        host=host,
        auth=exec_helpers.SSHAuth(username=username, keys=private_keys),
    )

    paramiko_ssh_client.assert_called_once()
    paramiko_keys_policy.assert_called_once()

    ssh_auth_logger.debug.assert_called_once_with(f"Main key has been updated, public key is: \n{ssh.auth.public_key}")

    pkey = private_keys[0]

    kwargs_no_key = {
        "hostname": host,
        "pkey": None,
        "port": port,
        "username": username,
        "password": None,
        "key_filename": (),
        "allow_agent": True,
    }
    kwargs_full = {key: kwargs_no_key[key] for key in kwargs_no_key}
    kwargs_full["pkey"] = pkey

    expected_calls = [
        ssh_.set_missing_host_key_policy("WarningPolicy"),
        ssh_.connect(**kwargs_full),
        ssh_.connect(**kwargs_no_key),
        ssh_.get_transport(),
        ssh_.get_transport().set_keepalive(1),
    ]

    assert expected_calls == paramiko_ssh_client().mock_calls


def test_002_use_next_key(paramiko_ssh_client, paramiko_keys_policy, ssh_auth_logger):
    """Reject 1 key and use next one."""
    # Helper code
    ssh_ = mock.call

    connect = mock.Mock(
        side_effect=[
            paramiko.AuthenticationException,
            paramiko.AuthenticationException,
            mock.Mock(),
        ]
    )
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    private_keys = gen_private_keys(2)

    # Test
    ssh = exec_helpers.SSHClient(
        host=host,
        auth=exec_helpers.SSHAuth(username=username, keys=private_keys),
    )

    paramiko_ssh_client.assert_called_once()
    paramiko_keys_policy.assert_called_once()

    ssh_auth_logger.debug.assert_called_once_with(f"Main key has been updated, public key is: \n{ssh.auth.public_key}")

    kwargs_no_key = {
        "hostname": host,
        "pkey": None,
        "port": port,
        "username": username,
        "password": None,
        "key_filename": (),
        "allow_agent": True,
    }
    kwargs_key_0 = {key: kwargs_no_key[key] for key in kwargs_no_key}
    kwargs_key_0["pkey"] = private_keys[0]
    kwargs_key_1 = {key: kwargs_no_key[key] for key in kwargs_no_key}
    kwargs_key_1["pkey"] = private_keys[1]

    expected_calls = [
        ssh_.set_missing_host_key_policy("WarningPolicy"),
        ssh_.connect(**kwargs_key_0),
        ssh_.connect(**kwargs_key_1),
        ssh_.connect(**kwargs_no_key),
        ssh_.get_transport(),
        ssh_.get_transport().set_keepalive(1),
    ]

    assert expected_calls == paramiko_ssh_client().mock_calls


def test_003_password_required(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """No password provided."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.PasswordRequiredException)
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    private_keys = gen_private_keys(2)

    # Test
    with pytest.raises(paramiko.PasswordRequiredException):
        exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(username=username, keys=private_keys),
        )
    ssh_auth_logger.assert_has_calls((mock.call.exception("No password has been set!"),))


def test_004_unexpected_password_required(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """Password available, but requested anyway."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.PasswordRequiredException)
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    private_keys = gen_private_keys(2)

    # Test
    with pytest.raises(paramiko.PasswordRequiredException):
        exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password,
                keys=private_keys,
            ),
        )
    ssh_auth_logger.assert_has_calls(
        (mock.call.critical("Unexpected PasswordRequiredException, when password is set!"),)
    )


def test_005_auth_impossible_password(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """Reject password."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(password=password))
    ssh_auth_logger.assert_has_calls((mock.call.exception("Connection using stored authentication info failed!"),))


def test_006_auth_impossible_key(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """Reject key."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(key=gen_private_keys(1).pop()),
        )
    ssh_auth_logger.assert_has_calls((mock.call.exception("Connection using stored authentication info failed!"),))


def test_007_auth_impossible_key_keys(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """Reject key."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(
                key=gen_private_keys(1).pop(),
                keys=gen_private_keys(2),
            ),
        )
    ssh_auth_logger.assert_has_calls((mock.call.exception("Connection using stored authentication info failed!"),))


def test_008_auth_impossible_key_no_verbose(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """Reject auth without log."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(key=gen_private_keys(1).pop()),
            verbose=False,
        )
    ssh_auth_logger.assert_not_called()


def test_009_auth_pass_no_key(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
):
    """Reject key and use password."""
    # Helper code
    connect = mock.Mock(side_effect=[paramiko.AuthenticationException, mock.Mock()])
    ssh_inst = mock.Mock()
    ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = ssh_inst
    key = gen_private_keys(1).pop()

    # Test
    ssh = exec_helpers.SSHClient(
        host=host,
        auth=exec_helpers.SSHAuth(username=username, password=password, key=key),
    )

    ssh_auth_logger.assert_has_calls(
        (mock.call.debug(f"Main key has been updated, public key is: \n{ssh.auth.public_key}"),)
    )

    assert ssh.auth.public_key is None


def test_010_context(paramiko_ssh_client, paramiko_keys_policy, ssh_auth_logger):
    """Context manager."""
    # Test
    with exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth()) as ssh:
        paramiko_ssh_client.assert_called_once()
        paramiko_keys_policy.assert_called_once()

        ssh_auth_logger.assert_not_called()

        assert ssh.auth == exec_helpers.SSHAuth()

        sftp = ssh._sftp
        assert sftp == paramiko_ssh_client().open_sftp()

        assert ssh._ssh == paramiko_ssh_client()

        assert ssh.hostname == host
        assert ssh.port == port


def test_011_clear_failed(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    """TearDown failed."""
    # Helper code
    ssh_ = mock.Mock()
    ssh_.attach_mock(
        mock.Mock(side_effect=[Exception("Mocked SSH close()"), mock.Mock()]),
        "close",
    )
    sftp_ = mock.Mock()
    sftp_.attach_mock(
        mock.Mock(side_effect=[Exception("Mocked SFTP close()"), mock.Mock()]),
        "close",
    )
    ssh_.attach_mock(mock.Mock(return_value=sftp_), "open_sftp")
    paramiko_ssh_client.return_value = ssh_

    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild(f"{host}:{port}")

    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())

    paramiko_ssh_client.assert_called_once()
    paramiko_keys_policy.assert_called_once()

    ssh_logger.assert_not_called()
    ssh_auth_logger.assert_not_called()

    assert ssh.auth == exec_helpers.SSHAuth()

    sftp = ssh._sftp
    assert sftp == paramiko_ssh_client().open_sftp()

    assert ssh._ssh == paramiko_ssh_client()

    assert ssh.hostname == host
    assert ssh.port == port

    ssh_logger.reset_mock()

    ssh.close()
    log.assert_has_calls(
        (
            mock.call.exception("Could not close ssh connection"),
            mock.call.exception("Could not close sftp connection"),
        )
    )


def test_012_re_connect(paramiko_ssh_client, paramiko_keys_policy, ssh_auth_logger):
    """Re-connect."""
    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())

    paramiko_ssh_client.reset_mock()
    paramiko_keys_policy.reset_mock()

    ssh.reconnect()

    ssh_ = mock.call()

    expected_calls = [
        ssh_.close(),
        ssh_,
        ssh_.set_missing_host_key_policy("WarningPolicy"),
        ssh_.connect(
            hostname="127.0.0.1",
            password=None,
            pkey=None,
            port=22,
            username=None,
            key_filename=(),
            allow_agent=True,
        ),
        ssh_.get_transport(),
        ssh_.get_transport().set_keepalive(1),
    ]

    assert paramiko_ssh_client.mock_calls == expected_calls


def test_013_no_sftp(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    """No sftp available."""
    # Helper code
    open_sftp = mock.Mock(side_effect=paramiko.SSHException)

    ssh_ = mock.Mock()
    ssh_.attach_mock(open_sftp, "open_sftp")
    paramiko_ssh_client.return_value = ssh_

    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild(f"{host}:{port}")
    # Test
    ssh = exec_helpers.SSHClient(
        host=host,
        auth=exec_helpers.SSHAuth(password=password),
    )

    with pytest.raises(paramiko.SSHException):
        # noinspection PyStatementEffect
        ssh._sftp  # pylint: disable=pointless-statement  # noqa: B018

    log.assert_has_calls(
        (
            mock.call.debug("SFTP is not connected, try to connect..."),
            mock.call.warning("SFTP enable failed! SSH only is accessible."),
        )
    )


def test_014_sftp_repair(
    paramiko_ssh_client,
    paramiko_keys_policy,
    ssh_auth_logger,
    get_logger,
):
    """No sftp available."""
    # Helper code
    sftp_ = mock.Mock()
    open_sftp = mock.Mock(side_effect=[paramiko.SSHException, sftp_, sftp_])

    ssh_ = mock.Mock()
    ssh_.attach_mock(open_sftp, "open_sftp")
    paramiko_ssh_client.return_value = ssh_

    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild(f"{host}:{port}")
    # Test
    ssh = exec_helpers.SSHClient(
        host=host,
        auth=exec_helpers.SSHAuth(password=password),
    )

    with pytest.raises(paramiko.SSHException):
        # noinspection PyStatementEffect
        ssh._sftp  # pylint: disable=pointless-statement  # noqa: B018

    log.assert_has_calls(
        (
            mock.call.debug("SFTP is not connected, try to connect..."),
            mock.call.warning("SFTP enable failed! SSH only is accessible."),
        )
    )
    ssh_logger.reset_mock()
    log.reset_mock()

    sftp = ssh._sftp
    assert sftp == open_sftp()
    log.assert_has_calls((mock.call.debug("SFTP is not connected, try to connect..."),))
