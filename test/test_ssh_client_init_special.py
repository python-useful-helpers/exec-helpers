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

import platform
import typing

import mock
import paramiko
import pytest

import exec_helpers


def gen_private_keys(amount: int = 1) -> typing.List[paramiko.RSAKey]:
    keys = []
    for _ in range(amount):
        keys.append(paramiko.RSAKey.generate(1024))
    return keys


def gen_public_key(private_key: typing.Optional[paramiko.RSAKey] = None) -> str:
    if private_key is None:
        private_key = paramiko.RSAKey.generate(1024)
    return "{0} {1}".format(private_key.get_name(), private_key.get_base64())


class FakeStream:
    def __init__(self, *args: bytes):
        self.__src = list(args)

    def __iter__(self):
        if len(self.__src) == 0:
            raise IOError()
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)


host = "127.0.0.1"
port = 22
username = "user"
password = "pass"


@pytest.fixture
def auto_add_policy(mocker):
    return mocker.patch("paramiko.AutoAddPolicy", return_value="AutoAddPolicy")


@pytest.fixture
def paramiko_ssh_client(mocker, monkeypatch):
    mocker.patch("time.sleep")
    return mocker.patch("paramiko.SSHClient")


@pytest.fixture
def ssh_auth_logger(mocker):
    return mocker.patch("exec_helpers.ssh_auth.logger")


@pytest.fixture
def get_logger(mocker):
    return mocker.patch("logging.getLogger")


def teardown_function(function):
    """Clean-up after tests."""
    with mock.patch("warnings.warn"):
        exec_helpers.SSHClient._clear_cache()


def test_001_require_key(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject key and allow to connect without key."""
    # Helper code
    _ssh = mock.call

    connect = mock.Mock(side_effect=[paramiko.AuthenticationException, mock.Mock()])
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    private_keys = gen_private_keys(1)

    # Test
    ssh = exec_helpers.SSHClient(host=host, username=username, private_keys=private_keys)

    paramiko_ssh_client.assert_called_once()
    auto_add_policy.assert_called_once()

    ssh_auth_logger.debug.assert_called_once_with(
        "Main key has been updated, public key is: \n" "{}".format(ssh.auth.public_key)
    )

    pkey = private_keys[0]

    kwargs = dict(hostname=host, pkey=None, port=port, username=username, password=None)
    kwargs1 = {key: kwargs[key] for key in kwargs}
    kwargs1["pkey"] = pkey

    expected_calls = [
        _ssh.set_missing_host_key_policy("AutoAddPolicy"),
        _ssh.connect(**kwargs),
        _ssh.connect(**kwargs1),
    ]

    assert expected_calls == paramiko_ssh_client().mock_calls


def test_002_use_next_key(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject 1 key and use next one."""
    # Helper code
    _ssh = mock.call

    connect = mock.Mock(side_effect=[paramiko.AuthenticationException, paramiko.AuthenticationException, mock.Mock()])
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    private_keys = gen_private_keys(2)

    # Test
    ssh = exec_helpers.SSHClient(host=host, username=username, private_keys=private_keys)

    paramiko_ssh_client.assert_called_once()
    auto_add_policy.assert_called_once()

    ssh_auth_logger.debug.assert_called_once_with(
        "Main key has been updated, public key is: \n" "{}".format(ssh.auth.public_key)
    )

    kwargs = dict(hostname=host, pkey=None, port=port, username=username, password=None)
    kwargs0 = {key: kwargs[key] for key in kwargs}
    kwargs0["pkey"] = private_keys[0]
    kwargs1 = {key: kwargs[key] for key in kwargs}
    kwargs1["pkey"] = private_keys[1]

    expected_calls = [
        _ssh.set_missing_host_key_policy("AutoAddPolicy"),
        _ssh.connect(**kwargs),
        _ssh.connect(**kwargs0),
        _ssh.connect(**kwargs1),
    ]

    assert expected_calls == paramiko_ssh_client().mock_calls


def test_003_password_required(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """No password provided."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.PasswordRequiredException)
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    private_keys = gen_private_keys(2)

    # Test
    with pytest.raises(paramiko.PasswordRequiredException):
        exec_helpers.SSHClient(host=host, username=username, private_keys=private_keys)
    ssh_auth_logger.assert_has_calls((mock.call.exception("No password has been set!"),))


def test_004_unexpected_password_required(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Password available, but requested anyway."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.PasswordRequiredException)
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    private_keys = gen_private_keys(2)

    # Test
    with pytest.raises(paramiko.PasswordRequiredException):
        exec_helpers.SSHClient(host=host, username=username, password=password, private_keys=private_keys)
    ssh_auth_logger.assert_has_calls(
        (mock.call.critical("Unexpected PasswordRequiredException, when password is set!"),)
    )


def test_005_auth_impossible_password(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject password."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(password=password))
    ssh_auth_logger.assert_has_calls((mock.call.exception("Connection using stored authentication info failed!"),))


def test_006_auth_impossible_key(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject key."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(key=gen_private_keys(1).pop()))
    ssh_auth_logger.assert_has_calls((mock.call.exception("Connection using stored authentication info failed!"),))


def test_007_auth_impossible_key_keys(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject key."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(
            host=host, auth=exec_helpers.SSHAuth(key=gen_private_keys(1).pop(), keys=gen_private_keys(2))
        )
    ssh_auth_logger.assert_has_calls((mock.call.exception("Connection using stored authentication info failed!"),))


def test_008_auth_impossible_key_no_verbose(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject auth without log."""
    # Helper code
    connect = mock.Mock(side_effect=paramiko.AuthenticationException)
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst

    # Test
    with pytest.raises(paramiko.AuthenticationException):
        exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(key=gen_private_keys(1).pop()), verbose=False)
    ssh_auth_logger.assert_not_called()


def test_009_auth_pass_no_key(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Reject key and use password."""
    # Helper code
    connect = mock.Mock(side_effect=[paramiko.AuthenticationException, mock.Mock()])
    _ssh_inst = mock.Mock()
    _ssh_inst.attach_mock(connect, "connect")
    paramiko_ssh_client.return_value = _ssh_inst
    key = gen_private_keys(1).pop()

    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(username=username, password=password, key=key))

    ssh_auth_logger.assert_has_calls((mock.call.debug("Main key has been updated, public key is: \nNone"),))

    assert ssh.auth == exec_helpers.SSHAuth(username=username, password=password, keys=[key])


def test_010_context(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Context manager."""
    # Test
    with exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth()) as ssh:
        paramiko_ssh_client.assert_called_once()
        auto_add_policy.assert_called_once()

        ssh_auth_logger.assert_not_called()

        assert ssh.auth == exec_helpers.SSHAuth()

        sftp = ssh._sftp
        assert sftp == paramiko_ssh_client().open_sftp()

        assert ssh._ssh == paramiko_ssh_client()

        assert ssh.hostname == host
        assert ssh.port == port


def test_011_clear_failed(paramiko_ssh_client, auto_add_policy, ssh_auth_logger, get_logger):
    """TearDown failed."""
    # Helper code
    _ssh = mock.Mock()
    _ssh.attach_mock(mock.Mock(side_effect=[Exception("Mocked SSH close()"), mock.Mock()]), "close")
    _sftp = mock.Mock()
    _sftp.attach_mock(mock.Mock(side_effect=[Exception("Mocked SFTP close()"), mock.Mock()]), "close")
    _ssh.attach_mock(mock.Mock(return_value=_sftp), "open_sftp")
    paramiko_ssh_client.return_value = _ssh

    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild("{host}:{port}".format(host=host, port=port))

    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())

    paramiko_ssh_client.assert_called_once()
    auto_add_policy.assert_called_once()

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
        (mock.call.exception("Could not close ssh connection"), mock.call.exception("Could not close sftp connection"))
    )


def test_012_re_connect(paramiko_ssh_client, auto_add_policy, ssh_auth_logger):
    """Re-connect."""
    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())

    paramiko_ssh_client.reset_mock()
    auto_add_policy.reset_mock()

    ssh.reconnect()

    _ssh = mock.call()

    expected_calls = [
        _ssh.close(),
        _ssh,
        _ssh.set_missing_host_key_policy("AutoAddPolicy"),
        _ssh.connect(hostname="127.0.0.1", password=None, pkey=None, port=22, username=None),
    ]

    assert paramiko_ssh_client.mock_calls == expected_calls


def test_013_no_sftp(paramiko_ssh_client, auto_add_policy, ssh_auth_logger, get_logger):
    """No sftp available."""
    # Helper code
    open_sftp = mock.Mock(side_effect=paramiko.SSHException)

    _ssh = mock.Mock()
    _ssh.attach_mock(open_sftp, "open_sftp")
    paramiko_ssh_client.return_value = _ssh

    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild("{host}:{port}".format(host=host, port=port))
    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(password=password))

    with pytest.raises(paramiko.SSHException):
        # noinspection PyStatementEffect
        ssh._sftp  # pylint: disable=pointless-statement

    log.assert_has_calls(
        (
            mock.call.debug("SFTP is not connected, try to connect..."),
            mock.call.warning("SFTP enable failed! SSH only is accessible."),
        )
    )


def test_014_sftp_repair(paramiko_ssh_client, auto_add_policy, ssh_auth_logger, get_logger):
    """No sftp available."""
    # Helper code
    _sftp = mock.Mock()
    open_sftp = mock.Mock(side_effect=[paramiko.SSHException, _sftp, _sftp])

    _ssh = mock.Mock()
    _ssh.attach_mock(open_sftp, "open_sftp")
    paramiko_ssh_client.return_value = _ssh

    ssh_logger = get_logger(exec_helpers.SSHClient.__name__)
    log = ssh_logger.getChild("{host}:{port}".format(host=host, port=port))
    # Test
    ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(password=password))

    with pytest.raises(paramiko.SSHException):
        # noinspection PyStatementEffect
        ssh._sftp  # pylint: disable=pointless-statement

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


def test_015_memorize(paramiko_ssh_client, auto_add_policy, ssh_auth_logger, mocker):
    """Memorize."""
    # Helper code
    mocker.patch("exec_helpers.exec_result.ExecResult")
    close_conn = mocker.patch("exec_helpers.ssh_client.SSHClient.close_connections")
    # Test
    port1 = 2222
    host1 = "127.0.0.2"

    # 1. Normal init
    ssh01 = exec_helpers.SSHClient(host=host)
    ssh02 = exec_helpers.SSHClient(host=host)
    ssh11 = exec_helpers.SSHClient(host=host, port=port1)
    ssh12 = exec_helpers.SSHClient(host=host, port=port1)
    ssh21 = exec_helpers.SSHClient(host=host1)
    ssh22 = exec_helpers.SSHClient(host=host1)

    assert ssh01 is ssh02
    assert ssh11 is ssh12
    assert ssh21 is ssh22

    assert ssh01 is not ssh11
    assert ssh01 is not ssh21
    assert ssh11 is not ssh21

    exec_helpers.SSHClient.close()
    close_conn.assert_not_called()

    # Mock returns false-connected state, so we just count close calls
    paramiko_ssh_client().close.assert_has_calls((mock.call(), mock.call(), mock.call()))

    # change creds
    exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(username=username))

    # Change back: new connection differs from old with the same creds
    ssh004 = exec_helpers.SSHAuth(host)

    assert ssh01 is not ssh004


def test_016_memorize_reconnect(paramiko_ssh_client, auto_add_policy, ssh_auth_logger, mocker):
    """Re-connect."""
    # Helper code
    mocker.patch("exec_helpers.ssh_client.SSHClient.execute", side_effect=paramiko.SSHException)
    # Test
    exec_helpers.SSHClient(host=host)
    paramiko_ssh_client.reset_mock()
    auto_add_policy.reset_mock()
    exec_helpers.SSHClient(host=host)
    paramiko_ssh_client.assert_called_once()
    auto_add_policy.assert_called_once()


@pytest.mark.skipif(
    "CPython" != platform.python_implementation(),
    reason="CPython only functionality: close connections depend on refcount",
)
def test_017_memorize_close_unused(paramiko_ssh_client, auto_add_policy, ssh_auth_logger, mocker):
    """Close unused connections."""
    # Helper code
    mocker.patch("warnings.warn")

    # Test
    ssh0 = exec_helpers.SSHClient(host=host)
    del ssh0  # remove reference - now it's cached and unused
    paramiko_ssh_client.reset_mock()
    # New connection on the same host:port with different auth
    ssh1 = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth(username=username))
    paramiko_ssh_client.assert_has_calls((mock.call().close(),))
    del ssh1  # remove reference - now it's cached and unused
    paramiko_ssh_client.reset_mock()
    exec_helpers.SSHClient._clear_cache()
    paramiko_ssh_client.assert_has_calls((mock.call().close(),))
