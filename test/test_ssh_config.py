# Standard Library
import io
import sys
from unittest import mock

# External Dependencies
import paramiko
import pytest

from exec_helpers import _ssh_helpers as ssh_helpers


HOST = "127.128.0.1"
PORT = 22
USER = "user"
IDENTIFY_FILES = ["/tmp/ssh/id_dsa", "/tmp/ssh/id_rsa", "/tmp/ssh/id_ecdsa", "/tmp/ssh/id_ed25519"]
PROXY_JUMP_1 = "127.127.0.1"
PROXY_JUMP_2 = "127.0.0.1"


SYSTEM_REAL_SSH_CONFIG = """
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
"""


SSH_CONFIG_ALL_NO_PROXY = f"""
Host 127.128.*.*
    Port {PORT}

    User {USER}
    IdentityFile {IDENTIFY_FILES[0]}
    IdentityFile {IDENTIFY_FILES[1]}
    IdentityFile {IDENTIFY_FILES[2]}
    IdentityFile {IDENTIFY_FILES[3]}

    ControlPath ~/.ssh/.control-%r@%h:%p
    ControlMaster auto
    Compression yes
"""

SSH_CONFIG_PROXY_COMMAND = """
Host 127.128.*.*
    ProxyCommand  ssh -q -A 127.127.0.1 nc %h %p
"""

SSH_CONFIG_PROXY_JUMP = f"""
Host 127.128.*.*
    ProxyJump {PROXY_JUMP_1}
"""


SSH_CONFIG_MULTI_PROXY_JUMP = f"""
Host 127.128.*.*
    ProxyJump {PROXY_JUMP_1}
Host {PROXY_JUMP_1}
    ProxyJump {PROXY_JUMP_2}
"""


SSH_CONFIG_OVERRIDE_HOSTNAME = f"""
HOST {PROXY_JUMP_1}
    Hostname {PROXY_JUMP_2}
"""


@pytest.fixture
def no_system_ssh_config(mocker):
    conf_sys: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_SYSTEM", autospec=True)
    conf_sys.exists.return_value = False


@pytest.fixture
def no_user_ssh_config(mocker):
    conf_user: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_USER", autospec=True)
    conf_user.exists.return_value = False


@pytest.fixture
def system_ssh_config(mocker) -> mock.MagicMock:
    conf_sys: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_SYSTEM", autospec=True)
    conf_sys.exists.return_value = True
    return conf_sys.open


@pytest.fixture
def user_ssh_config(mocker) -> mock.MagicMock:
    conf_sys: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_USER", autospec=True)
    conf_sys.exists.return_value = True
    return conf_sys.open


def test_no_configs(no_system_ssh_config, no_user_ssh_config):
    config = ssh_helpers.parse_ssh_config(None, HOST)
    assert config == {HOST: {"hostname": HOST}}

    host_config = config[HOST]
    assert host_config == ssh_helpers.SSHConfig(hostname=HOST)
    assert host_config != object()

    assert host_config.port is None

    assert host_config.user is None
    assert host_config.identityfile is None

    assert host_config.proxycommand is None
    assert host_config.proxyjump is None

    assert host_config.controlpath is None
    assert host_config.controlmaster is None

    assert host_config.compression is None


@pytest.mark.xfail(sys.version_info[:2] == (3, 6), reason="Patching of config file is not functional")
def test_simple_config(system_ssh_config, user_ssh_config):
    mock.mock_open(system_ssh_config, read_data=SYSTEM_REAL_SSH_CONFIG)
    mock.mock_open(user_ssh_config, SSH_CONFIG_ALL_NO_PROXY)

    config = ssh_helpers.parse_ssh_config(None, HOST)

    host_config = config[HOST]

    assert host_config.hostname == HOST
    assert host_config.port == PORT

    assert host_config.user == USER
    assert host_config.identityfile == IDENTIFY_FILES

    assert host_config.controlpath == f"~/.ssh/.control-{USER}@{HOST}:{PORT}"
    assert not host_config.controlmaster  # auto => False

    assert host_config.compression


@pytest.mark.xfail(sys.version_info[:2] == (3, 6), reason="Patching of config file is not functional")
def test_simple_override_proxy_command(system_ssh_config, user_ssh_config):
    mock.mock_open(system_ssh_config, SSH_CONFIG_ALL_NO_PROXY)
    mock.mock_open(user_ssh_config, SSH_CONFIG_PROXY_COMMAND)

    config = ssh_helpers.parse_ssh_config(None, HOST)

    host_config = config[HOST]

    assert host_config.hostname == HOST
    assert host_config.proxycommand == f"ssh -q -A {PROXY_JUMP_1} nc {HOST} {PORT}"

    assert host_config.as_dict == host_config
    assert ssh_helpers.SSHConfig.from_ssh_config(host_config.as_dict) == host_config


@pytest.mark.xfail(sys.version_info[:2] == (3, 6), reason="Patching of config file is not functional")
def test_simple_override_single_proxy_jump(system_ssh_config, user_ssh_config):
    mock.mock_open(system_ssh_config, SSH_CONFIG_ALL_NO_PROXY)
    mock.mock_open(user_ssh_config, SSH_CONFIG_PROXY_JUMP)

    config = ssh_helpers.parse_ssh_config(None, HOST)

    host_config = config[HOST]

    assert host_config.hostname == HOST
    assert host_config.proxycommand is None
    assert host_config.proxyjump == PROXY_JUMP_1

    assert PROXY_JUMP_1 in config
    assert config[PROXY_JUMP_1].hostname == PROXY_JUMP_1

    assert host_config.as_dict == host_config
    assert ssh_helpers.SSHConfig.from_ssh_config(host_config.as_dict) == host_config


@pytest.mark.xfail(sys.version_info[:2] == (3, 6), reason="Patching of config file is not functional")
def test_simple_override_chain_proxy_jump(system_ssh_config, user_ssh_config):
    mock.mock_open(system_ssh_config, SSH_CONFIG_ALL_NO_PROXY)
    mock.mock_open(user_ssh_config, SSH_CONFIG_MULTI_PROXY_JUMP)

    config = ssh_helpers.parse_ssh_config(None, HOST)

    host_config = config[HOST]

    assert host_config.hostname == HOST
    assert host_config.proxycommand is None
    assert host_config.proxyjump == PROXY_JUMP_1

    assert PROXY_JUMP_1 in config
    assert config[PROXY_JUMP_1].hostname == PROXY_JUMP_1
    assert config[PROXY_JUMP_1].proxyjump == PROXY_JUMP_2

    assert PROXY_JUMP_2 in config
    assert config[PROXY_JUMP_2].hostname == PROXY_JUMP_2
    assert config[PROXY_JUMP_2].proxyjump is None

    # Rebuild possibility even with chains
    config_as_dict = {host: conf.as_dict for host, conf in config.items()}
    assert ssh_helpers.parse_ssh_config(config_as_dict, HOST) == config


def test_simple_override_hostname(no_system_ssh_config, no_user_ssh_config):
    paramiko_config = paramiko.SSHConfig()
    paramiko_config.parse(io.StringIO(SSH_CONFIG_OVERRIDE_HOSTNAME))

    config = ssh_helpers.parse_ssh_config(paramiko_config, PROXY_JUMP_1)
    assert PROXY_JUMP_1 in config
    assert config[PROXY_JUMP_1].hostname == PROXY_JUMP_2
    assert PROXY_JUMP_2 in config
    assert config[PROXY_JUMP_1] == config[PROXY_JUMP_2]


def test_negative(no_system_ssh_config, no_user_ssh_config):
    with pytest.raises(ValueError):
        ssh_helpers.SSHConfig(HOST, port=0)

    with pytest.raises(ValueError):
        ssh_helpers.SSHConfig(HOST, port=65536)

    with pytest.raises(ValueError):
        ssh_helpers.SSHConfig(HOST, proxycommand=f"ssh -q -A {PROXY_JUMP_1} nc {HOST} {PORT}", proxyjump=PROXY_JUMP_1)


def test_negative_read(system_ssh_config, no_user_ssh_config):
    system_ssh_config.side_effect = RuntimeError()
    config = ssh_helpers.parse_ssh_config(None, HOST)
    assert config == {HOST: {"hostname": HOST}}
