#    Copyright 2018 - 2021 Alexey Stepanov aka penguinolog.

#    Copyright 2013 - 2016 Mirantis, Inc.
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

"""SSH client helper based on Paramiko. Base class."""

from __future__ import annotations

# Standard Library
import concurrent.futures
import copy
import datetime
import getpass
import logging
import pathlib
import shlex
import stat
import time
import typing

# External Dependencies
import paramiko
import tenacity
import threaded

# Package Implementation
from exec_helpers import api
from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import exec_result
from exec_helpers import proc_enums
from exec_helpers import ssh_auth
from exec_helpers.api import CalledProcessErrorSubClassT
from exec_helpers.api import CommandT
from exec_helpers.api import ErrorInfoT
from exec_helpers.api import ExpectedExitCodesT
from exec_helpers.api import LogMaskReT
from exec_helpers.api import OptionalStdinT
from exec_helpers.api import OptionalTimeoutT
from exec_helpers.proc_enums import ExitCodeT

# Local Implementation
from . import _log_templates
from . import _ssh_helpers
from ._ssh_helpers import SSHConfigsDictT

if typing.TYPE_CHECKING:
    # Standard Library
    import socket

__all__ = ("SSHClientBase", "SshExecuteAsyncResult", "SupportPathT")

KeepAlivePeriodT = typing.Union[int, bool]
SupportPathT = typing.Union[str, pathlib.PurePath]
_OptionalSSHAuthMapT = typing.Optional[typing.Union[typing.Dict[str, ssh_auth.SSHAuth], ssh_auth.SSHAuthMapping]]
_OptionalSSHConfigArgT = typing.Union[
    str,
    paramiko.SSHConfig,
    SSHConfigsDictT,
    _ssh_helpers.HostsSSHConfigs,
    None,
]
_SSHConnChainT = typing.List[typing.Tuple[_ssh_helpers.SSHConfig, ssh_auth.SSHAuth]]
_OptSSHAuthT = typing.Optional[ssh_auth.SSHAuth]
_RType = typing.TypeVar("_RType")


class RetryOnExceptions(tenacity.retry_if_exception):  # type: ignore
    """Advanced retry on exceptions.

    :param retry_on: Exceptions to retry on
    :type retry_on: typing.Union[typing.Type[BaseException], typing.Tuple[typing.Type[BaseException], ...]]
    :param reraise: Exceptions, which should be reraised, even if subclasses retry_on
    :type reraise: typing.Union[typing.Type[BaseException], typing.Tuple[typing.Type[BaseException], ...]]
    """

    def __init__(
        self,
        retry_on: typing.Union[typing.Type[BaseException], typing.Tuple[typing.Type[BaseException], ...]],
        reraise: typing.Union[typing.Type[BaseException], typing.Tuple[typing.Type[BaseException], ...]],
    ) -> None:
        """Retry on exceptions, except several types."""
        super().__init__(lambda e: isinstance(e, retry_on) and not isinstance(e, reraise))


# noinspection PyTypeHints
class SshExecuteAsyncResult(api.ExecuteAsyncResult):
    """Override original NamedTuple with proper typing."""

    __slots__ = ()

    @property
    def interface(self) -> paramiko.Channel:
        """Override original NamedTuple with proper typing.

        :return: control interface
        :rtype: paramiko.Channel
        """
        return super().interface  # type: ignore

    @property
    def stdin(self) -> paramiko.ChannelFile:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDIN interface
        :rtype: paramiko.ChannelFile
        """
        return super().stdin

    @property
    def stderr(self) -> typing.Optional[paramiko.ChannelFile]:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDERR interface
        :rtype: typing.Optional[paramiko.ChannelFile]
        """
        return super().stderr

    @property
    def stdout(self) -> typing.Optional[paramiko.ChannelFile]:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDOUT interface
        :rtype: typing.Optional[paramiko.ChannelFile]
        """
        return super().stdout


class _SudoContext(typing.ContextManager[None]):
    """Context manager for call commands with sudo.

    :param ssh: connection instance
    :type ssh: SSHClientBase
    :param enforce: sudo mode for context manager
    :type enforce: typing.Optional[bool]
    """

    __slots__ = ("__ssh", "__sudo_status", "__enforce")

    def __init__(self, ssh: SSHClientBase, enforce: typing.Optional[bool] = None) -> None:
        """Context manager for call commands with sudo."""
        self.__ssh: SSHClientBase = ssh
        self.__sudo_status: bool = ssh.sudo_mode
        self.__enforce: typing.Optional[bool] = enforce

    def __enter__(self) -> None:
        self.__sudo_status = self.__ssh.sudo_mode
        if self.__enforce is not None:
            self.__ssh.sudo_mode = self.__enforce

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        self.__ssh.sudo_mode = self.__sudo_status


class _KeepAliveContext(typing.ContextManager[None]):
    """Context manager for keepalive management.

    :param ssh: connection instance
    :type ssh: SSHClientBase
    :param enforce: keepalive period for context manager
    :type enforce: int
    """

    __slots__ = ("__ssh", "__keepalive_period", "__enforce")

    def __init__(self, ssh: SSHClientBase, enforce: int) -> None:
        """Context manager for keepalive management."""
        self.__ssh: SSHClientBase = ssh
        self.__keepalive_period: int = ssh.keepalive_period
        self.__enforce: int = enforce

    def __enter__(self) -> None:
        self.__ssh.__enter__()
        self.__keepalive_period = self.__ssh.keepalive_period
        self.__ssh.keepalive_period = self.__enforce

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        # Exit before releasing!
        self.__ssh.__exit__(exc_type=exc_type, exc_val=exc_val, exc_tb=exc_tb)  # type: ignore
        self.__ssh.keepalive_period = self.__keepalive_period


class SSHClientBase(api.ExecHelper):
    """SSH Client helper.

    :param host: remote hostname
    :type host: str
    :param port: remote ssh port
    :type port: typing.Optional[int]
    :param username: remote username.
    :type username: typing.Optional[str]
    :param password: remote password
    :type password: typing.Optional[str]
    :param auth: credentials for connection
    :type auth: typing.Optional[ssh_auth.SSHAuth]
    :param verbose: show additional error/warning messages
    :type verbose: bool
    :param ssh_config: SSH configuration for connection. Maybe config path, parsed as dict and paramiko parsed.
    :type ssh_config:
        typing.Union[
            str,
            paramiko.SSHConfig,
            typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]],
            HostsSSHConfigs,
            None
        ]
    :param ssh_auth_map: SSH authentication information mapped to host names. Useful for complex SSH Proxy cases.
    :type ssh_auth_map: typing.Optional[typing.Union[typing.Dict[str, ssh_auth.SSHAuth], ssh_auth.SSHAuthMapping]]
    :param sock: socket for connection. Useful for ssh proxies support
    :type sock: typing.Optional[typing.Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]]
    :param keepalive: keepalive period
    :type keepalive: typing.Union[int, bool]

    .. note:: auth has priority over username/password/private_keys
    .. note::

        for proxy connection auth information is collected from SSHConfig
        if ssh_auth_map record is not available

    .. versionchanged:: 6.0.0 private_keys, auth and verbose became keyword-only arguments
    .. versionchanged:: 6.0.0 added optional ssh_config for ssh-proxy & low level connection parameters handling
    .. versionchanged:: 6.0.0 added optional ssh_auth_map for ssh proxy cases with authentication on each step
    .. versionchanged:: 6.0.0 added optional sock for manual proxy chain handling
    .. versionchanged:: 6.0.0 keepalive exposed to constructor
    .. versionchanged:: 6.0.0 keepalive became int, now used in ssh transport as period of keepalive requests
    .. versionchanged:: 6.0.0 private_keys is deprecated
    .. versionchanged:: 7.0.0 private_keys is removed
    .. versionchanged:: 7.0.0 keepalive_mode is removed
    """

    __slots__ = (
        "__hostname",
        "__port",
        "__auth_mapping",
        "__ssh",
        "__sftp",
        "__sudo_mode",
        "__keepalive_period",
        "__verbose",
        "__ssh_config",
        "__sock",
        "__conn_chain",
    )

    def __hash__(self) -> int:
        """Hash for usage as dict keys.

        :return: hash describing current connection
        :rtype: int
        """
        return hash((self.__class__, self.hostname, self.port, self.auth))

    def __init__(
        self,
        host: str,
        port: typing.Optional[int] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        *,
        auth: _OptSSHAuthT = None,
        verbose: bool = True,
        ssh_config: _OptionalSSHConfigArgT = None,
        ssh_auth_map: _OptionalSSHAuthMapT = None,
        sock: typing.Optional[typing.Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]] = None,
        keepalive: KeepAlivePeriodT = 1,
    ) -> None:
        """Main SSH Client helper."""
        # Init ssh config. It's main source for connection parameters
        if isinstance(ssh_config, _ssh_helpers.HostsSSHConfigs):
            self.__ssh_config: _ssh_helpers.HostsSSHConfigs = ssh_config
        else:
            self.__ssh_config = _ssh_helpers.parse_ssh_config(ssh_config, host)

        # Get config. We are not resolving full chain. If you are have a chain by some reason - init config manually.
        config: _ssh_helpers.SSHConfig = self.__ssh_config[host]

        # Save resolved hostname and port
        self.__hostname: str = config.hostname
        if port is not None:
            self.__port: int = port
        else:
            self.__port = config.port if config.port is not None else 22

        # Store initial auth mapping
        self.__auth_mapping = ssh_auth.SSHAuthMapping(ssh_auth_map)
        # We are already resolved hostname
        if self.hostname not in self.__auth_mapping and host in self.__auth_mapping:
            self.__auth_mapping[self.hostname] = self.__auth_mapping[host]

        self.__sudo_mode = False
        self.__keepalive_period: int = int(keepalive)
        self.__verbose: bool = verbose
        self.__sock = sock

        self.__ssh: paramiko.SSHClient
        self.__sftp: typing.Optional[paramiko.SFTPClient] = None

        # Rebuild SSHAuth object if required.
        # Priority: auth > credentials > auth mapping
        if auth is not None:
            self.__auth_mapping[self.hostname] = real_auth = copy.copy(auth)
        elif self.hostname not in self.__auth_mapping or any((username, password)):
            self.__auth_mapping[self.hostname] = real_auth = ssh_auth.SSHAuth(
                username=username if username is not None else config.user,
                password=password,
                key_filename=config.identityfile,
            )
        else:
            real_auth = self.__auth_mapping[self.hostname]

        # Init super with host and real port and username
        mod_name = "exec_helpers" if self.__module__.startswith("exec_helpers") else self.__module__
        log_username: str = real_auth.username if real_auth.username is not None else getpass.getuser()

        super().__init__(
            logger=logging.getLogger(f"{mod_name}.{self.__class__.__name__}").getChild(
                f"({log_username}@{host}:{self.port})"
            )
        )

        # Update config for target host: merge with data from credentials and parameters.
        # SSHConfig is the single source for hostname/port/... during low level connection construction.
        self.__rebuild_ssh_config()

        # Build connection chain once and use it for connection later
        if sock is None:
            self.__conn_chain: _SSHConnChainT = self.__build_connection_chain()
        else:
            self.__conn_chain = []

        self.__connect()

    def __rebuild_ssh_config(self) -> None:
        """Rebuild main ssh config from available information."""
        self.__ssh_config[self.hostname] = self.__ssh_config[self.hostname].overridden_by(
            _ssh_helpers.SSHConfig(
                hostname=self.hostname,
                port=self.port,
                user=self.auth.username,
                identityfile=self.auth.key_filename,
            )
        )

    def __build_connection_chain(self) -> _SSHConnChainT:
        """Build ssh connection chain to reach destination host.

        :return: list of SSHConfig - SSHAuth pairs in order of connection
        :rtype: typing.List[typing.Tuple[SSHConfig, ssh_auth.SSHAuth]]
        """
        conn_chain: _SSHConnChainT = []

        config = self.ssh_config[self.hostname]
        default_auth = ssh_auth.SSHAuth(username=config.user, key_filename=config.identityfile)
        auth = self.__auth_mapping.get_with_alt_hostname(config.hostname, self.hostname, default=default_auth)
        conn_chain.append((config, auth))

        while config.proxyjump is not None:
            # pylint: disable=no-member
            config = self.ssh_config[config.proxyjump]
            default_auth = ssh_auth.SSHAuth(username=config.user, key_filename=config.identityfile)
            conn_chain.append((config, self.__auth_mapping.get(config.hostname, default_auth)))
        return conn_chain[::-1]

    @property
    def auth(self) -> ssh_auth.SSHAuth:
        """Internal authorisation object.

        Attention: this public property is mainly for inheritance,
        debug and information purposes.
        Calls outside SSHClient and child classes is sign of incorrect design.
        Change is completely disallowed.

        :return: SSH authorisation object for current connection.
        :rtype: ssh_auth.SSHAuth
        """
        return self.__auth_mapping[self.hostname]

    @property
    def hostname(self) -> str:
        """Connected remote host name.

        :return: remote hostname
        :rtype: str
        """
        return self.__hostname

    @property
    def port(self) -> int:
        """Connected remote port number.

        :return: remote port
        :rtype: int
        """
        return self.__port

    @property
    def ssh_config(self) -> _ssh_helpers.HostsSSHConfigs:
        """SSH connection config.

        :return: SSH config for connection
        :rtype: HostsSSHConfigs
        """
        return copy.deepcopy(self.__ssh_config)

    @property
    def _ssh_transport(self) -> paramiko.Transport:
        """Paramiko transport object getter.

        :return: Paramiko transport.
        :rtype: paramiko.Transport
        :raises ConnectionError: Can not get SSH transport (with reconnect)
        Used internally.
        """
        with self.lock:
            transport = self.__ssh.get_transport()
            if transport is not None:
                return transport

            self.reconnect()
            transport = self.__ssh.get_transport()
            if transport is not None:
                return transport
            raise ConnectionError("Can not get SSH transport (with reconnect)")

    @property
    def is_alive(self) -> bool:
        """Paramiko status: ready to use|reconnect required.

        :return: Paramiko transport is available
        :rtype: bool
        """
        return self.__ssh.get_transport() is not None

    def __repr__(self) -> str:
        """Representation for debug purposes.

        :return: brief connection information for debug purposes
        :rtype: str
        """
        return f"{self.__class__.__name__}(host={self.hostname}, port={self.port}, auth={self.auth!r})"

    def __str__(self) -> str:  # pragma: no cover
        """Representation for debug purposes.

        :return: short string with connection information
        :rtype: str
        """
        return f"{self.__class__.__name__}(host={self.hostname}, port={self.port}) for user {self.auth.username}"

    @property
    def _ssh(self) -> paramiko.SSHClient:
        """Ssh client object getter for inheritance support only.

        Attention: ssh client object creation and change
        is allowed only by __init__ and reconnect call.

        :rtype: paramiko.SSHClient
        """
        return self.__ssh

    @tenacity.retry(
        retry=RetryOnExceptions(retry_on=paramiko.SSHException, reraise=paramiko.AuthenticationException),
        stop=tenacity.stop.stop_after_attempt(3),  # type: ignore
        wait=tenacity.wait.wait_fixed(3),  # type: ignore
        reraise=True,
    )
    def __connect(self) -> None:
        """Main method for connection open."""
        with self.lock:
            if self.__sock is not None:
                sock = self.__sock

                self.__ssh = paramiko.SSHClient()
                self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.auth.connect(
                    client=self.__ssh,
                    hostname=self.hostname,
                    port=self.port,
                    log=self.__verbose,
                    sock=sock,
                )
            else:
                self.__ssh = self.__get_client()

            transport: paramiko.Transport = self._ssh_transport
            transport.set_keepalive(1 if self.__keepalive_period else 0)  # send keepalive packets

    def __get_client(self) -> paramiko.SSHClient:
        """Connect using connection chain information.

        :return: paramiko ssh connection object
        :rtype: paramiko.SSHClient
        :raises ValueError: ProxyCommand found in connection chain after first host reached
        :raises RuntimeError: Unexpected state
        :raises ConnectionError: Can not get SSH transport
        """

        last_ssh_client: paramiko.SSHClient = paramiko.SSHClient()
        last_ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        config, auth = self.__conn_chain[0]
        if config.proxycommand:
            auth.connect(
                last_ssh_client,
                hostname=config.hostname,
                port=config.port or 22,
                sock=paramiko.ProxyCommand(config.proxycommand),
            )
        else:
            auth.connect(last_ssh_client, hostname=config.hostname, port=config.port or 22)

        for config, auth in self.__conn_chain[1:]:  # start has another logic, so do it out of cycle
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if config.proxyjump:
                transport = last_ssh_client.get_transport()
                if transport is None:
                    raise ConnectionError("Can not get SSH transport")
                sock = transport.open_channel(
                    kind="direct-tcpip",
                    dest_addr=(config.hostname, config.port or 22),
                    src_addr=(config.proxyjump, 0),
                )
                auth.connect(ssh, hostname=config.hostname, port=config.port or 22, sock=sock)
                last_ssh_client = ssh
                continue

            if config.proxycommand:
                raise ValueError(f"ProxyCommand found in connection chain after first host reached!\n{config}")

            raise RuntimeError("Unexpected state: Final host by configuration, but requested host is not reached")
        return last_ssh_client

    def __connect_sftp(self) -> None:
        """SFTP connection opener."""
        with self.lock:
            try:
                self.__sftp = self.__ssh.open_sftp()
            except paramiko.SSHException:
                self.logger.warning("SFTP enable failed! SSH only is accessible.")

    @property
    def _sftp(self) -> paramiko.sftp_client.SFTPClient:
        """SFTP channel access for inheritance.

        :rtype: paramiko.sftp_client.SFTPClient
        :raises paramiko.SSHException: SFTP connection failed
        """
        if self.__sftp is not None:
            return self.__sftp
        self.logger.debug("SFTP is not connected, try to connect...")
        self.__connect_sftp()
        if self.__sftp is not None:
            return self.__sftp
        raise paramiko.SSHException("SFTP connection failed")

    def close(self) -> None:
        """Close SSH and SFTP sessions."""
        with self.lock:
            # noinspection PyBroadException
            try:
                self.__ssh.close()
                self.__sftp = None
            except Exception:
                self.logger.exception("Could not close ssh connection")
                if self.__sftp is not None:
                    # noinspection PyBroadException
                    try:
                        self.__sftp.close()
                    except Exception:
                        self.logger.exception("Could not close sftp connection")

    def __del__(self) -> None:
        """Destructor helper: close channel and threads BEFORE closing others.

        Due to threading in paramiko, default destructor could generate asserts on close,
        so we calling channel close before closing main ssh object.
        """
        try:
            self.__ssh.close()
        except BaseException as e:  # pragma: no cover  # NOSONAR
            self.logger.debug(f"Exception in {self!s} destructor call: {e}")
        self.__sftp = None

    def __enter__(self) -> SSHClientBase:  # pylint: disable=useless-super-delegation
        """Get context manager.

        :return: exec helper instance with entered context manager
        :rtype: SSHClientBase
        """
        # noinspection PyTypeChecker
        return super().__enter__()

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        """Exit context manager.

        .. versionchanged:: 1.0.0 disconnect enforced on close
        .. versionchanged:: 1.1.0 release lock on exit
        .. versionchanged:: 1.2.1 disconnect enforced on close only not in keepalive mode
        """
        if not self.__keepalive_period:
            self.close()
        super().__exit__(exc_type, exc_val, exc_tb)

    @property
    def sudo_mode(self) -> bool:
        """Persistent sudo mode for connection object.

        :rtype: bool
        """
        return self.__sudo_mode

    @sudo_mode.setter
    def sudo_mode(self, mode: bool) -> None:
        """Persistent sudo mode change for connection object.

        :param mode: sudo status: enabled | disabled
        :type mode: bool
        """
        self.__sudo_mode = bool(mode)

    @property
    def keepalive_period(self) -> int:
        """Keepalive period for connection object.

        :rtype: int
        If 0 - close connection on exit from context manager.
        """
        return self.__keepalive_period

    @keepalive_period.setter
    def keepalive_period(self, period: KeepAlivePeriodT) -> None:
        """Keepalive period change for connection object.

        :param period: keepalive period change
        :type period: typing.Union[int, bool]
        If 0 - close connection on exit from context manager.
        """
        self.__keepalive_period = int(period)
        transport: paramiko.Transport = self._ssh_transport
        transport.set_keepalive(int(period))

    def reconnect(self) -> None:
        """Reconnect SSH session."""
        with self.lock:
            self.close()
            self.__connect()

    def sudo(self, enforce: typing.Optional[bool] = None) -> _SudoContext:
        """Call contextmanager for sudo mode change.

        :param enforce: Enforce sudo enabled or disabled. By default: None
        :type enforce: typing.Optional[bool]
        :return: context manager with selected sudo state inside
        :rtype: typing.ContextManager[None]
        """
        return _SudoContext(ssh=self, enforce=enforce)

    def keepalive(self, enforce: KeepAlivePeriodT = 1) -> _KeepAliveContext:
        """Call contextmanager with keepalive period change.

        :param enforce: Enforce keepalive period.
        :type enforce: typing.Union[int, bool]
        :return: context manager with selected keepalive state inside
        :rtype: typing.ContextManager[None]

        .. Note:: Enter and exit ssh context manager is produced as well.
        .. versionadded:: 1.2.1
        """
        return _KeepAliveContext(ssh=self, enforce=int(enforce))

    def _prepare_command(self, cmd: str, chroot_path: typing.Optional[str] = None) -> str:
        """Prepare command: cower chroot and other cases.

        :param cmd: main command
        :param chroot_path: path to make chroot for execution
        :return: final command, includes chroot, if required
        """
        if not self.sudo_mode:
            return super()._prepare_command(cmd=cmd, chroot_path=chroot_path)
        quoted_command: str = shlex.quote(cmd)
        if any((chroot_path, self._chroot_path)):
            target_path: str = shlex.quote(chroot_path if chroot_path else self._chroot_path)  # type: ignore
            return f'chroot {target_path} sudo sh -c {shlex.quote(f"eval {quoted_command}")}'
        return f'sudo -S sh -c {shlex.quote(f"eval {quoted_command}")}'

    # noinspection PyMethodOverriding
    def _execute_async(  # pylint: disable=arguments-differ
        self,
        command: str,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
        **kwargs: typing.Any,
    ) -> SshExecuteAsyncResult:
        """Execute command in async mode and return channel with IO objects.

        :param command: Command for execution
        :type command: str
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param chroot_path: chroot path override
        :type chroot_path: typing.Optional[str]
        :param get_pty: Get PTY for connection
        :type get_pty: bool
        :param width: PTY width
        :type width: int
        :param height: PTY height
        :type height: int
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Tuple with control interface and file-like objects for STDIN/STDERR/STDOUT
        :rtype: typing.NamedTuple(
                    'SshExecuteAsyncResult',
                    [
                        ('interface', paramiko.Channel),
                        ('stdin', paramiko.ChannelFile),
                        ('stderr', typing.Optional[paramiko.ChannelFile]),
                        ('stdout', typing.Optional[paramiko.ChannelFile]),
                        ("started", datetime.datetime),
                    ]
                )

        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 stdin data
        .. versionchanged:: 1.2.0 get_pty moved to `**kwargs`
        .. versionchanged:: 2.1.0 Use typed NamedTuple as result
        .. versionchanged:: 3.2.0 Expose pty options as optional keyword-only arguments
        .. versionchanged:: 4.1.0 support chroot
        """
        chan: paramiko.Channel = self._ssh_transport.open_session()

        if get_pty:
            # Open PTY
            chan.get_pty(term="vt100", width=width, height=height, width_pixels=0, height_pixels=0)

        _stdin: paramiko.ChannelFile = chan.makefile("wb")  # type: ignore
        stdout: paramiko.ChannelFile = chan.makefile("rb")  # type: ignore
        if open_stderr:
            stderr: typing.Optional[paramiko.ChannelFile] = chan.makefile_stderr("rb")  # type: ignore
        else:
            stderr = None

        cmd = f"{self._prepare_command(cmd=command, chroot_path=chroot_path)}\n"

        started = datetime.datetime.utcnow()
        if self.sudo_mode:
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side
            if not stdout.channel.closed:
                # noinspection PyTypeChecker
                self.auth.enter_password(_stdin)
                _stdin.flush()
        else:
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side

        if stdin is not None:
            if not _stdin.channel.closed:
                stdin_str: bytes = self._string_bytes_bytearray_as_bytes(stdin)

                _stdin.write(stdin_str)
                _stdin.flush()
            else:
                self.logger.warning("STDIN Send failed: closed channel")

        if open_stdout:
            res_stdout = stdout
        else:
            stdout.close()
            res_stdout = None

        # noinspection PyArgumentList
        return SshExecuteAsyncResult(
            interface=chan,
            stdin=_stdin,
            stderr=stderr,
            stdout=res_stdout,
            started=started,
        )

    def _exec_command(  # type: ignore
        self,
        command: str,
        async_result: SshExecuteAsyncResult,
        timeout: OptionalTimeoutT,
        *,
        verbose: bool = False,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Get exit status from channel with timeout.

        :param command: executed command (for logs)
        :type command: str
        :param async_result: execute_async result
        :type async_result: SshExecuteAsyncResult
        :param timeout: timeout before stop execution with TimeoutError
        :type timeout: typing.Union[int, float, None]
        :param verbose: produce log.info records for STDOUT/STDERR
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """

        def poll_streams() -> None:
            """Poll FIFO buffers if data available."""
            if async_result.stdout and async_result.interface.recv_ready():
                result.read_stdout(src=async_result.stdout, log=self.logger, verbose=verbose)
            if async_result.stderr and async_result.interface.recv_stderr_ready():
                result.read_stderr(src=async_result.stderr, log=self.logger, verbose=verbose)

        @threaded.threadpooled
        def poll_pipes() -> None:
            """Polling task for FIFO buffers."""
            while not async_result.interface.status_event.is_set():
                time.sleep(0.1)
                if async_result.stdout or async_result.stderr:
                    poll_streams()

            result.read_stdout(src=async_result.stdout, log=self.logger, verbose=verbose)
            result.read_stderr(src=async_result.stderr, log=self.logger, verbose=verbose)
            result.exit_code = async_result.interface.exit_status

        # channel.status_event.wait(timeout)
        cmd_for_log: str = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        # Store command with hidden data
        result = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)

        # noinspection PyNoneFunctionAssignment,PyTypeChecker
        future: concurrent.futures.Future[None] = poll_pipes()

        concurrent.futures.wait([future], timeout)

        # Process closed?
        if async_result.interface.status_event.is_set():
            async_result.interface.close()
            return result

        async_result.interface.close()
        async_result.interface.status_event.set()
        future.cancel()

        concurrent.futures.wait([future], 0.001)
        result.set_timestamp()

        wait_err_msg: str = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(result=result, timeout=timeout)  # type: ignore

    def execute(  # pylint: disable=arguments-differ
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param get_pty: Get PTY for connection
        :type get_pty: bool
        :param width: PTY width
        :type width: int
        :param height: PTY height
        :type height: int
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        .. versionchanged:: 7.0.0 Allow command as list of arguments. Command will be joined with components escaping.
        """
        return super().execute(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            get_pty=get_pty,
            width=width,
            height=height,
            **kwargs,
        )

    def __call__(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param get_pty: Get PTY for connection
        :type get_pty: bool
        :param width: PTY width
        :type width: int
        :param height: PTY height
        :type height: int
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        """
        return super().__call__(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            get_pty=get_pty,
            width=width,
            height=height,
            **kwargs,
        )

    def check_call(  # pylint: disable=arguments-differ
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        error_info: ErrorInfoT = None,
        expected: ExpectedExitCodesT = (proc_enums.EXPECTED,),
        raise_on_err: bool = True,
        *,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
        exception_class: CalledProcessErrorSubClassT = exceptions.CalledProcessError,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command and check for return code.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param error_info: Text for error details, if fail happens
        :type error_info: typing.Optional[str]
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param get_pty: Get PTY for connection
        :type get_pty: bool
        :param width: PTY width
        :type width: int
        :param height: PTY height
        :type height: int
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[exceptions.CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        return super().check_call(
            command=command,
            verbose=verbose,
            timeout=timeout,
            error_info=error_info,
            expected=expected,
            raise_on_err=raise_on_err,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            get_pty=get_pty,
            width=width,
            height=height,
            exception_class=exception_class,
            **kwargs,
        )

    def check_stderr(  # pylint: disable=arguments-differ
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        error_info: ErrorInfoT = None,
        raise_on_err: bool = True,
        *,
        expected: ExpectedExitCodesT = (proc_enums.EXPECTED,),
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
        exception_class: CalledProcessErrorSubClassT = exceptions.CalledProcessError,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param error_info: Text for error details, if fail happens
        :type error_info: typing.Optional[str]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param get_pty: Get PTY for connection
        :type get_pty: bool
        :param width: PTY width
        :type width: int
        :param height: PTY height
        :type height: int
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[exceptions.CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        return super().check_stderr(
            command=command,
            verbose=verbose,
            timeout=timeout,
            error_info=error_info,
            raise_on_err=raise_on_err,
            expected=expected,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            get_pty=get_pty,
            width=width,
            height=height,
            exception_class=exception_class,
            **kwargs,
        )

    def _get_proxy_channel(
        self,
        port: typing.Optional[int],
        ssh_config: _ssh_helpers.SSHConfig,
    ) -> paramiko.Channel:
        """Get ssh proxy channel.

        :param port: target port
        :type port: typing.Optional[int]
        :param ssh_config: pre-parsed ssh config
        :type ssh_config: SSHConfig
        :return: ssh channel for usage as socket for new connection over it
        :rtype: paramiko.Channel

        .. versionadded:: 6.0.0
        """
        if port is not None:
            dest_port: int = port
        else:
            dest_port = ssh_config.port if ssh_config.port is not None else 22

        return self._ssh_transport.open_channel(
            kind="direct-tcpip",
            dest_addr=(ssh_config.hostname, dest_port),
            src_addr=(self.hostname, 0),
        )

    def proxy_to(
        self,
        host: str,
        port: typing.Optional[int] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        *,
        auth: _OptSSHAuthT = None,
        verbose: bool = True,
        ssh_config: _OptionalSSHConfigArgT = None,
        ssh_auth_map: _OptionalSSHAuthMapT = None,
        keepalive: KeepAlivePeriodT = 1,
    ) -> SSHClientBase:
        """Start new SSH connection using current as proxy.

        :param host: remote hostname
        :type host: str
        :param port: remote ssh port
        :type port: typing.Optional[int]
        :param username: remote username.
        :type username: typing.Optional[str]
        :param password: remote password
        :type password: typing.Optional[str]
        :param auth: credentials for connection
        :type auth: typing.Optional[ssh_auth.SSHAuth]
        :param verbose: show additional error/warning messages
        :type verbose: bool
        :param ssh_config: SSH configuration for connection. Maybe config path, parsed as dict and paramiko parsed.
        :type ssh_config:
            typing.Union[
                str,
                paramiko.SSHConfig,
                typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]],
                HostsSSHConfigs,
                None
            ]
        :param ssh_auth_map: SSH authentication information mapped to host names. Useful for complex SSH Proxy cases.
        :type ssh_auth_map: typing.Optional[typing.Union[typing.Dict[str, ssh_auth.SSHAuth], ssh_auth.SSHAuthMapping]]
        :param keepalive: keepalive period
        :type keepalive: typing.Union[int, bool]
        :return: new ssh client instance using current as a proxy
        :rtype: SSHClientBase

        .. note:: auth has priority over username/password

        .. versionadded:: 6.0.0
        """
        if isinstance(ssh_config, _ssh_helpers.HostsSSHConfigs):
            parsed_ssh_config: _ssh_helpers.HostsSSHConfigs = ssh_config
        else:
            parsed_ssh_config = _ssh_helpers.parse_ssh_config(ssh_config, host)

        hostname = parsed_ssh_config[host].hostname

        sock: paramiko.Channel = self._get_proxy_channel(port=port, ssh_config=parsed_ssh_config[hostname])
        cls: typing.Type[SSHClientBase] = self.__class__
        return cls(
            host=host,
            port=port,
            username=username,
            password=password,
            auth=auth,
            verbose=verbose,
            ssh_config=ssh_config,
            sock=sock,
            ssh_auth_map=ssh_auth_map if ssh_auth_map is not None else self.__auth_mapping,
            keepalive=int(keepalive),
        )

    def execute_through_host(
        self,
        hostname: str,
        command: CommandT,
        *,
        auth: _OptSSHAuthT = None,
        port: typing.Optional[int] = None,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        log_mask_re: LogMaskReT = None,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
    ) -> exec_result.ExecResult:
        """Execute command on remote host through currently connected host.

        :param hostname: target hostname
        :type hostname: str
        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param auth: credentials for target machine
        :type auth: typing.Optional[ssh_auth.SSHAuth]
        :param port: target port
        :type port: typing.Optional[int]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param get_pty: open PTY on target machine
        :type get_pty: bool
        :param width: PTY width
        :type width: int
        :param height: PTY height
        :type height: int
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 3.2.0 Expose pty options as optional keyword-only arguments
        .. versionchanged:: 4.0.0 Expose stdin and log_mask_re as optional keyword-only arguments
        .. versionchanged:: 6.0.0 Move channel open to separate method and make proper ssh-proxy usage
        .. versionchanged:: 6.0.0 only hostname and command are positional argument, target_port changed to port.
        .. versionchanged:: 7.0.0 target_port argument removed
        """
        conn: SSHClientBase
        if auth is None:
            auth = self.auth

        with self.proxy_to(
            host=hostname,
            port=port,
            auth=auth,
            verbose=verbose,
            ssh_config=self.ssh_config,
            keepalive=False,
        ) as conn:
            return conn(
                command,
                timeout=timeout,
                stdin=stdin,
                open_stdout=open_stdout,
                open_stderr=open_stderr,
                log_mask_re=log_mask_re,
                get_pty=get_pty,
                width=width,
                height=height,
            )

    @classmethod
    def execute_together(
        cls,
        remotes: typing.Iterable[SSHClientBase],
        command: CommandT,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        expected: ExpectedExitCodesT = (proc_enums.EXPECTED,),
        raise_on_err: bool = True,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        verbose: bool = False,
        log_mask_re: LogMaskReT = None,
        exception_class: typing.Type[exceptions.ParallelCallProcessError] = exceptions.ParallelCallProcessError,
        **kwargs: typing.Any,
    ) -> typing.Dict[typing.Tuple[str, int], exec_result.ExecResult]:
        """Execute command on multiple remotes in async mode.

        :param remotes: Connections to execute on
        :type remotes: typing.Iterable[SSHClientBase]
        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param verbose: produce verbose log record on command call
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param exception_class: Exception to raise on error. Mandatory subclass of exceptions.ParallelCallProcessError
        :type exception_class: typing.Type[exceptions.ParallelCallProcessError]
        :param kwargs: additional parameters for execute_async call.
        :type kwargs: typing.Any
        :return: dictionary {(hostname, port): result}
        :rtype: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult]
        :raises ParallelCallProcessError: Unexpected any code at lest on one target
        :raises ParallelCallExceptions: At lest one exception raised during execution (including timeout)

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        .. versionchanged:: 4.0.0 Expose stdin and log_mask_re as optional keyword-only arguments
        """

        @threaded.threadpooled
        def get_result(remote: SSHClientBase) -> exec_result.ExecResult:
            """Get result from remote call.

            :param remote: SSH connection instance
            :return: execution result
            """
            # pylint: disable=protected-access
            cmd_for_log: str = remote._mask_command(cmd=cmd, log_mask_re=log_mask_re)
            remote._log_command_execute(
                command=cmd,
                log_mask_re=log_mask_re,
                log_level=log_level,
                **kwargs,
            )

            async_result: SshExecuteAsyncResult = remote._execute_async(
                cmd,
                stdin=stdin,
                log_mask_re=log_mask_re,
                open_stdout=open_stdout,
                open_stderr=open_stderr,
                **kwargs,
            )
            # pylint: enable=protected-access

            async_result.interface.status_event.wait(timeout)
            exit_code = async_result.interface.recv_exit_status()

            res = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)
            res.read_stdout(src=async_result.stdout)
            res.read_stderr(src=async_result.stderr)
            res.exit_code = exit_code

            async_result.interface.close()
            return res

        prep_expected: typing.Sequence[ExitCodeT] = proc_enums.exit_codes_to_enums(expected)
        log_level: int = logging.INFO if verbose else logging.DEBUG
        cmd = cls._cmd_to_string(command)

        futures: typing.Dict[SSHClientBase, concurrent.futures.Future[exec_result.ExecResult]] = {
            remote: get_result(remote) for remote in set(remotes)
        }  # Use distinct remotes
        results: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult] = {}
        errors: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult] = {}
        raised_exceptions: typing.Dict[typing.Tuple[str, int], Exception] = {}

        _, not_done = concurrent.futures.wait(list(futures.values()), timeout=timeout)

        for fut in not_done:  # pragma: no cover
            fut.cancel()

        for remote, future in futures.items():
            try:
                result = future.result()
                results[(remote.hostname, remote.port)] = result
                if result.exit_code not in prep_expected:
                    errors[(remote.hostname, remote.port)] = result
            except Exception as e:
                raised_exceptions[(remote.hostname, remote.port)] = e

        if raised_exceptions:  # always raise
            raise exceptions.ParallelCallExceptions(
                command=cmd,
                exceptions=raised_exceptions,
                errors=errors,
                results=results,
                expected=prep_expected,
            )
        if errors and raise_on_err:
            raise exception_class(cmd, errors, results, expected=prep_expected)
        return results

    def open(self, path: SupportPathT, mode: str = "r") -> paramiko.SFTPFile:
        """Open file on remote using SFTP session.

        :param path: filesystem object path
        :type path: typing.Union[str, pathlib.PurePath]
        :param mode: open file mode ('t' is not supported)
        :type mode: str
        :return: file.open() stream
        :rtype: paramiko.SFTPFile
        """
        return self._sftp.open(pathlib.PurePath(path).as_posix(), mode)  # pragma: no cover

    def exists(self, path: SupportPathT) -> bool:
        """Check for file existence using SFTP session.

        :param path: filesystem object path
        :type path: typing.Union[str, pathlib.PurePath]
        :return: path is valid (object exists)
        :rtype: bool
        """
        try:
            self._sftp.lstat(pathlib.PurePath(path).as_posix())
            return True
        except IOError:
            return False

    def stat(self, path: SupportPathT) -> paramiko.sftp_attr.SFTPAttributes:
        """Get stat info for path with following symlinks.

        :param path: filesystem object path
        :type path: typing.Union[str, pathlib.PurePath]
        :return: stat like information for remote path
        :rtype: paramiko.sftp_attr.SFTPAttributes
        """
        return self._sftp.stat(pathlib.PurePath(path).as_posix())  # pragma: no cover

    def utime(self, path: SupportPathT, times: typing.Optional[typing.Tuple[int, int]] = None) -> None:
        """Set atime, mtime.

        :param path: filesystem object path
        :type path: typing.Union[str, pathlib.PurePath]
        :param times: (atime, mtime)
        :type times: typing.Optional[typing.Tuple[int, int]]

        .. versionadded:: 1.0.0
        """
        self._sftp.utime(pathlib.PurePath(path).as_posix(), times)  # pragma: no cover

    def isfile(self, path: SupportPathT) -> bool:
        """Check, that path is file using SFTP session.

        :param path: remote path to validate
        :type path: typing.Union[str, pathlib.PurePath]
        :return: path is file
        :rtype: bool
        """
        try:
            attrs: paramiko.sftp_attr.SFTPAttributes = self._sftp.lstat(pathlib.PurePath(path).as_posix())
            return stat.S_ISREG(attrs.st_mode)  # type: ignore  # in case of None we will handle except
        except (TypeError, IOError):
            return False

    def isdir(self, path: SupportPathT) -> bool:
        """Check, that path is directory using SFTP session.

        :param path: remote path to validate
        :type path: typing.Union[str, pathlib.PurePath]
        :return: path is directory
        :rtype: bool
        """
        try:
            attrs: paramiko.sftp_attr.SFTPAttributes = self._sftp.lstat(pathlib.PurePath(path).as_posix())
            return stat.S_ISDIR(attrs.st_mode)  # type: ignore  # in case of None we will handle except
        except (TypeError, IOError):
            return False

    def islink(self, path: SupportPathT) -> bool:
        """Check, that path is symlink using SFTP session.

        :param path: remote path to validate
        :type path: typing.Union[str, pathlib.PurePath]
        :return: path is symlink
        :rtype: bool
        """
        try:
            attrs: paramiko.sftp_attr.SFTPAttributes = self._sftp.lstat(pathlib.PurePath(path).as_posix())
            return stat.S_ISLNK(attrs.st_mode)  # type: ignore  # in case of None we will handle except
        except (TypeError, IOError):
            return False

    def symlink(self, source: SupportPathT, dest: SupportPathT) -> None:
        """Produce symbolic link like `os.symlink`.

        :param source: source path
        :type source: typing.Union[str, pathlib.PurePath]
        :param dest: source path
        :type dest: typing.Union[str, pathlib.PurePath]
        """
        self._sftp.symlink(pathlib.PurePath(source).as_posix(), pathlib.PurePath(dest).as_posix())  # pragma: no cover

    def chmod(self, path: SupportPathT, mode: int) -> None:
        """Change the mode (permissions) of a file like `os.chmod`.

        :param path: filesystem object path
        :type path: typing.Union[str, pathlib.PurePath]
        :param mode: new permissions
        :type mode: int
        """
        self._sftp.chmod(pathlib.PurePath(path).as_posix(), mode)  # pragma: no cover
