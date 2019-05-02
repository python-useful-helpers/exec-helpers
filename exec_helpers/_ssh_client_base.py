#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.

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

__all__ = ("SSHClientBase", "SshExecuteAsyncResult")

# Standard Library
import abc
import base64
import collections
import concurrent.futures
import copy
import datetime
import logging
import platform
import stat
import sys
import time
import typing
import warnings

# External Dependencies
import advanced_descriptors
import paramiko  # type: ignore
import tenacity  # type: ignore
import threaded

# Exec-Helpers Implementation
from exec_helpers import _log_templates
from exec_helpers import api
from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import exec_result
from exec_helpers import proc_enums
from exec_helpers import ssh_auth

logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("iso8601").setLevel(logging.WARNING)


class RetryOnExceptions(tenacity.retry_if_exception):  # type: ignore
    """Advanced retry on exceptions."""

    def __init__(
        self,
        retry_on: "typing.Union[typing.Type[BaseException], typing.Tuple[typing.Type[BaseException], ...]]",
        reraise: "typing.Union[typing.Type[BaseException], typing.Tuple[typing.Type[BaseException], ...]]",
    ) -> None:
        """Retry on exceptions, except several types.

        :param retry_on: Exceptions to retry on
        :param reraise: Exceptions, which should be reraised, even if subclasses retry_on
        """
        super(RetryOnExceptions, self).__init__(lambda e: isinstance(e, retry_on) and not isinstance(e, reraise))


# noinspection PyTypeHints
class SshExecuteAsyncResult(api.ExecuteAsyncResult):
    """Override original NamedTuple with proper typing."""

    @property
    def interface(self) -> paramiko.Channel:
        """Override original NamedTuple with proper typing."""
        return super(SshExecuteAsyncResult, self).interface

    @property
    def stdin(self) -> paramiko.ChannelFile:  # type: ignore
        """Override original NamedTuple with proper typing."""
        return super(SshExecuteAsyncResult, self).stdin

    @property
    def stderr(self) -> typing.Optional[paramiko.ChannelFile]:  # type: ignore
        """Override original NamedTuple with proper typing."""
        return super(SshExecuteAsyncResult, self).stderr

    @property
    def stdout(self) -> typing.Optional[paramiko.ChannelFile]:  # type: ignore
        """Override original NamedTuple with proper typing."""
        return super(SshExecuteAsyncResult, self).stdout


CPYTHON = "CPython" == platform.python_implementation()


class _MemorizedSSH(abc.ABCMeta):
    """Memorize metaclass for SSHClient.

    This class implements caching and managing of SSHClient connections.
    Class is not in public scope: all required interfaces is accessible throw
      SSHClient classmethods.

    Main flow is:
      SSHClient() -> check for cached connection and
        - If exists the same: check for alive, reconnect if required and return
        - If exists with different credentials: delete and continue processing
          create new connection and cache on success
      * Note: each invocation of SSHClient instance will return current dir to
        the root of the current user home dir ("cd ~").
        It is necessary to avoid unpredictable behavior when the same
        connection is used from different places.
        If you need to enter some directory and execute command there, please
        use the following approach:
        cmd1 = "cd <some dir> && <command1>"
        cmd2 = "cd <some dir> && <command2>"

    Close cached connections is allowed per-client and all stored:
      connection will be closed, but still stored in cache for faster reconnect

    Clear cache is strictly not recommended:
      from this moment all open connections should be managed manually,
      duplicates is possible.
    """

    __cache = {}  # type: typing.Dict[typing.Tuple[str, int], SSHClientBase]

    @classmethod
    def __prepare__(  # type: ignore  # pylint: disable=unused-argument
        mcs: typing.Type["_MemorizedSSH"], name: str, bases: typing.Iterable[type], **kwargs: typing.Any
    ) -> "collections.OrderedDict[str, typing.Any]":
        """Metaclass magic for object storage.

        .. versionadded:: 1.2.0
        """
        return collections.OrderedDict()

    def __call__(  # type: ignore
        cls: "_MemorizedSSH",
        host: str,
        port: int = 22,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        private_keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = None,
        auth: typing.Optional[ssh_auth.SSHAuth] = None,
        verbose: bool = True,
    ) -> "SSHClientBase":
        """Main memorize method: check for cached instance and return it. API follows target __init__.

        :param host: remote hostname
        :type host: str
        :param port: remote ssh port
        :type port: int
        :param username: remote username.
        :type username: typing.Optional[str]
        :param password: remote password
        :type password: typing.Optional[str]
        :param private_keys: private keys for connection
        :type private_keys: typing.Optional[typing.Iterable[paramiko.RSAKey]]
        :param auth: credentials for connection
        :type auth: typing.Optional[ssh_auth.SSHAuth]
        :param verbose: show additional error/warning messages
        :type verbose: bool
        :return: SSH client instance
        :rtype: SSHClientBase
        """
        if (host, port) in cls.__cache:
            key = host, port
            if auth is None:
                auth = ssh_auth.SSHAuth(username=username, password=password, keys=private_keys)
            if hash((cls, host, port, auth)) == hash(cls.__cache[key]):
                ssh = cls.__cache[key]
                # noinspection PyBroadException
                try:
                    ssh.execute("cd ~", timeout=5)
                except BaseException:  # Note: Do not change to lower level!
                    ssh.logger.debug("Reconnect")
                    ssh.reconnect()
                return ssh
            if CPYTHON and sys.getrefcount(cls.__cache[key]) == 2:  # pragma: no cover
                # If we have only cache reference and temporary getrefcount
                # reference: close connection before deletion
                cls.__cache[key].logger.debug("Closing as unused")
                cls.__cache[key].close()  # type: ignore
            del cls.__cache[key]
        # noinspection PyArgumentList
        ssh = super(_MemorizedSSH, cls).__call__(
            host=host,
            port=port,
            username=username,
            password=password,
            private_keys=private_keys,
            auth=auth,
            verbose=verbose,
        )
        cls.__cache[(ssh.hostname, ssh.port)] = ssh
        return ssh

    @classmethod
    def clear_cache(mcs: typing.Type["_MemorizedSSH"]) -> None:
        """Clear cached connections for initialize new instance on next call.

        getrefcount is used to check for usage, so connections closed on CPYTHON only.
        """
        n_count = 3
        # PY3: cache, ssh, temporary
        for ssh in mcs.__cache.values():
            if CPYTHON and sys.getrefcount(ssh) == n_count:  # pragma: no cover
                ssh.logger.debug("Closing as unused")
                ssh.close()  # type: ignore
        mcs.__cache = {}

    @classmethod
    def close_connections(mcs: typing.Type["_MemorizedSSH"]) -> None:
        """Close connections for selected or all cached records."""
        for ssh in mcs.__cache.values():
            if ssh.is_alive:
                ssh.close()  # type: ignore


class _SudoContext:
    """Context manager for call commands with sudo."""

    __slots__ = ("__ssh", "__sudo_status", "__enforce")

    def __init__(self, ssh: "SSHClientBase", enforce: typing.Optional[bool] = None) -> None:
        """Context manager for call commands with sudo.

        :param ssh: connection instance
        :type ssh: SSHClientBase
        :param enforce: sudo mode for context manager
        :type enforce: typing.Optional[bool]
        """
        self.__ssh = ssh  # type: SSHClientBase
        self.__sudo_status = ssh.sudo_mode  # type: bool
        self.__enforce = enforce  # type: typing.Optional[bool]

    def __enter__(self) -> None:
        self.__sudo_status = self.__ssh.sudo_mode
        if self.__enforce is not None:
            self.__ssh.sudo_mode = self.__enforce

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        self.__ssh.sudo_mode = self.__sudo_status


class _KeepAliveContext:
    """Context manager for keepalive management."""

    __slots__ = ("__ssh", "__keepalive_status", "__enforce")

    def __init__(self, ssh: "SSHClientBase", enforce: bool = True) -> None:
        """Context manager for keepalive management.

        :param ssh: connection instance
        :type ssh: SSHClientBase
        :param enforce: keepalive mode for context manager
        :type enforce: bool
        :param enforce: Keep connection alive after context manager exit
        """
        self.__ssh = ssh  # type: SSHClientBase
        self.__keepalive_status = ssh.keepalive_mode  # type: bool
        self.__enforce = enforce  # type: typing.Optional[bool]

    def __enter__(self) -> None:
        self.__ssh.__enter__()
        self.__keepalive_status = self.__ssh.keepalive_mode
        if self.__enforce is not None:
            self.__ssh.keepalive_mode = self.__enforce

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        # Exit before releasing!
        self.__ssh.__exit__(exc_type=exc_type, exc_val=exc_val, exc_tb=exc_tb)  # type: ignore
        self.__ssh.keepalive_mode = self.__keepalive_status


class SSHClientBase(api.ExecHelper, metaclass=_MemorizedSSH):
    """SSH Client helper."""

    __slots__ = ("__hostname", "__port", "__auth", "__ssh", "__sftp", "__sudo_mode", "__keepalive_mode", "__verbose")

    def __hash__(self) -> int:
        """Hash for usage as dict keys."""
        return hash((self.__class__, self.hostname, self.port, self.auth))

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        private_keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = None,
        auth: typing.Optional[ssh_auth.SSHAuth] = None,
        verbose: bool = True,
    ) -> None:
        """Main SSH Client helper.

        :param host: remote hostname
        :type host: str
        :param port: remote ssh port
        :type port: int
        :param username: remote username.
        :type username: typing.Optional[str]
        :param password: remote password
        :type password: typing.Optional[str]
        :param private_keys: private keys for connection
        :type private_keys: typing.Optional[typing.Iterable[paramiko.RSAKey]]
        :param auth: credentials for connection
        :type auth: typing.Optional[ssh_auth.SSHAuth]
        :param verbose: show additional error/warning messages
        :type verbose: bool

        .. note:: auth has priority over username/password/private_keys
        """
        super(SSHClientBase, self).__init__(
            logger=logging.getLogger(self.__class__.__name__).getChild("({host}:{port})".format(host=host, port=port))
        )

        self.__hostname = host
        self.__port = port

        self.__sudo_mode = False
        self.__keepalive_mode = True
        self.__verbose = verbose

        self.__ssh = paramiko.SSHClient()
        self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.__sftp = None

        if auth is None:
            self.__auth = ssh_auth.SSHAuth(username=username, password=password, keys=private_keys)
        else:
            self.__auth = copy.copy(auth)

        self.__connect()

    @property
    def auth(self) -> ssh_auth.SSHAuth:
        """Internal authorisation object.

        Attention: this public property is mainly for inheritance,
        debug and information purposes.
        Calls outside SSHClient and child classes is sign of incorrect design.
        Change is completely disallowed.

        :rtype: ssh_auth.SSHAuth
        """
        return self.__auth

    @property
    def hostname(self) -> str:
        """Connected remote host name.

        :rtype: str
        """
        return self.__hostname

    @property
    def port(self) -> int:
        """Connected remote port number.

        :rtype: int
        """
        return self.__port

    @property
    def is_alive(self) -> bool:
        """Paramiko status: ready to use|reconnect required.

        :rtype: bool
        """
        return self.__ssh.get_transport() is not None

    def __repr__(self) -> str:
        """Representation for debug purposes."""
        return "{cls}(host={self.hostname}, port={self.port}, auth={self.auth!r})".format(
            cls=self.__class__.__name__, self=self
        )

    def __str__(self) -> str:  # pragma: no cover
        """Representation for debug purposes."""
        return "{cls}(host={self.hostname}, port={self.port}) for user {username}".format(
            cls=self.__class__.__name__, self=self, username=self.auth.username
        )

    @property
    def _ssh(self) -> paramiko.SSHClient:
        """Ssh client object getter for inheritance support only.

        Attention: ssh client object creation and change
        is allowed only by __init__ and reconnect call.

        :rtype: paramiko.SSHClient
        """
        return self.__ssh

    @tenacity.retry(  # type: ignore
        retry=RetryOnExceptions(retry_on=paramiko.SSHException, reraise=paramiko.AuthenticationException),
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
    )
    def __connect(self) -> None:
        """Main method for connection open."""
        with self.lock:
            self.auth.connect(client=self.__ssh, hostname=self.hostname, port=self.port, log=self.__verbose)

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

    @advanced_descriptors.SeparateClassMethod
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

    # noinspection PyMethodParameters
    @close.class_method  # type: ignore
    def close(cls: typing.Type["SSHClientBase"]) -> None:  # pylint: disable=no-self-argument
        """Close all memorized SSH and SFTP sessions."""
        # noinspection PyUnresolvedReferences
        cls.__class__.close_connections()

    @classmethod
    def _clear_cache(cls: typing.Type["SSHClientBase"]) -> None:
        """Enforce clear memorized records."""
        warnings.warn("_clear_cache() is dangerous and not recommended for normal use!", Warning)
        _MemorizedSSH.clear_cache()

    def __del__(self) -> None:
        """Destructor helper: close channel and threads BEFORE closing others.

        Due to threading in paramiko, default destructor could generate asserts on close,
        so we calling channel close before closing main ssh object.
        """
        try:
            self.__ssh.close()
        except BaseException as e:  # pragma: no cover
            self.logger.debug("Exception in {self!s} destructor call: {exc}".format(self=self, exc=e))
        self.__sftp = None

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        """Exit context manager.

        .. versionchanged:: 1.0.0 disconnect enforced on close
        .. versionchanged:: 1.1.0 release lock on exit
        .. versionchanged:: 1.2.1 disconnect enforced on close only not in keepalive mode
        """
        if not self.__keepalive_mode:
            self.close()  # type: ignore
        super(SSHClientBase, self).__exit__(exc_type, exc_val, exc_tb)

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
    def keepalive_mode(self) -> bool:
        """Persistent keepalive mode for connection object.

        :rtype: bool
        """
        return self.__keepalive_mode

    @keepalive_mode.setter
    def keepalive_mode(self, mode: bool) -> None:
        """Persistent keepalive mode change for connection object.

        :param mode: keepalive mode enable/disable
        :type mode: bool
        """
        self.__keepalive_mode = bool(mode)

    def reconnect(self) -> None:
        """Reconnect SSH session."""
        with self.lock:
            self.close()  # type: ignore

            self.__ssh = paramiko.SSHClient()
            self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.__connect()

    def sudo(self, enforce: typing.Optional[bool] = None) -> "typing.ContextManager[None]":
        """Call contextmanager for sudo mode change.

        :param enforce: Enforce sudo enabled or disabled. By default: None
        :type enforce: typing.Optional[bool]
        :return: context manager with selected sudo state inside
        :rtype: typing.ContextManager
        """
        return _SudoContext(ssh=self, enforce=enforce)

    def keepalive(self, enforce: bool = True) -> "typing.ContextManager[None]":
        """Call contextmanager with keepalive mode change.

        :param enforce: Enforce keepalive enabled or disabled.
        :type enforce: bool
        :return: context manager with selected keepalive state inside
        :rtype: typing.ContextManager

        .. Note:: Enter and exit ssh context manager is produced as well.
        .. versionadded:: 1.2.1
        """
        return _KeepAliveContext(ssh=self, enforce=enforce)

    # noinspection PyMethodOverriding
    def execute_async(  # pylint: disable=arguments-differ
        self,
        command: str,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        *,
        chroot_path: typing.Optional[str] = None,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24,
        **kwargs: typing.Any
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
        :param verbose: produce verbose log record on command call
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
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
        .. versionchanged:: 2.9.3 Expose pty options as optional keyword-only arguments
        .. versionchanged:: 2.12.0 support chroot
        """
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        self.logger.log(
            level=logging.INFO if verbose else logging.DEBUG, msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        chan = self._ssh.get_transport().open_session()

        if get_pty:
            # Open PTY
            chan.get_pty(term="vt100", width=width, height=height, width_pixels=0, height_pixels=0)

        _stdin = chan.makefile("wb")  # type: paramiko.ChannelFile
        stdout = chan.makefile("rb")  # type: paramiko.ChannelFile
        stderr = chan.makefile_stderr("rb") if open_stderr else None

        cmd = "{cmd}\n".format(cmd=self._prepare_command(cmd=command, chroot_path=chroot_path))
        started = datetime.datetime.utcnow()
        if self.sudo_mode:
            encoded_cmd = base64.b64encode(cmd.encode("utf-8")).decode("utf-8")
            cmd = 'sudo -S bash -c \'eval "$(base64 -d <(echo "{0}"))"\''.format(encoded_cmd)
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side
            if stdout.channel.closed is False:
                # noinspection PyTypeChecker
                self.auth.enter_password(_stdin)
                _stdin.flush()
        else:
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side

        if stdin is not None:
            if not _stdin.channel.closed:
                stdin_str = self._string_bytes_bytearray_as_bytes(stdin)

                _stdin.write(stdin_str)
                _stdin.flush()
            else:
                self.logger.warning("STDIN Send failed: closed channel")

        if open_stdout:
            res_stdout = stdout
        else:
            stdout.close()
            res_stdout = None

        return SshExecuteAsyncResult(interface=chan, stdin=_stdin, stderr=stderr, stdout=res_stdout, started=started)

    def _exec_command(  # type: ignore
        self,
        command: str,
        async_result: SshExecuteAsyncResult,
        timeout: typing.Union[int, float, None],
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        *,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        **kwargs: typing.Any
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
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        # Store command with hidden data
        result = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)

        # noinspection PyNoneFunctionAssignment
        future = poll_pipes()  # type: "concurrent.futures.Future[None]"
        # pylint: enable=assignment-from-no-return

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

        wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(result=result, timeout=timeout)  # type: ignore

    def execute_through_host(
        self,
        hostname: str,
        command: str,
        auth: typing.Optional[ssh_auth.SSHAuth] = None,
        target_port: int = 22,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        *,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        log_mask_re: typing.Optional[str] = None,
        get_pty: bool = False,
        width: int = 80,
        height: int = 24
    ) -> exec_result.ExecResult:
        """Execute command on remote host through currently connected host.

        :param hostname: target hostname
        :type hostname: str
        :param command: Command for execution
        :type command: str
        :param auth: credentials for target machine
        :type auth: typing.Optional[ssh_auth.SSHAuth]
        :param target_port: target port
        :type target_port: int
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
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
        .. versionchanged:: 2.9.3 Expose pty options as optional keyword-only arguments
        .. versionchanged:: 2.11.0 Expose stdin and log_mask_re as optional keyword-only arguments
        """
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)
        self.logger.log(
            level=logging.INFO if verbose else logging.DEBUG, msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        if auth is None:
            auth = self.auth

        intermediate_channel = self._ssh.get_transport().open_channel(
            kind="direct-tcpip", dest_addr=(hostname, target_port), src_addr=(self.hostname, 0)
        )
        transport = paramiko.Transport(sock=intermediate_channel)

        # start client and authenticate transport
        auth.connect(transport)

        # open ssh session
        channel = transport.open_session()
        if get_pty:
            # Open PTY
            channel.get_pty(term="vt100", width=width, height=height, width_pixels=0, height_pixels=0)

        # Make proxy objects for read
        _stdin = channel.makefile("wb")  # type: paramiko.ChannelFile
        stdout = channel.makefile("rb")  # type: paramiko.ChannelFile
        stderr = channel.makefile_stderr("rb")  # type: paramiko.ChannelFile

        started = datetime.datetime.utcnow()

        channel.exec_command(command)  # nosec  # Sanitize on caller side

        if stdin is not None:
            if not _stdin.channel.closed:
                stdin_str = self._string_bytes_bytearray_as_bytes(stdin)

                _stdin.write(stdin_str)
                _stdin.flush()
            else:
                self.logger.warning("STDIN Send failed: closed channel")

        async_result = SshExecuteAsyncResult(
            interface=channel, stdin=_stdin, stdout=stdout, stderr=stderr, started=started
        )

        # noinspection PyDictCreation
        result = self._exec_command(
            command, async_result=async_result, timeout=timeout, verbose=verbose, log_mask_re=log_mask_re, stdin=stdin
        )

        intermediate_channel.close()

        return result

    @classmethod
    def execute_together(
        cls,
        remotes: typing.Iterable["SSHClientBase"],
        command: str,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]] = (proc_enums.EXPECTED,),
        raise_on_err: bool = True,
        *,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        log_mask_re: typing.Optional[str] = None,
        exception_class: "typing.Type[exceptions.ParallelCallProcessError]" = exceptions.ParallelCallProcessError,
        **kwargs: typing.Any
    ) -> typing.Dict[typing.Tuple[str, int], exec_result.ExecResult]:
        """Execute command on multiple remotes in async mode.

        :param remotes: Connections to execute on
        :type remotes: typing.Iterable[SSHClientBase]
        :param command: Command for execution
        :type command: str
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
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
        .. versionchanged:: 2.9.3 Exception class can be substituted
        .. versionchanged:: 2.10.0 Expected is not optional, defaults os dependent
        .. versionchanged:: 2.11.0 Expose stdin and log_mask_re as optional keyword-only arguments
        """

        @threaded.threadpooled
        def get_result(remote: "SSHClientBase") -> exec_result.ExecResult:
            """Get result from remote call.

            :param remote: SSH connection instance
            :returns: execution result
            """
            async_result = remote.execute_async(command, stdin=stdin, log_mask_re=log_mask_re, **kwargs)

            async_result.interface.status_event.wait(timeout)
            exit_code = async_result.interface.recv_exit_status()

            # pylint: disable=protected-access
            cmd_for_log = remote._mask_command(cmd=command, log_mask_re=kwargs.get("log_mask_re", None))
            # pylint: enable=protected-access

            res = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)
            res.read_stdout(src=async_result.stdout)
            res.read_stderr(src=async_result.stderr)
            res.exit_code = exit_code

            async_result.interface.close()
            return res

        expected = proc_enums.exit_codes_to_enums(expected)

        futures = {remote: get_result(remote) for remote in set(remotes)}  # Use distinct remotes
        results = {}
        errors = {}
        raised_exceptions = {}

        _, not_done = concurrent.futures.wait(list(futures.values()), timeout=timeout)

        for fut in not_done:  # pragma: no cover
            fut.cancel()

        for (remote, future) in futures.items():
            try:
                result = future.result()
                results[(remote.hostname, remote.port)] = result
                if result.exit_code not in expected:
                    errors[(remote.hostname, remote.port)] = result
            except Exception as e:
                raised_exceptions[(remote.hostname, remote.port)] = e

        if raised_exceptions:  # always raise
            raise exceptions.ParallelCallExceptions(command, raised_exceptions, errors, results, expected=expected)
        if errors and raise_on_err:
            raise exception_class(command, errors, results, expected=expected)
        return results

    def open(self, path: str, mode: str = "r") -> paramiko.SFTPFile:
        """Open file on remote using SFTP session.

        :param path: filesystem object path
        :type path: str
        :param mode: open file mode ('t' is not supported)
        :type mode: str
        :return: file.open() stream
        :rtype: paramiko.SFTPFile
        """
        return self._sftp.open(path, mode)  # pragma: no cover

    def exists(self, path: str) -> bool:
        """Check for file existence using SFTP session.

        :param path: filesystem object path
        :type path: str
        :return: path is valid (object exists)
        :rtype: bool
        """
        try:
            self._sftp.lstat(path)
            return True
        except IOError:
            return False

    def stat(self, path: str) -> paramiko.sftp_attr.SFTPAttributes:
        """Get stat info for path with following symlinks.

        :param path: filesystem object path
        :type path: str
        :return: stat like information for remote path
        :rtype: paramiko.sftp_attr.SFTPAttributes
        """
        return self._sftp.stat(path)  # pragma: no cover

    def utime(self, path: str, times: typing.Optional[typing.Tuple[int, int]] = None) -> None:
        """Set atime, mtime.

        :param path: filesystem object path
        :type path: str
        :param times: (atime, mtime)
        :type times: typing.Optional[typing.Tuple[int, int]]

        .. versionadded:: 1.0.0
        """
        self._sftp.utime(path, times)  # pragma: no cover

    def isfile(self, path: str) -> bool:
        """Check, that path is file using SFTP session.

        :param path: remote path to validate
        :type path: str
        :return: path is file
        :rtype: bool
        """
        try:
            attrs = self._sftp.lstat(path)
            return stat.S_ISREG(attrs.st_mode)
        except IOError:
            return False

    def isdir(self, path: str) -> bool:
        """Check, that path is directory using SFTP session.

        :param path: remote path to validate
        :type path: str
        :return: path is directory
        :rtype: bool
        """
        try:
            attrs = self._sftp.lstat(path)
            return stat.S_ISDIR(attrs.st_mode)
        except IOError:
            return False

    def islink(self, path: str) -> bool:
        """Check, that path is symlink using SFTP session.

        :param path: remote path to validate
        :type path: str
        :return: path is symlink
        :rtype: bool
        """
        try:
            attrs = self._sftp.lstat(path)
            return stat.S_ISLNK(attrs.st_mode)
        except IOError:
            return False

    def symlink(self, source: str, dest: str) -> None:
        """Produce symbolic link like `os.symlink`.

        :param source: source path
        :type source: str
        :param dest: source path
        :type dest: str
        """
        self._sftp.symlink(source, dest)  # pragma: no cover

    def chmod(self, path: str, mode: int) -> None:
        """Change the mode (permissions) of a file like `os.chmod`.

        :param path: filesystem object path
        :type path: str
        :param mode: new permissions
        :type mode: int
        """
        self._sftp.chmod(path, mode)  # pragma: no cover
