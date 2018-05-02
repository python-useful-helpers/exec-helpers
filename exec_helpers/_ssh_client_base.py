#    Copyright 2018 Alexey Stepanov aka penguinolog.

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

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import base64
import collections
# noinspection PyCompatibility
import concurrent.futures
import copy
import logging
import platform
import stat
import sys
import threading
import time
import typing
import warnings

import advanced_descriptors
import paramiko
import tenacity
import threaded
import six

from exec_helpers import _api
from exec_helpers import constants
from exec_helpers import exec_result
from exec_helpers import exceptions
from exec_helpers import proc_enums
from exec_helpers import ssh_auth
from exec_helpers import _log_templates

__all__ = ('SSHClientBase', )

logger = logging.getLogger(__name__)
logging.getLogger('paramiko').setLevel(logging.WARNING)
logging.getLogger('iso8601').setLevel(logging.WARNING)

_type_ConnectSSH = typing.Union[
    paramiko.client.SSHClient, paramiko.transport.Transport
]
_type_RSAKeys = typing.Iterable[paramiko.RSAKey]
_type_exit_codes = typing.Union[int, proc_enums.ExitCodes]
_type_multiple_results = typing.Dict[
    typing.Tuple[str, int], exec_result.ExecResult
]
_type_execute_async = typing.Tuple[
    paramiko.Channel,
    paramiko.ChannelFile,
    typing.Optional[paramiko.ChannelFile],
    typing.Optional[paramiko.ChannelFile]
]

CPYTHON = 'CPython' == platform.python_implementation()


class _MemorizedSSH(type):
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
    def __prepare__(
        mcs,
        name,
        bases,
        **kwargs
    ):  # pylint: disable=unused-argument
        """Metaclass magic for object storage.

        .. versionadded:: 1.2.0
        """
        return collections.OrderedDict()  # pragma: no cover

    def __call__(
        cls,
        host,  # type: str
        port=22,  # type: int
        username=None,  # type: typing.Optional[str]
        password=None,  # type: typing.Optional[str]
        private_keys=None,  # type: typing.Optional[_type_RSAKeys]
        auth=None,  # type: typing.Optional[ssh_auth.SSHAuth]
    ):  # type: (...) -> SSHClientBase
        """Main memorize method: check for cached instance and return it.

        :type host: str
        :type port: int
        :type username: str
        :type password: str
        :type private_keys: list
        :type auth: ssh_auth.SSHAuth
        :rtype: SSHClient
        """
        if (host, port) in cls.__cache:
            key = host, port
            if auth is None:
                auth = ssh_auth.SSHAuth(
                    username=username,
                    password=password,
                    keys=private_keys
                )
            if hash((cls, host, port, auth)) == hash(cls.__cache[key]):
                ssh = cls.__cache[key]
                # noinspection PyBroadException
                try:
                    ssh.execute('cd ~', timeout=5)
                except BaseException:  # Note: Do not change to lower level!
                    logger.debug('Reconnect {}'.format(ssh))
                    ssh.reconnect()
                return ssh
            if (
                CPYTHON and
                sys.getrefcount(cls.__cache[key]) == 2
            ):    # pragma: no cover
                # If we have only cache reference and temporary getrefcount
                # reference: close connection before deletion
                logger.debug('Closing {} as unused'.format(cls.__cache[key]))
                cls.__cache[key].close()
            del cls.__cache[key]
        # noinspection PyArgumentList
        ssh = super(
            _MemorizedSSH,
            cls
        ).__call__(
            host=host, port=port,
            username=username, password=password, private_keys=private_keys,
            auth=auth)
        cls.__cache[(ssh.hostname, ssh.port)] = ssh
        return ssh

    @classmethod
    def clear_cache(mcs):  # type: () -> None
        """Clear cached connections for initialize new instance on next call.

        getrefcount is used to check for usage.
        """
        n_count = 3 if six.PY3 else 4
        # PY3: cache, ssh, temporary
        # PY4: cache, values mapping, ssh, temporary
        for ssh in mcs.__cache.values():
            if (
                CPYTHON and
                sys.getrefcount(ssh) == n_count
            ):  # pragma: no cover
                logger.debug('Closing {} as unused'.format(ssh))
                ssh.close()
        mcs.__cache = {}

    @classmethod
    def close_connections(
        mcs,
        hostname=None  # type: typing.Optional[str]
    ):  # type: (...) -> None
        """Close connections for selected or all cached records.

        :type hostname: str
        """
        if hostname is None:
            keys = [key for key, ssh in mcs.__cache.items() if ssh.is_alive]
        else:
            keys = [
                (host, port)
                for (host, port), ssh
                in mcs.__cache.items() if host == hostname and ssh.is_alive]
        # raise ValueError(keys)
        for key in keys:
            mcs.__cache[key].close()


class SSHClientBase(six.with_metaclass(_MemorizedSSH, _api.ExecHelper)):
    """SSH Client helper."""

    __slots__ = (
        '__hostname', '__port', '__auth', '__ssh', '__sftp', 'sudo_mode',
    )

    class __get_sudo(object):
        """Context manager for call commands with sudo."""

        def __init__(
            self,
            ssh,  # type: SSHClientBase
            enforce=None  # type: typing.Optional[bool]
        ):  # type: (...) -> None
            """Context manager for call commands with sudo.

            :type ssh: SSHClient
            :type enforce: bool
            """
            self.__ssh = ssh
            self.__sudo_status = ssh.sudo_mode
            self.__enforce = enforce

        def __enter__(self):
            self.__sudo_status = self.__ssh.sudo_mode
            if self.__enforce is not None:
                self.__ssh.sudo_mode = self.__enforce

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.__ssh.sudo_mode = self.__sudo_status

    def __hash__(self):
        """Hash for usage as dict keys."""
        return hash((
            self.__class__,
            self.hostname,
            self.port,
            self.auth))

    def __init__(
        self,
        host,  # type: str
        port=22,  # type: int
        username=None,  # type: typing.Optional[str]
        password=None,  # type: typing.Optional[str]
        private_keys=None,  # type: typing.Optional[_type_RSAKeys]
        auth=None,  # type: typing.Optional[ssh_auth.SSHAuth]
    ):  # type: (...) -> None
        """SSHClient helper.

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

        .. note:: auth has priority over username/password/private_keys
        """
        super(SSHClientBase, self).__init__(
            logger=logger.getChild(
                '{host}:{port}'.format(host=host, port=port)
            ),
        )

        self.__hostname = host
        self.__port = port

        self.sudo_mode = False
        self.__ssh = paramiko.SSHClient()
        self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.__sftp = None

        if auth is None:
            self.__auth = ssh_auth.SSHAuth(
                username=username,
                password=password,
                keys=private_keys
            )
        else:
            self.__auth = copy.copy(auth)

        self.__connect()

    @property
    def auth(self):  # type: () -> ssh_auth.SSHAuth
        """Internal authorisation object.

        Attention: this public property is mainly for inheritance,
        debug and information purposes.
        Calls outside SSHClient and child classes is sign of incorrect design.
        Change is completely disallowed.

        :rtype: ssh_auth.SSHAuth
        """
        return self.__auth

    @property
    def hostname(self):  # type: () -> str
        """Connected remote host name.

        :rtype: str
        """
        return self.__hostname

    @property
    def port(self):  # type: () -> int
        """Connected remote port number.

        :rtype: int
        """
        return self.__port

    @property
    def is_alive(self):  # type: () -> bool
        """Paramiko status: ready to use|reconnect required.

        :rtype: bool
        """
        return self.__ssh.get_transport() is not None

    def __repr__(self):
        """Representation for debug purposes."""
        return '{cls}(host={host}, port={port}, auth={auth!r})'.format(
            cls=self.__class__.__name__, host=self.hostname, port=self.port,
            auth=self.auth
        )

    def __str__(self):
        """Representation for debug purposes."""
        return '{cls}(host={host}, port={port}) for user {user}'.format(
            cls=self.__class__.__name__, host=self.hostname, port=self.port,
            user=self.auth.username
        )

    @property
    def _ssh(self):  # type: () -> paramiko.SSHClient
        """ssh client object getter for inheritance support only.

        Attention: ssh client object creation and change
        is allowed only by __init__ and reconnect call.

        :rtype: paramiko.SSHClient
        """
        return self.__ssh

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(paramiko.SSHException),
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_fixed(3),
        reraise=True,
    )
    def __connect(self):
        """Main method for connection open."""
        with self.lock:
            self.auth.connect(
                client=self.__ssh,
                hostname=self.hostname, port=self.port,
                log=True)

    def __connect_sftp(self):
        """SFTP connection opener."""
        with self.lock:
            try:
                self.__sftp = self.__ssh.open_sftp()
            except paramiko.SSHException:
                self.logger.warning(
                    'SFTP enable failed! SSH only is accessible.'
                )

    @property
    def _sftp(self):  # type: () -> paramiko.sftp_client.SFTPClient
        """SFTP channel access for inheritance.

        :rtype: paramiko.sftp_client.SFTPClient
        :raises paramiko.SSHException: SFTP connection failed
        """
        if self.__sftp is not None:
            return self.__sftp
        self.logger.debug('SFTP is not connected, try to connect...')
        self.__connect_sftp()
        if self.__sftp is not None:
            return self.__sftp
        raise paramiko.SSHException('SFTP connection failed')

    @advanced_descriptors.SeparateClassMethod
    def close(self):
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
                        self.logger.exception(
                            "Could not close sftp connection"
                        )

    # noinspection PyMethodParameters
    @close.class_method
    def close(cls):  # pylint: disable=no-self-argument
        """Close all memorized SSH and SFTP sessions."""
        # noinspection PyUnresolvedReferences
        cls.__class__.close_connections()

    @classmethod
    def _clear_cache(cls):
        """Enforce clear memorized records."""
        warnings.warn(
            '_clear_cache() is dangerous and not recommended for normal use!',
            Warning
        )
        _MemorizedSSH.clear_cache()

    def __del__(self):
        """Destructor helper: close channel and threads BEFORE closing others.

        Due to threading in paramiko, default destructor could generate asserts
        on close, so we calling channel close before closing main ssh object.
        """
        try:
            self.__ssh.close()
        except BaseException as e:  # pragma: no cover
            self.logger.debug(
                'Exception in {self!s} destructor call: {exc}'.format(
                    self=self,
                    exc=e
                )
            )
        self.__sftp = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager.

        .. versionchanged:: 1.0.0 disconnect enforced on close
        .. versionchanged:: 1.1.0 release lock on exit
        """
        self.close()
        super(SSHClientBase, self).__exit__(exc_type, exc_val, exc_tb)

    def reconnect(self):  # type: () -> None
        """Reconnect SSH session."""
        with self.lock:
            self.close()

            self.__ssh = paramiko.SSHClient()
            self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.__connect()

    def sudo(
        self,
        enforce=None  # type: typing.Optional[bool]
    ):
        """Call contextmanager for sudo mode change.

        :param enforce: Enforce sudo enabled or disabled. By default: None
        :type enforce: typing.Optional[bool]
        """
        return self.__get_sudo(ssh=self, enforce=enforce)

    def execute_async(
        self,
        command,  # type: str
        stdin=None,  # type: typing.Union[six.text_type, six.binary_type, bytearray, None]
        open_stdout=True,  # type: bool
        open_stderr=True,  # type: bool
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs
    ):  # type: (...) -> _type_execute_async
        """Execute command in async mode and return channel with IO objects.

        :param command: Command for execution
        :type command: str
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[six.text_type, six.binary_type, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param verbose: produce verbose log record on command call
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :rtype: typing.Tuple[
            paramiko.Channel,
            paramiko.ChannelFile,
            typing.Optional[paramiko.ChannelFile],
            typing.Optional[paramiko.ChannelFile],
        ]

        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 stdin data
        .. versionchanged:: 1.2.0 get_pty moved to `**kwargs`
        """
        cmd_for_log = self._mask_command(
            cmd=command,
            log_mask_re=log_mask_re
        )

        self.logger.log(
            level=logging.INFO if verbose else logging.DEBUG,
            msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        chan = self._ssh.get_transport().open_session()

        if kwargs.get('get_pty', False):
            # Open PTY
            chan.get_pty(
                term='vt100',
                width=kwargs.get('width', 80), height=kwargs.get('height', 24),
                width_pixels=0, height_pixels=0
            )

        _stdin = chan.makefile('wb')  # type: paramiko.ChannelFile
        stdout = chan.makefile('rb') if open_stdout else None
        stderr = chan.makefile_stderr('rb') if open_stderr else None

        cmd = "{command}\n".format(command=command)
        if self.sudo_mode:
            encoded_cmd = base64.b64encode(cmd.encode('utf-8')).decode('utf-8')
            cmd = "sudo -S bash -c 'eval \"$(base64 -d <(echo \"{0}\"))\"'".format(encoded_cmd)
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side
            if stdout.channel.closed is False:
                self.auth.enter_password(_stdin)
                _stdin.flush()
        else:
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side

        if stdin is not None:
            if not _stdin.channel.closed:
                _stdin.write('{stdin}\n'.format(stdin=stdin))
                _stdin.flush()
            else:
                self.logger.warning('STDIN Send failed: closed channel')

        return chan, _stdin, stderr, stdout

    def _exec_command(
        self,
        command,  # type: str
        interface,  # type: paramiko.channel.Channel
        stdout,  # type: paramiko.channel.ChannelFile
        stderr,  # type: paramiko.channel.ChannelFile
        timeout,  # type: int
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Get exit status from channel with timeout.

        :type command: str
        :type interface: paramiko.channel.Channel
        :type stdout: paramiko.channel.ChannelFile
        :type stderr: paramiko.channel.ChannelFile
        :type timeout: int
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        def poll_streams(
            result,  # type: exec_result.ExecResult
        ):
            """Poll FIFO buffers if data available."""
            if stdout and interface.recv_ready():
                result.read_stdout(
                    src=stdout,
                    log=self.logger,
                    verbose=verbose
                )
            if stderr and interface.recv_stderr_ready():
                result.read_stderr(
                    src=stderr,
                    log=self.logger,
                    verbose=verbose
                )

        @threaded.threadpooled
        def poll_pipes(
            result,  # type: exec_result.ExecResult
            stop,  # type: threading.Event
        ):
            """Polling task for FIFO buffers.

            :type stdout: paramiko.channel.ChannelFile
            :type stderr: paramiko.channel.ChannelFile
            :type result: ExecResult
            :type stop: Event
            :type channel: paramiko.channel.Channel
            """
            while not stop.is_set():
                time.sleep(0.1)
                if stdout or stderr:
                    poll_streams(result=result)

                if interface.status_event.is_set():
                    result.read_stdout(
                        src=stdout,
                        log=self.logger,
                        verbose=verbose)
                    result.read_stderr(
                        src=stderr,
                        log=self.logger,
                        verbose=verbose
                    )
                    result.exit_code = interface.exit_status

                    stop.set()

        # channel.status_event.wait(timeout)
        cmd_for_log = self._mask_command(
            cmd=command,
            log_mask_re=log_mask_re
        )

        # Store command with hidden data
        result = exec_result.ExecResult(cmd=cmd_for_log)

        stop_event = threading.Event()

        # pylint: disable=assignment-from-no-return
        future = poll_pipes(
            result=result,
            stop=stop_event,
        )  # type: concurrent.futures.Future
        # pylint: enable=assignment-from-no-return

        concurrent.futures.wait([future], timeout)

        # Process closed?
        if stop_event.is_set():
            stop_event.clear()
            interface.close()
            return result

        stop_event.set()
        interface.close()
        future.cancel()

        wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(
            result=result,
            timeout=timeout
        )
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(wait_err_msg)

    def execute_through_host(
        self,
        hostname,  # type: str
        command,  # type: str
        auth=None,  # type: typing.Optional[ssh_auth.SSHAuth]
        target_port=22,  # type: int
        verbose=False,  # type: bool
        timeout=constants.DEFAULT_TIMEOUT,  # type: typing.Optional[int]
        get_pty=False,  # type: bool
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
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
        :type timeout: typing.Optional[int]
        :param get_pty: open PTY on target machine
        :type get_pty: bool
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        cmd_for_log = self._mask_command(
            cmd=command,
            log_mask_re=kwargs.get('log_mask_re', None)
        )
        self.logger.log(
            level=logging.INFO if verbose else logging.DEBUG,
            msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        if auth is None:
            auth = self.auth

        intermediate_channel = self._ssh.get_transport().open_channel(
            kind='direct-tcpip',
            dest_addr=(hostname, target_port),
            src_addr=(self.hostname, 0))
        transport = paramiko.Transport(sock=intermediate_channel)

        # start client and authenticate transport
        auth.connect(transport)

        # open ssh session
        channel = transport.open_session()
        if get_pty:
            # Open PTY
            channel.get_pty(
                term='vt100',
                width=kwargs.get('width', 80), height=kwargs.get('height', 24),
                width_pixels=0, height_pixels=0
            )

        # Make proxy objects for read
        stdout = channel.makefile('rb')
        stderr = channel.makefile_stderr('rb')

        channel.exec_command(command)  # nosec  # Sanitize on caller side

        # noinspection PyDictCreation
        result = self._exec_command(
            command, channel, stdout, stderr, timeout, verbose=verbose,
            log_mask_re=kwargs.get('log_mask_re', None),
        )

        intermediate_channel.close()

        return result

    @classmethod
    def execute_together(
        cls,
        remotes,  # type: typing.Iterable[SSHClientBase]
        command,  # type: str
        timeout=constants.DEFAULT_TIMEOUT,  # type: typing.Optional[int]
        expected=None,  # type: typing.Optional[typing.Iterable[int]]
        raise_on_err=True,  # type: bool
        **kwargs
    ):  # type: (...) -> _type_multiple_results
        """Execute command on multiple remotes in async mode.

        :param remotes: Connections to execute on
        :type remotes: typing.Iterable[SSHClientBase]
        :param command: Command for execution
        :type command: str
        :param timeout: Timeout for command execution.
        :type timeout: typing.Optional[int]
        :param expected: expected return codes (0 by default)
        :type expected: typing.Optional[typing.Iterable[]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :return: dictionary {(hostname, port): result}
        :rtype: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult]
        :raises ParallelCallProcessError: Unexpected any code at lest on one target
        :raises ParallelCallExceptions: At lest one exception raised during execution (including timeout)

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        @threaded.threadpooled
        def get_result(
            remote  # type: SSHClientBase
        ):  # type: (...) -> exec_result.ExecResult
            """Get result from remote call."""
            (
                chan,
                _,
                stderr,
                stdout,
            ) = remote.execute_async(
                command,
                **kwargs
            )  # type: _type_execute_async

            chan.status_event.wait(timeout)
            exit_code = chan.recv_exit_status()

            # pylint: disable=protected-access
            cmd_for_log = remote._mask_command(
                cmd=command,
                log_mask_re=kwargs.get('log_mask_re', None)
            )
            # pylint: enable=protected-access

            result = exec_result.ExecResult(cmd=cmd_for_log)
            result.read_stdout(src=stdout)
            result.read_stderr(src=stderr)
            result.exit_code = exit_code

            chan.close()
            return result

        expected = expected or [proc_enums.ExitCodes.EX_OK]
        expected = proc_enums.exit_codes_to_enums(expected)

        futures = {}
        results = {}
        errors = {}
        raised_exceptions = {}

        for remote in set(remotes):  # Use distinct remotes
            futures[remote] = get_result(remote)

        (
            _,
            not_done,
        ) = concurrent.futures.wait(
            list(futures.values()),
            timeout=timeout
        )  # type: typing.Set[concurrent.futures.Future], typing.Set[concurrent.futures.Future]
        for future in not_done:
            future.cancel()

        for (
            remote,
            future,
        ) in futures.items():  # type: SSHClientBase, concurrent.futures.Future
            try:
                result = future.result()
                results[(remote.hostname, remote.port)] = result
                if result.exit_code not in expected:
                    errors[(remote.hostname, remote.port)] = result
            except Exception as e:
                raised_exceptions[(remote.hostname, remote.port)] = e

        if raised_exceptions:  # always raise
            raise exceptions.ParallelCallExceptions(
                command,
                raised_exceptions,
                errors,
                results,
                expected=expected
            )
        if errors and raise_on_err:
            raise exceptions.ParallelCallProcessError(
                command, errors, results, expected=expected
            )
        return results

    def open(self, path, mode='r'):
        """Open file on remote using SFTP session.

        :type path: str
        :type mode: str
        :return: file.open() stream
        """
        return self._sftp.open(path, mode)  # pragma: no cover

    def exists(self, path):  # type: (str) -> bool
        """Check for file existence using SFTP session.

        :type path: str
        :rtype: bool
        """
        try:
            self._sftp.lstat(path)
            return True
        except IOError:
            return False

    def stat(self, path):  # type: (str) -> paramiko.sftp_attr.SFTPAttributes
        """Get stat info for path with following symlinks.

        :type path: str
        :rtype: paramiko.sftp_attr.SFTPAttributes
        """
        return self._sftp.stat(path)  # pragma: no cover

    def utime(
        self,
        path,  # type: str
        times=None  # type: typing.Optional[typing.Tuple[int, int]]
    ):
        """Set atime, mtime.

        :param path: filesystem object path
        :type path: str
        :param times: (atime, mtime)
        :type times: typing.Optional[typing.Tuple[int, int]]

        .. versionadded:: 1.0.0
        """
        return self._sftp.utime(path, times)  # pragma: no cover

    def isfile(self, path):  # type: (str) -> bool
        """Check, that path is file using SFTP session.

        :type path: str
        :rtype: bool
        """
        try:
            attrs = self._sftp.lstat(path)
            return attrs.st_mode & stat.S_IFREG != 0
        except IOError:
            return False

    def isdir(self, path):  # type: (str) -> bool
        """Check, that path is directory using SFTP session.

        :type path: str
        :rtype: bool
        """
        try:
            attrs = self._sftp.lstat(path)
            return attrs.st_mode & stat.S_IFDIR != 0
        except IOError:
            return False
