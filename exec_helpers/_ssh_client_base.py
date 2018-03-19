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

from __future__ import unicode_literals

import base64
import copy
import io  # noqa  # pylint: disable=unused-import
import logging
import stat
import sys
import threading
import time
import typing
import warnings

# noinspection PyCompatibility
import concurrent.futures
import paramiko
import retrying
import threaded
import six

from exec_helpers import exceptions
from exec_helpers import exec_result
from exec_helpers import _log_templates
from exec_helpers import proc_enums

__all__ = ('SSHAuth', 'SSHClientBase')

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


class SSHAuth(object):
    """SSH Authorization object."""

    __slots__ = ('__username', '__password', '__key', '__keys')

    def __init__(
        self,
        username=None,  # type: typing.Optional[str]
        password=None,  # type: typing.Optional[str]
        key=None,  # type: typing.Optional[paramiko.RSAKey]
        keys=None,  # type: typing.Optional[_type_RSAKeys]
    ):
        """SSH authorisation object.

        Used to authorize SSHClient.
        Single SSHAuth object is associated with single host:port.
        Password and key is private, other data is read-only.

        :type username: str
        :type password: str
        :type key: paramiko.RSAKey
        :type keys: list
        """
        self.__username = username
        self.__password = password
        self.__key = key
        self.__keys = [None]
        if key is not None:
            # noinspection PyTypeChecker
            self.__keys.append(key)
        if keys is not None:
            for k in keys:
                if k not in self.__keys:
                    self.__keys.append(k)

    @property
    def username(self):  # type: () -> str
        """Username for auth.

        :rtype: str
        """
        return self.__username

    @staticmethod
    def __get_public_key(key):  # type: () -> typing.Optional[str]
        """Internal method for get public key from private.

        :type key: paramiko.RSAKey
        """
        if key is None:
            return None
        return '{0} {1}'.format(key.get_name(), key.get_base64())

    @property
    def public_key(self):  # type: () -> typing.Optional[str]
        """public key for stored private key if presents else None.

        :rtype: str
        """
        return self.__get_public_key(self.__key)

    def enter_password(self, tgt):  # type: (io.StringIO) -> None
        """Enter password to STDIN.

        Note: required for 'sudo' call

        :type tgt: file
        :rtype: str
        """
        # noinspection PyTypeChecker
        return tgt.write('{}\n'.format(self.__password))

    def connect(
        self,
        client,  # type: _type_ConnectSSH
        hostname=None,  # type: typing.Optional[str]
        port=22,  # type: int
        log=True,  # type: bool
    ):
        """Connect SSH client object using credentials.

        :type client:
            paramiko.client.SSHClient
            paramiko.transport.Transport
        :type hostname: typing.Optional[str]
        :type port: int
        :type log: bool
        :raises paramiko.AuthenticationException
        """
        kwargs = {
            'username': self.username,
            'password': self.__password}
        if hostname is not None:
            kwargs['hostname'] = hostname
            kwargs['port'] = port

        keys = [self.__key]
        keys.extend([k for k in self.__keys if k != self.__key])

        for key in keys:
            kwargs['pkey'] = key
            try:
                client.connect(**kwargs)
                if self.__key != key:
                    self.__key = key
                    logger.debug(
                        'Main key has been updated, public key is: \n'
                        '{}'.format(self.public_key))
                return
            except paramiko.PasswordRequiredException:
                if self.__password is None:
                    logger.exception('No password has been set!')
                    raise
                else:
                    logger.critical(
                        'Unexpected PasswordRequiredException, '
                        'when password is set!')
                    raise
            except (paramiko.AuthenticationException,
                    paramiko.BadHostKeyException):
                continue
        msg = 'Connection using stored authentication info failed!'
        if log:
            logger.exception(msg)
        raise paramiko.AuthenticationException(msg)

    def __hash__(self):
        """Hash for usage as dict keys and comparison."""
        return hash((
            self.__class__,
            self.username,
            self.__password,
            tuple(self.__keys)
        ))

    def __eq__(self, other):
        """Comparison helper."""
        return hash(self) == hash(other)

    def __ne__(self, other):
        """Comparison helper."""
        return not self.__eq__(other)

    def __deepcopy__(self, memo):
        """Helper for copy.deepcopy."""
        return self.__class__(
            username=self.username,
            password=self.__password,
            key=self.__key,
            keys=self.__keys.copy()
        )

    def __copy__(self):
        """Copy self."""
        return self.__class__(
            username=self.username,
            password=self.__password,
            key=self.__key,
            keys=self.__keys
        )

    def __repr__(self):
        """Representation for debug purposes."""
        _key = (
            None if self.__key is None else
            '<private for pub: {}>'.format(self.public_key)
        )
        _keys = []
        for k in self.__keys:
            if k == self.__key:
                continue
            # noinspection PyTypeChecker
            _keys.append(
                '<private for pub: {}>'.format(
                    self.__get_public_key(key=k)) if k is not None else None)

        return (
            '{cls}(username={username}, '
            'password=<*masked*>, key={key}, keys={keys})'.format(
                cls=self.__class__.__name__,
                username=self.username,
                key=_key,
                keys=_keys)
        )

    def __str__(self):
        """Representation for debug purposes."""
        return (
            '{cls} for {username}'.format(
                cls=self.__class__.__name__,
                username=self.username,
            )
        )


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

    __cache = {}

    def __call__(
        cls,
        host,  # type: str
        port=22,  # type: int
        username=None,  # type: typing.Optional[str]
        password=None,  # type: typing.Optional[str]
        private_keys=None,  # type: typing.Optional[_type_RSAKeys]
        auth=None,  # type: typing.Optional[SSHAuth]
    ):  # type: (...) -> SSHClient
        """Main memorize method: check for cached instance and return it.

        :type host: str
        :type port: int
        :type username: str
        :type password: str
        :type private_keys: list
        :type auth: SSHAuth
        :rtype: SSHClient
        """
        if (host, port) in cls.__cache:
            key = host, port
            if auth is None:
                auth = SSHAuth(
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
            if sys.getrefcount(cls.__cache[key]) == 2:
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
    def clear_cache(mcs):
        """Clear cached connections for initialize new instance on next call.

        getrefcount is used to check for usage.
        """
        n_count = 3 if six.PY3 else 4
        # PY3: cache, ssh, temporary
        # PY4: cache, values mapping, ssh, temporary
        for ssh in mcs.__cache.values():
            if sys.getrefcount(ssh) == n_count:
                logger.debug('Closing {} as unused'.format(ssh))
                ssh.close()
        mcs.__cache = {}

    @classmethod
    def close_connections(mcs, hostname=None):
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


def _py2_str(src):
    """Convert text to correct python type."""
    if not six.PY3 and isinstance(src, six.text_type):
        return src.encode(
            encoding='utf-8',
            errors='strict',
        )
    return src


BaseSSHClient = type.__new__(  # noqa
    _MemorizedSSH,
    _py2_str('BaseSSHClient'),
    (object, ),
    {'__slots__': ()}
)


class SSHClientBase(BaseSSHClient):
    """SSH Client helper."""

    __slots__ = (
        '__hostname', '__port', '__auth', '__ssh', '__sftp', 'sudo_mode',
        '__lock'
    )

    class __get_sudo(object):
        """Context manager for call commands with sudo."""

        def __init__(
            self,
            ssh,  # type: SSHClient
            enforce=None  # type: typing.Optional[bool]
        ):
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
        auth=None,  # type: typing.Optional[SSHAuth]
    ):
        """SSHClient helper.

        :type host: str
        :type port: int
        :type username: str
        :type password: str
        :type private_keys: list
        :type auth: SSHAuth
        """
        self.__lock = threading.RLock()

        self.__hostname = host
        self.__port = port

        self.sudo_mode = False
        self.__ssh = paramiko.SSHClient()
        self.__ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.__sftp = None

        if auth is None:
            self.__auth = SSHAuth(
                username=username,
                password=password,
                keys=private_keys
            )
        else:
            self.__auth = copy.copy(auth)

        self.__connect()

    @property
    def lock(self):  # type: () -> threading.RLock
        """Connection lock.

        :rtype: threading.RLock
        """
        return self.__lock

    @property
    def auth(self):  # type: () -> SSHAuth
        """Internal authorisation object.

        Attention: this public property is mainly for inheritance,
        debug and information purposes.
        Calls outside SSHClient and child classes is sign of incorrect design.
        Change is completely disallowed.

        :rtype: SSHAuth
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

    @retrying.retry(
        retry_on_exception=lambda exc: isinstance(exc, paramiko.SSHException),
        stop_max_attempt_number=3,
        wait_fixed=3 * 1000,
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
                logger.warning('SFTP enable failed! SSH only is accessible.')

    @property
    def _sftp(self):  # type: () -> paramiko.sftp_client.SFTPClient
        """SFTP channel access for inheritance.

        :rtype: paramiko.sftp_client.SFTPClient
        :raises: paramiko.SSHException
        """
        if self.__sftp is not None:
            return self.__sftp
        logger.debug('SFTP is not connected, try to connect...')
        self.__connect_sftp()
        if self.__sftp is not None:
            return self.__sftp
        raise paramiko.SSHException('SFTP connection failed')

    def close(self):
        """Close SSH and SFTP sessions."""
        with self.lock:
            # noinspection PyBroadException
            try:
                self.__ssh.close()
                self.__sftp = None
            except Exception:
                logger.exception("Could not close ssh connection")
                if self.__sftp is not None:
                    # noinspection PyBroadException
                    try:
                        self.__sftp.close()
                    except Exception:
                        logger.exception("Could not close sftp connection")

    @classmethod
    def _clear_cache(cls):
        """Enforce clear memorized records."""
        warnings.warn(
            '_clear_cache() is dangerous and not recommended for normal use!',
            Warning
        )
        _MemorizedSSH.clear_cache()

    @classmethod
    def close_connections(
        cls,
        hostname=None  # type: typing.Optional[str]
    ):
        """Close cached connections: if hostname is not set, then close all.

        :type hostname: str
        """
        _MemorizedSSH.close_connections(hostname=hostname)

    def __del__(self):
        """Destructor helper: close channel and threads BEFORE closing others.

        Due to threading in paramiko, default destructor could generate asserts
        on close, so we calling channel close before closing main ssh object.
        """
        try:
            self.__ssh.close()
        except BaseException as e:
            logger.debug(
                'Exception in {self!s} destructor call: {exc}'.format(
                    self=self,
                    exc=e
                )
            )
        self.__sftp = None

    def __enter__(self):
        """Get context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        pass

    def reconnect(self):
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

        :type enforce: typing.Optional[bool]
        :param enforce: Enforce sudo enabled or disabled. By default: None
        """
        return self.__get_sudo(ssh=self, enforce=enforce)

    def check_call(
        self,
        command,  # type: str
        verbose=False,  # type: bool
        timeout=None,  # type: typing.Optional[int]
        error_info=None,  # type: typing.Optional[str]
        expected=None,  # type: typing.Optional[typing.Iterable[]]
        raise_on_err=True,  # type: bool
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command and check for return code.

        :type command: str
        :type verbose: bool
        :type timeout: typing.Optional[int]
        :type error_info: typing.Optional[str]
        :type expected: typing.Optional[typing.Iterable[]]
        :type raise_on_err: bool
        :rtype: ExecResult
        :raises: CalledProcessError
        """
        expected = proc_enums.exit_codes_to_enums(expected)
        ret = self.execute(command, verbose, timeout, **kwargs)
        if ret.exit_code not in expected:
            message = (
                _log_templates.CMD_UNEXPECTED_EXIT_CODE.format(
                    append=error_info + '\n' if error_info else '',
                    cmd=command,
                    code=ret.exit_code,
                    expected=expected,
                ))
            logger.error(message)
            if raise_on_err:
                raise exceptions.CalledProcessError(
                    command, ret.exit_code,
                    expected=expected,
                    stdout=ret.stdout_brief,
                    stderr=ret.stderr_brief
                )
        return ret

    def check_stderr(
        self,
        command,  # type: str
        verbose=False,  # type: bool
        timeout=None,  # type: typing.Optional[int]
        error_info=None,  # type: typing.Optional[str]
        raise_on_err=True,  # type: bool
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command expecting return code 0 and empty STDERR.

        :type command: str
        :type verbose: bool
        :type timeout: typing.Optional[int]
        :type error_info: typing.Optional[str]
        :type raise_on_err: bool
        :rtype: ExecResult
        :raises: CalledProcessError
        """
        ret = self.check_call(
            command, verbose, timeout=timeout,
            error_info=error_info, raise_on_err=raise_on_err, **kwargs)
        if ret.stderr:
            message = (
                _log_templates.CMD_UNEXPECTED_STDERR.format(
                    append=error_info + '\n' if error_info else '',
                    cmd=command,
                    code=ret.exit_code,
                ))
            logger.error(message)
            if raise_on_err:
                raise exceptions.CalledProcessError(
                    command,
                    ret.exit_code,
                    expected=kwargs.get('expected'),
                    stdout=ret.stdout_brief,
                    stderr=ret.stderr_brief
                )
        return ret

    @classmethod
    def execute_together(
        cls,
        remotes,
        command,  # type: str
        timeout=None,  # type: typing.Optional[int]
        expected=None,  # type: typing.Optional[typing.Iterable[]]
        raise_on_err=True,  # type: bool
        **kwargs
    ):  # type: (...) -> _type_multiple_results
        """Execute command on multiple remotes in async mode.

        :type remotes: list
        :type command: str
        :type timeout: typing.Optional[int]
        :type expected: typing.Optional[typing.Iterable[]]
        :type raise_on_err: bool
        :raises: ParallelCallProcessError
        :raises: ParallelCallExceptions
        """
        @threaded.threadpooled
        def get_result(remote):  # type: (SSHClient) -> exec_result.ExecResult
            """Get result from remote call."""
            chan, _, stderr, stdout = remote.execute_async(command, **kwargs)
            chan.status_event.wait(timeout)
            exit_code = chan.recv_exit_status()

            result = exec_result.ExecResult(cmd=command)
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
            _,  # type: typing.Set[concurrent.futures.Future]
            not_done,  # type: typing.Set[concurrent.futures.Future]
        ) = concurrent.futures.wait(
            list(futures.values()),
            timeout=timeout
        )
        for future in not_done:
            future.cancel()

        for (
            remote,  # type: SSHClientBase
            future,  # type: concurrent.futures.Future
        ) in futures.items():
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

    @classmethod
    def __exec_command(
        cls,
        command,  # type: str
        channel,  # type: paramiko.channel.Channel
        stdout,  # type: paramiko.channel.ChannelFile
        stderr,  # type: paramiko.channel.ChannelFile
        timeout,  # type: int
        verbose=False  # type: bool
    ):  # type: (...) -> exec_result.ExecResult
        """Get exit status from channel with timeout.

        :type command: str
        :type channel: paramiko.channel.Channel
        :type stdout: paramiko.channel.ChannelFile
        :type stderr: paramiko.channel.ChannelFile
        :type timeout: int
        :type verbose: bool
        :rtype: ExecResult
        :raises: ExecWrapperTimeoutError
        """
        def poll_streams(
            result,  # type: exec_result.ExecResult
            channel,  # type: paramiko.channel.Channel
            stdout,  # type:  paramiko.channel.ChannelFile
            stderr,  # type:  paramiko.channel.ChannelFile
        ):
            """Poll FIFO buffers if data available."""
            if channel.recv_ready():
                result.read_stdout(src=stdout, log=logger, verbose=verbose)
            if channel.recv_stderr_ready():
                result.read_stderr(src=stderr, log=logger, verbose=verbose)

        @threaded.threadpooled
        def poll_pipes(
            stdout,  # type:  paramiko.channel.ChannelFile
            stderr,  # type:  paramiko.channel.ChannelFile
            result,  # type: exec_result.ExecResult
            stop,  # type: threading.Event
            channel  # type: paramiko.channel.Channel
        ):
            """Polling task for FIFO buffers.

            :type stdout: paramiko.channel.ChannelFile
            :type stderr: paramiko.channel.ChannelFile
            :type result: ExecResult
            :type stop: Event
            :type channel: paramiko.channel.Channel
            """
            while not stop.isSet():
                time.sleep(0.1)
                poll_streams(
                    result=result,
                    channel=channel,
                    stdout=stdout,
                    stderr=stderr,
                )

                if channel.status_event.is_set():
                    result.read_stdout(src=stdout, log=logger, verbose=verbose)
                    result.read_stderr(src=stderr, log=logger, verbose=verbose)
                    result.exit_code = channel.exit_status

                    stop.set()

        # channel.status_event.wait(timeout)
        result = exec_result.ExecResult(cmd=command)
        stop_event = threading.Event()
        message = _log_templates.CMD_EXEC.format(cmd=command.rstrip())
        logger.log(
            level=logging.INFO if verbose else logging.DEBUG,
            msg=message
        )

        # pylint: disable=assignment-from-no-return
        future = poll_pipes(
            stdout=stdout,
            stderr=stderr,
            result=result,
            stop=stop_event,
            channel=channel
        )  # type: concurrent.futures.Future
        # pylint: enable=assignment-from-no-return

        concurrent.futures.wait([future], timeout)

        # Process closed?
        if stop_event.isSet():
            stop_event.clear()
            channel.close()
            return result

        stop_event.set()
        channel.close()
        future.cancel()

        wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(
            cmd=command.rstrip(),
            timeout=timeout)
        output_brief_msg = (
            '\tSTDOUT:\n'
            '{result.stdout_brief}\n'
            '\tSTDERR"\n'
            '{result.stderr_brief}'.format(result=result)
        )
        logger.debug(wait_err_msg)
        raise exceptions.ExecWrapperTimeoutError(
            wait_err_msg + output_brief_msg
        )

    def execute(
        self,
        command,  # type: str
        verbose=False,  # type: bool
        timeout=None,  # type: typing.Optional[int]
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command and wait for return code.

        :type command: str
        :type verbose: bool
        :type timeout: typing.Optional[int]
        :rtype: ExecResult
        :raises: ExecWrapperTimeoutError
        """
        chan, _, stderr, stdout = self.execute_async(command, **kwargs)

        result = self.__exec_command(
            command, chan, stdout, stderr, timeout,
            verbose=verbose
        )
        message = _log_templates.CMD_RESULT.format(
            cmd=command.rstrip(), code=result.exit_code
        )
        logger.log(
            level=logging.INFO if verbose else logging.DEBUG,
            msg=message
        )
        return result

    def execute_async(
        self,
        command,  # type: str
        get_pty=False,  # type: bool
        **kwargs
    ):
        """Execute command in async mode and return channel with IO objects.

        :type command: str
        :type get_pty: bool
        :rtype:
            tuple(
                paramiko.Channel,
                paramiko.ChannelFile,
                paramiko.ChannelFile,
                paramiko.ChannelFile
            )
        """
        message = _log_templates.CMD_EXEC.format(cmd=command.rstrip())
        logger.debug(message)

        chan = self._ssh.get_transport().open_session()

        if get_pty:
            # Open PTY
            chan.get_pty(
                term='vt100',
                width=kwargs.get('width', 80), height=kwargs.get('height', 24),
                width_pixels=0, height_pixels=0
            )

        stdin = chan.makefile('wb')
        stdout = chan.makefile('rb')
        stderr = chan.makefile_stderr('rb')
        cmd = "{command}\n".format(command=command)
        if self.sudo_mode:
            encoded_cmd = base64.b64encode(cmd.encode('utf-8')).decode('utf-8')
            cmd = (
                "sudo -S bash -c 'eval \"$(base64 -d <(echo \"{0}\"))\"'"
            ).format(
                encoded_cmd
            )
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side
            if stdout.channel.closed is False:
                self.auth.enter_password(stdin)
                stdin.flush()
        else:
            chan.exec_command(cmd)  # nosec  # Sanitize on caller side
        return chan, stdin, stderr, stdout

    def execute_through_host(
        self,
        hostname,  # type: str
        command,  # type: str
        auth=None,  # type: typing.Optional[SSHAuth]
        target_port=22,  # type: int
        timeout=None,  # type: typing.Optional[int]
        verbose=False,  # type: bool
        get_pty=False,  # type: bool
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command on remote host through currently connected host.

        :type hostname: str
        :type command: str
        :type auth: typing.Optional[SSHAuth]
        :type target_port: int
        :type timeout: typing.Optional[int]
        :type verbose: bool
        :rtype: ExecResult
        :type get_pty: bool
        :raises: ExecWrapperTimeoutError
        """
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
        result = self.__exec_command(
            command, channel, stdout, stderr, timeout, verbose=verbose)

        intermediate_channel.close()

        return result

    def open(self, path, mode='r'):
        """Open file on remote using SFTP session.

        :type path: str
        :type mode: str
        :return: file.open() stream
        """
        return self._sftp.open(path, mode)

    def exists(self, path):  # type: (str) -> Bool
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
        return self._sftp.stat(path)

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
