#    Copyright 2018 - 2021 Alexey Stepanov aka penguinolog.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Python asyncio.create_subprocess_shell wrapper.

.. versionadded:: 3.0.0
"""

from __future__ import annotations

# Standard Library
import asyncio
import copy
import datetime
import errno
import logging
import os
import typing
import warnings

# Package Implementation
from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import proc_enums
from exec_helpers import subprocess
from exec_helpers.async_api import api
from exec_helpers.async_api import exec_result

# Local Implementation
from .. import _log_templates
from .. import _subprocess_helpers

if typing.TYPE_CHECKING:
    # Standard Library
    import types

    # Package Implementation
    from exec_helpers.api import CalledProcessErrorSubClassT
    from exec_helpers.api import CommandT
    from exec_helpers.api import ErrorInfoT
    from exec_helpers.api import ExpectedExitCodesT
    from exec_helpers.api import LogMaskReT
    from exec_helpers.api import OptionalTimeoutT
    from exec_helpers.exec_result import OptionalStdinT
    from exec_helpers.subprocess import CwdT
    from exec_helpers.subprocess import EnvT

__all__ = ("Subprocess", "SubprocessExecuteAsyncResult")


# noinspection PyTypeHints,PyTypeChecker
class SubprocessExecuteAsyncResult(subprocess.SubprocessExecuteAsyncResult):
    """Override original NamedTuple with proper typing."""

    __slots__ = ()

    # pylint: disable=no-member
    @property
    def interface(self) -> asyncio.subprocess.Process:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: control interface
        :rtype: asyncio.subprocess.Process
        """
        return super().interface  # type: ignore

    # pylint: enable=no-member

    @property
    def stdin(self) -> typing.Optional[asyncio.StreamWriter]:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDIN interface
        :rtype: typing.Optional[asyncio.StreamWriter]
        """
        warnings.warn("stdin access deprecated: FIFO is often closed on execution and direct access is not expected.")
        return super().stdin  # type: ignore

    @property
    def stderr(self) -> typing.Optional[typing.AsyncIterable[bytes]]:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDERR interface
        :rtype: typing.Optional[typing.AsyncIterable[bytes]]
        """
        return super().stderr  # type: ignore

    @property
    def stdout(self) -> typing.Optional[typing.AsyncIterable[bytes]]:  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDOUT interface
        :rtype: typing.Optional[typing.AsyncIterable[bytes]]
        """
        return super().stdout  # type: ignore


class _SubprocessExecuteContext(api.ExecuteContext, typing.AsyncContextManager[SubprocessExecuteAsyncResult]):
    """Subprocess Execute context."""

    __slots__ = ("__cwd", "__env", "__process")

    def __init__(
        self,
        *,
        command: str,
        stdin: typing.Optional[bytes] = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        logger: logging.Logger,
        **kwargs: typing.Any,
    ) -> None:
        """Subprocess Execute context.

        :param command: Command for execution (fully formatted)
        :type command: str
        :param stdin: pass STDIN text to the process (fully formatted)
        :type stdin: bytes
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param logger: instance logger
        :type logger: logging.Logger
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        """
        super().__init__(
            command=command,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            logger=logger,
            **kwargs,
        )
        self.__cwd = cwd
        self.__env = env
        self.__process: typing.Optional[asyncio.subprocess.Process] = None  # pylint: disable=no-member

    def __repr__(self) -> str:
        """Debug string.

        :return: reproduce for debug
        :rtype: str
        """
        return (
            f"<Subprocess().open_execute_context("
            f"command={self.command!r}, "
            f"stdin={self.stdin!r}, "
            f"open_stdout={self.open_stdout!r}, "
            f"open_stderr={self.open_stderr!r}, "
            f"cwd={self.__cwd!r}, "
            f"env={self.__env!r}, "
            f"logger={self.logger!r}) "
            f"at {id(self)}>"
        )

    async def __aenter__(self) -> SubprocessExecuteAsyncResult:
        """Context manager enter.

        :return: raw execution information
        :rtype: SshExecuteAsyncResult
        :raises OSError: stdin write failed/stdin close failed

        Command is executed only in context manager to be sure, that everything will be cleaned up properly.
        """
        started = datetime.datetime.utcnow()

        self.__process = await asyncio.create_subprocess_shell(
            cmd=self.command,
            stdout=asyncio.subprocess.PIPE if self.open_stdout else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE if self.open_stderr else asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.PIPE,
            cwd=self.__cwd,
            env=self.__env,
            universal_newlines=False,
            **_subprocess_helpers.subprocess_kw,
        )
        process = self.__process

        if self.stdin is not None:
            if process.stdin is None:
                self.logger.warning("STDIN pipe is not set, but STDIN data is available to send.")
            else:
                try:
                    process.stdin.write(self.stdin)
                    await process.stdin.drain()
                except BrokenPipeError:
                    self.logger.warning("STDIN Send failed: broken PIPE")
                except ConnectionResetError:
                    self.logger.warning("STDIN Send failed: closed PIPE")
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    self.logger.warning("STDIN Send failed: broken PIPE")
                except OSError as exc:
                    if exc.errno != errno.EINVAL:
                        _subprocess_helpers.kill_proc_tree(process.pid)
                        process.kill()
                        raise

        # noinspection PyArgumentList
        return SubprocessExecuteAsyncResult(
            interface=process,
            stdin=None,
            stderr=process.stderr,
            stdout=process.stdout,
            started=started,
        )

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]],
        exc_val: typing.Optional[BaseException],
        exc_tb: typing.Optional[types.TracebackType],
    ) -> None:
        process = self.__process
        if process is not None:
            _subprocess_helpers.kill_proc_tree(process.pid)
            try:
                process.kill()
            except ProcessLookupError:
                pass  # process already closed
            self.__process = None


class Subprocess(api.ExecHelper):
    """Subprocess helper with timeouts and lock-free FIFO.

    :param log_mask_re: regex lookup rule to mask command for logger.
                        all MATCHED groups will be replaced by '<*masked*>'
    :type log_mask_re: typing.Optional[str]
    :param logger: logger instance to use
    :type logger: logging.Logger

    .. versionchanged:: 3.1.0 Not singleton anymore. Only lock is shared between all instances.
    .. versionchanged:: 3.2.0 Logger can be enforced.
    .. versionchanged:: 4.1.0 support chroot
    .. versionchanged:: 4.3.0 Lock is not shared anymore: allow parallel call of different instances.
    """

    __slots__ = ()

    def __init__(
        self,
        log_mask_re: LogMaskReT = None,
        *,
        logger: logging.Logger = logging.getLogger(__name__),  # noqa: B008
    ) -> None:
        """Subprocess helper with timeouts and lock-free FIFO."""
        super().__init__(logger=logger, log_mask_re=log_mask_re)

    async def __aenter__(self) -> Subprocess:
        """Async context manager.

        :return: exec helper instance with async entered context manager
        :rtype: Subprocess
        """
        # noinspection PyTypeChecker
        return await super().__aenter__()

    def __enter__(self) -> Subprocess:  # pylint: disable=useless-super-delegation
        """Get context manager.

        :return: exec helper instance with entered context manager
        :rtype: Subprocess
        """
        # noinspection PyTypeChecker
        return super().__enter__()  # type: ignore  # pylint: disable=no-member

    async def _exec_command(  # type: ignore
        self,
        command: str,
        async_result: SubprocessExecuteAsyncResult,
        timeout: OptionalTimeoutT,
        *,
        verbose: bool = False,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Get exit status from channel with timeout.

        :param command: Command for execution
        :type command: str
        :param async_result: execute_async result
        :type async_result: SubprocessExecuteAsyncResult
        :param timeout: Timeout for command execution
        :type timeout: typing.Union[int, float, None]
        :param verbose: produce verbose log record on command call
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
        :raises OSError: exception during process kill (and not regarding to already closed process)
        :raises ExecHelperNoKillError: Process not dies on SIGTERM & SIGKILL
        :raises ExecHelperTimeoutError: Timeout exceeded
        """

        async def poll_stdout() -> None:
            """Sync stdout poll."""
            await result.read_stdout(src=async_result.stdout, log=self.logger, verbose=verbose)

        async def poll_stderr() -> None:
            """Sync stderr poll."""
            await result.read_stderr(src=async_result.stderr, log=self.logger, verbose=verbose)

        # Store command with hidden data
        cmd_for_log: str = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        result = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)

        stdout_task: asyncio.Task[None] = asyncio.create_task(poll_stdout())
        stderr_task: asyncio.Task[None] = asyncio.create_task(poll_stderr())

        try:
            # Wait real timeout here
            exit_code: int = await asyncio.wait_for(async_result.interface.wait(), timeout=timeout)
            result.exit_code = exit_code
            return result
        except asyncio.TimeoutError as exc:
            # kill -9 for all subprocesses
            _subprocess_helpers.kill_proc_tree(async_result.interface.pid)
            exit_signal: typing.Optional[int] = await asyncio.wait_for(async_result.interface.wait(), timeout=0.001)
            if exit_signal is None:
                raise exceptions.ExecHelperNoKillError(result=result, timeout=timeout) from exc  # type: ignore
            result.exit_code = exit_signal
        finally:
            stdout_task.cancel()
            stderr_task.cancel()
            result.set_timestamp()

        wait_err_msg: str = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(result=result, timeout=timeout)  # type: ignore

    # noinspection PyMethodOverriding
    async def _execute_async(  # pylint: disable=arguments-differ
        self,
        command: str,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> SubprocessExecuteAsyncResult:
        """Execute command in async mode and return Popen with IO objects.

        :param command: Command for execution
        :type command: str
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[str, bytes, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param chroot_path: chroot path override
        :type chroot_path: typing.Optional[str]
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Tuple with control interface and file-like objects for STDIN/STDERR/STDOUT
        :rtype: typing.NamedTuple(
                    'SubprocessExecuteAsyncResult',
                    [
                        ('interface', asyncio.subprocess.Process),
                        ('stdin', typing.Optional[asyncio.StreamWriter]),
                        ('stderr', typing.Optional[asyncio.StreamReader]),
                        ('stdout', typing.Optional[asyncio.StreamReader]),
                        ("started", datetime.datetime),
                    ]
                )
        :raises OSError: impossible to process STDIN
        """
        warnings.warn("_execute_async is deprecated and will be removed soon", DeprecationWarning)
        started = datetime.datetime.utcnow()

        if env_patch is not None:
            # make mutable copy
            env = dict(copy.deepcopy(os.environ) if env is None else copy.deepcopy(env))  # type: ignore
            env.update(env_patch)  # type: ignore

        process: asyncio.subprocess.Process = await asyncio.create_subprocess_shell(  # pylint: disable=no-member
            cmd=self._prepare_command(cmd=command, chroot_path=chroot_path),
            stdout=asyncio.subprocess.PIPE if open_stdout else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE if open_stderr else asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
            universal_newlines=False,
            **_subprocess_helpers.subprocess_kw,
        )

        if stdin is None:
            process_stdin: typing.Optional[asyncio.StreamWriter] = process.stdin
        else:
            stdin_str: bytes = self._string_bytes_bytearray_as_bytes(stdin)
            try:
                process.stdin.write(stdin_str)  # type: ignore
                await process.stdin.drain()  # type: ignore
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    # bpo-19612, bpo-30418: On Windows, stdin.write() fails
                    # with EINVAL if the child process exited or if the child
                    # process is still running but closed the pipe.
                    self.logger.warning("STDIN Send failed: closed PIPE")
                elif exc.errno in (errno.EPIPE, errno.ESHUTDOWN):
                    self.logger.warning("STDIN Send failed: broken PIPE")
                else:
                    _subprocess_helpers.kill_proc_tree(process.pid)
                    process.kill()
                    raise
            try:
                process.stdin.close()  # type: ignore
            except OSError as exc:
                if exc.errno in (errno.EINVAL, errno.EPIPE, errno.ESHUTDOWN):
                    pass  # PIPE already closed
                else:
                    _subprocess_helpers.kill_proc_tree(process.pid)
                    process.kill()
                    raise

            process_stdin = None

        # noinspection PyArgumentList
        return SubprocessExecuteAsyncResult(
            interface=process,
            stdin=process_stdin,
            stderr=process.stderr,
            stdout=process.stdout,
            started=started,
        )

    def open_execute_context(  # pylint: disable=arguments-differ
        self,
        command: str,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> _SubprocessExecuteContext:
        """Get execution context manager.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param chroot_path: chroot path override
        :type chroot_path: typing.Optional[str]
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execute context
        :rtype: _SubprocessExecuteContext
        .. versionadded:: 8.0.0
        """
        if env_patch is not None:
            # make mutable copy
            env = dict(copy.deepcopy(os.environ) if env is None else copy.deepcopy(env))  # type: ignore
            env.update(env_patch)  # type: ignore
        return _SubprocessExecuteContext(
            command=f"{self._prepare_command(cmd=command, chroot_path=chroot_path)}\n",
            stdin=None if stdin is None else self._string_bytes_bytearray_as_bytes(stdin),
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            cwd=cwd,
            env=env,
            logger=self.logger,
            **kwargs,
        )

    async def execute(  # pylint: disable=arguments-differ
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
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
        :param chroot_path: chroot path override
        :type chroot_path: typing.Optional[str]
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        .. versionchanged:: 7.0.0 Allow command as list of arguments. Command will be joined with components escaping.
        .. versionchanged:: 8.0.0 chroot path exposed.
        """
        return await super().execute(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            chroot_path=chroot_path,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            **kwargs,
        )

    async def __call__(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
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
        :param chroot_path: chroot path override
        :type chroot_path: typing.Optional[str]
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        """
        return await super().__call__(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            chroot_path=chroot_path,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            **kwargs,
        )

    async def check_call(  # pylint: disable=arguments-differ
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
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
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
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
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
        return await super().check_call(
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
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            exception_class=exception_class,
            **kwargs,
        )

    async def check_stderr(  # pylint: disable=arguments-differ
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
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
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
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, pathlib.Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
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
        return await super().check_stderr(
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
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            exception_class=exception_class,
            **kwargs,
        )
