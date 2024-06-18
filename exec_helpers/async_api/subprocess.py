#    Copyright 2018 - 2023 Aleksei Stepanov aka penguinolog.

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

import asyncio
import contextlib
import copy
import datetime
import errno
import logging
import os
import typing
import warnings

from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import proc_enums
from exec_helpers import subprocess
from exec_helpers.async_api import api
from exec_helpers.async_api import exec_result

from .. import _log_templates
from .. import _subprocess_helpers

if typing.TYPE_CHECKING:
    import types
    from collections.abc import AsyncIterable

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

    @property
    def interface(self) -> asyncio.subprocess.Process:  # type: ignore[override]
        """Override original NamedTuple with proper typing.

        :return: Control interface.
        :rtype: asyncio.subprocess.Process
        """
        return super().interface  # type: ignore[return-value]

    # pylint: enable=no-member

    @property
    def stdin(self) -> asyncio.StreamWriter | None:  # type: ignore[override]
        """Override original NamedTuple with proper typing.

        :return: STDIN interface.
        :rtype: asyncio.StreamWriter | None
        """
        warnings.warn(
            "stdin access deprecated: FIFO is often closed on execution and direct access is not expected.",
            DeprecationWarning,
            stacklevel=2,
        )
        return super().stdin  # type: ignore[return-value]

    @property
    def stderr(self) -> AsyncIterable[bytes] | None:  # type: ignore[override]
        """Override original NamedTuple with proper typing.

        :return: STDERR interface.
        :rtype: AsyncIterable[bytes] | None
        """
        return super().stderr  # type: ignore[return-value]

    @property
    def stdout(self) -> AsyncIterable[bytes] | None:  # type: ignore[override]
        """Override original NamedTuple with proper typing.

        :return: STDOUT interface.
        :rtype: AsyncIterable[bytes] | None
        """
        return super().stdout  # type: ignore[return-value]


class _SubprocessExecuteContext(api.ExecuteContext, typing.AsyncContextManager[SubprocessExecuteAsyncResult]):
    """Subprocess Execute context."""

    __slots__ = ("__cwd", "__env", "__process")

    def __init__(
        self,
        *,
        command: str,
        stdin: bytes | None = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        logger: logging.Logger,
        **kwargs: typing.Any,
    ) -> None:
        """Subprocess Execute context.

        :param command: Command for execution (fully formatted).
        :type command: str
        :param stdin: Pass STDIN text to the process (fully formatted).
        :type stdin: bytes
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: str | bytes | pathlib.Path | None
        :param env: Defines the environment variables for the new process.
        :type env: Mapping[str | bytes, str | bytes] | None
        :param logger: Logger instance.
        :type logger: logging.Logger
        :param kwargs: Additional parameters for call.
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
        self.__process: asyncio.subprocess.Process | None = None

    def __repr__(self) -> str:
        """Debug string.

        :return: Reproduce for debug.
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

        :return: Raw execution information.
        :rtype: SshExecuteAsyncResult
        :raises OSError: STDIN write failed/STDIN close failed.

        The Command is executed only in the context manager to be sure that everything will be cleaned up properly.
        """
        started = datetime.datetime.now(tz=datetime.timezone.utc)

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
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        process = self.__process
        if process is not None:  # pylint: disable=consider-using-assignment-expr
            _subprocess_helpers.kill_proc_tree(process.pid)
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            self.__process = None


class Subprocess(api.ExecHelper):
    """Subprocess helper with timeouts and lock-free FIFO.

    :param log_mask_re: Regex lookup rule to mask command for logger.
                        All MATCHED groups will be replaced by '<*masked*>'.
    :type log_mask_re: str | re.Pattern[str] | None
    :param logger: Logger instance to use.
    :type logger: logging.Logger

    .. versionchanged:: 3.1.0 Not singleton anymore. Only lock is shared between all instances.
    .. versionchanged:: 3.2.0 Logger can be enforced.
    .. versionchanged:: 4.1.0 Support chroot
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

    async def _exec_command(  # type: ignore[override]
        self,
        command: str,
        async_result: SubprocessExecuteAsyncResult,
        timeout: OptionalTimeoutT,
        *,
        verbose: bool = False,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        log_stdout: bool = True,
        log_stderr: bool = True,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Get exit status from a channel with timeout.

        :param command: Command for execution.
        :type command: str
        :param async_result: execute_async result.
        :type async_result: SubprocessExecuteAsyncResult
        :param timeout: Timeout for command execution.
        :type timeout: int | float | None
        :param verbose: Produce verbose log record on command call.
        :type verbose: bool
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :param stdin: pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param log_stdout: Log STDOUT during read.
        :type log_stdout: bool
        :param log_stderr: Log STDERR during read.
        :type log_stderr: bool
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises OSError: exception during process kill (and not regarding already closed process).
        :raises ExecHelperNoKillError: Process not dies on SIGTERM & SIGKILL.
        :raises ExecHelperTimeoutError: Timeout exceeded.
        """

        async def poll_stdout() -> None:
            """Sync stdout poll."""
            await result.read_stdout(src=async_result.stdout, log=self.logger if log_stdout else None, verbose=verbose)

        async def poll_stderr() -> None:
            """Sync stderr poll."""
            await result.read_stderr(src=async_result.stderr, log=self.logger if log_stderr else None, verbose=verbose)

        # Store command with hidden data
        cmd_for_log: str = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        result = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)

        stdout_task: asyncio.Task[None] = asyncio.create_task(poll_stdout())
        stderr_task: asyncio.Task[None] = asyncio.create_task(poll_stderr())

        try:
            # Wait real timeout here
            exit_code: int = await asyncio.wait_for(async_result.interface.wait(), timeout=timeout)
            result.exit_code = exit_code
        except asyncio.TimeoutError as exc:
            # kill -9 for all subprocesses
            _subprocess_helpers.kill_proc_tree(async_result.interface.pid)
            exit_signal: int | None = await asyncio.wait_for(async_result.interface.wait(), timeout=0.001)
            if exit_signal is None:  # pylint: disable=consider-using-assignment-expr
                raise exceptions.ExecHelperNoKillError(
                    result=result,
                    timeout=timeout,  # type: ignore[arg-type]
                ) from exc
            result.exit_code = exit_signal
        else:
            return result
        finally:
            stdout_task.cancel()
            stderr_task.cancel()
            result.set_timestamp()

        wait_err_msg: str = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(result=result, timeout=timeout)  # type: ignore[arg-type]

    def open_execute_context(
        self,
        command: str,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: str | None = None,
        chroot_exe: str | None = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> _SubprocessExecuteContext:
        """Get execution context manager.

        :param command: Command for execution.
        :type command: str | Iterable[str]
        :param stdin: Pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param chroot_path: chroot path override.
        :type chroot_path: str | None
        :param chroot_exe: chroot exe override.
        :type chroot_exe: str | None
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: str | bytes | pathlib.Path | None
        :param env: Defines the environment variables for the new process.
        :type env: Mapping[str | bytes, str | bytes] | None
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: Mapping[str | bytes, str | bytes] | None
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execute context.
        :rtype: _SubprocessExecuteContext
        .. versionadded:: 8.0.0
        """
        if env_patch is not None:
            # make mutable copy
            env = dict(copy.deepcopy(os.environ) if env is None else copy.deepcopy(env))  # type: ignore[arg-type]
            env.update(env_patch)  # type: ignore[arg-type]
        return _SubprocessExecuteContext(
            command=f"{self._prepare_command(cmd=command, chroot_path=chroot_path, chroot_exe=chroot_exe)}\n",
            stdin=None if stdin is None else self._string_bytes_bytearray_as_bytes(stdin),
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            cwd=cwd,
            env=env,
            logger=self.logger,
            **kwargs,
        )

    async def execute(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        log_stdout: bool = True,
        open_stderr: bool = True,
        log_stderr: bool = True,
        chroot_path: str | None = None,
        chroot_exe: str | None = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution.
        :type command: str | Iterable[str]
        :param verbose: Produce log.info records for command call and output.
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: int | float | None
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :param stdin: Pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param log_stdout: Log STDOUT during read.
        :type log_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param log_stderr: Log STDERR during read.
        :type log_stderr: bool
        :param chroot_path: chroot path override.
        :type chroot_path: str | None
        :param chroot_exe: chroot exe override.
        :type chroot_exe: str | None
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: str | bytes | pathlib.Path | None
        :param env: Defines the environment variables for the new process.
        :type env: Mapping[str | bytes, str | bytes] | None
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: Mapping[str | bytes, str | bytes] | None
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.

        .. versionchanged:: 1.2.0 Default timeout 1 hour.
        .. versionchanged:: 2.1.0 Allow parallel calls.
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
            log_stdout=log_stdout,
            open_stderr=open_stderr,
            log_stderr=log_stderr,
            chroot_path=chroot_path,
            chroot_exe=chroot_exe,
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
        log_stdout: bool = True,
        open_stderr: bool = True,
        log_stderr: bool = True,
        chroot_path: str | None = None,
        chroot_exe: str | None = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution.
        :type command: str | Iterable[str]
        :param verbose: Produce log.info records for command call and output.
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: int | float | None
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :param stdin: pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param log_stdout: Log STDOUT during read.
        :type log_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param log_stderr: Log STDERR during read.
        :type log_stderr: bool
        :param chroot_path: chroot path override.
        :type chroot_path: str | None
        :param chroot_exe: chroot exe override.
        :type chroot_exe: str | None
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: str | bytes | pathlib.Path | None
        :param env: Defines the environment variables for the new process.
        :type env: Mapping[str | bytes, str | bytes] | None
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: Mapping[str | bytes, str | bytes] | None
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.

        .. versionchanged:: 1.2.0 Default timeout 1 hour.
        .. versionchanged:: 2.1.0 Allow parallel calls.
        """
        return await super().__call__(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            log_stdout=log_stdout,
            open_stderr=open_stderr,
            log_stderr=log_stderr,
            chroot_path=chroot_path,
            chroot_exe=chroot_exe,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            **kwargs,
        )

    async def check_call(
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
        log_stdout: bool = True,
        open_stderr: bool = True,
        log_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        exception_class: CalledProcessErrorSubClassT = exceptions.CalledProcessError,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command and check for return code.

        :param command: Command for execution.
        :type command: str | Iterable[str]
        :param verbose: Produce log.info records for command call and output.
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: int | float | None
        :param error_info: Text for error details, if fail happens.
        :type error_info: str | None
        :param expected: Expected return codes (0 by default).
        :type expected: Iterable[int | proc_enums.ExitCodes]
        :param raise_on_err: Raise exception on unexpected return code.
        :type raise_on_err: bool
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :param stdin: Pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param log_stdout: Log STDOUT during read.
        :type log_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param log_stderr: Log STDERR during read.
        :type log_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: str | bytes | pathlib.Path | None
        :param env: Defines the environment variables for the new process.
        :type env: Mapping[str | bytes, str | bytes] | None
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: Mapping[str | bytes, str | bytes] | None
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: type[exceptions.CalledProcessError]
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.
        :raises CalledProcessError: Unexpected exit code.

        .. versionchanged:: 1.2.0 Default timeout 1 hour.
        .. versionchanged:: 3.2.0 Exception class can be substituted.
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent.
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
            log_stdout=log_stdout,
            open_stderr=open_stderr,
            log_stderr=log_stderr,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            exception_class=exception_class,
            **kwargs,
        )

    async def check_stderr(
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
        log_stdout: bool = True,
        open_stderr: bool = True,
        log_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        exception_class: CalledProcessErrorSubClassT = exceptions.CalledProcessError,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution.
        :type command: str | Iterable[str]
        :param verbose: Produce log.info records for command call and output.
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: int | float | None
        :param error_info: Text for error details, if fail happens.
        :type error_info: str | None
        :param raise_on_err: Raise exception on unexpected return code.
        :type raise_on_err: bool
        :param expected: Expected return codes (0 by default).
        :type expected: Iterable[int | proc_enums.ExitCodes]
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :param stdin: Pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param log_stdout: Log STDOUT during read.
        :type log_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param log_stderr: Log STDERR during read.
        :type log_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: str | bytes | pathlib.Path | None
        :param env: Defines the environment variables for the new process.
        :type env: Mapping[str | bytes, str | bytes] | None
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: Mapping[str | bytes, str | bytes] | None
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: type[exceptions.CalledProcessError]
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.
        :raises CalledProcessError: Unexpected exit code or stderr presents.

        .. versionchanged:: 1.2.0 Default timeout 1 hour.
        .. versionchanged:: 3.2.0 Exception class can be substituted.
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent.
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
            log_stdout=log_stdout,
            open_stderr=open_stderr,
            log_stderr=log_stderr,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            exception_class=exception_class,
            **kwargs,
        )
