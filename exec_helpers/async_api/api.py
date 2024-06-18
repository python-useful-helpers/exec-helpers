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

"""Async API.

.. versionadded:: 3.0.0
"""

from __future__ import annotations

import abc
import asyncio
import logging
import pathlib
import typing

from exec_helpers import api
from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import proc_enums
from exec_helpers.api import CalledProcessErrorSubClassT
from exec_helpers.api import ChRootPathSetT
from exec_helpers.api import CommandT
from exec_helpers.api import ErrorInfoT
from exec_helpers.api import ExpectedExitCodesT
from exec_helpers.api import LogMaskReT
from exec_helpers.api import OptionalStdinT
from exec_helpers.api import OptionalTimeoutT

from .. import _helpers

if typing.TYPE_CHECKING:
    import types
    from collections.abc import Sequence

    from typing_extensions import Self

    from exec_helpers.async_api import exec_result
    from exec_helpers.proc_enums import ExitCodeT

__all__ = (
    "CalledProcessErrorSubClassT",
    "ChRootPathSetT",
    "CommandT",
    "ErrorInfoT",
    "ExecHelper",
    "ExpectedExitCodesT",
    "LogMaskReT",
    "OptionalStdinT",
    "OptionalTimeoutT",
)


class ExecuteContext(typing.AsyncContextManager[api.ExecuteAsyncResult], abc.ABC):
    """Execute context manager."""

    __slots__ = (
        "__command",
        "__logger",
        "__open_stderr",
        "__open_stdout",
        "__stdin",
    )

    def __init__(
        self,
        *,
        command: str,
        stdin: bytes | None = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        logger: logging.Logger,
        **kwargs: typing.Any,
    ) -> None:
        """Execute async context manager.

        :param command: Command for execution (fully formatted).
        :type command: str
        :param stdin: Pass STDIN text to the process (fully formatted).
        :type stdin: bytes
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param logger: Logger instance.
        :type logger: logging.Logger
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        """
        self.__command = command
        self.__stdin = stdin
        self.__open_stdout = open_stdout
        self.__open_stderr = open_stderr
        self.__logger = logger
        if kwargs:
            self.__logger.warning(f"Unexpected arguments: {kwargs!r}.", stack_info=True)

    @property
    def logger(self) -> logging.Logger:
        """Instance logger.

        :return: Logger.
        :rtype: logging.Logger
        """
        return self.__logger

    @property
    def command(self) -> str:
        """Command for execution (fully formatted).

        :return: Command as string.
        :rtype: str
        """
        return self.__command

    @property
    def stdin(self) -> bytes | None:
        """Pass STDIN text to the process (fully formatted).

        :return: pass STDIN text to the process
        :rtype: str | None
        """
        return self.__stdin

    @property
    def open_stdout(self) -> bool:
        """Open STDOUT stream for read.

        :return: Open STDOUT for handling.
        :rtype: bool
        """
        return self.__open_stdout

    @property
    def open_stderr(self) -> bool:
        """Open STDERR stream for read.

        :return: Open STDERR for handling.
        :rtype: bool
        """
        return self.__open_stderr


# noinspection PyProtectedMember
class _ChRootContext(typing.AsyncContextManager[None]):
    """Async extension for chroot.

    :param conn: Connection instance.
    :type conn: ExecHelper
    :param path: chroot path or None for no chroot.
    :type path: str | pathlib.Path | None
    :param chroot_exe: chroot executable.
    :type chroot_exe: str | None
    :raises TypeError: incorrect type of path or chroot_exe variable.
    """

    def __init__(self, conn: ExecHelper, path: ChRootPathSetT = None, chroot_exe: str | None = None) -> None:
        """Context manager for call commands with sudo.

        :raises TypeError: incorrect type of path or chroot_exe variable
        """
        self._conn: ExecHelper = conn
        self._chroot_status: str | None = conn._chroot_path
        self._chroot_exe_status: str | None = conn._chroot_exe
        if path is None or isinstance(path, str):
            self._path: str | None = path
        elif isinstance(path, pathlib.Path):
            self._path = path.as_posix()  # get an absolute path
        else:
            raise TypeError(f"path={path!r} is not instance of {ChRootPathSetT}")
        if chroot_exe is None or isinstance(chroot_exe, str):
            self._exe: str | None = chroot_exe
        else:
            raise TypeError(f"chroot_exe={chroot_exe!r} is not None or instance of str")

    async def __aenter__(self) -> None:
        await self._conn.__aenter__()
        self._chroot_status = self._conn._chroot_path
        self._conn._chroot_path = self._path
        self._chroot_exe_status = self._conn._chroot_exe
        self._conn._chroot_exe = self._exe

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self._conn._chroot_path = self._chroot_status
        self._conn._chroot_exe = self._chroot_exe_status
        await self._conn.__aexit__(exc_type=exc_type, exc_val=exc_val, exc_tb=exc_tb)


class ExecHelper(
    typing.Callable[..., typing.Awaitable["ExecHelper"]],  # type: ignore[misc]
    typing.AsyncContextManager["ExecHelper"],
    abc.ABC,
):
    """Subprocess helper with timeouts and lock-free FIFO.

    :param logger: Logger instance to use.
    :type logger: logging.Logger
    :param log_mask_re: Regex lookup rule to mask command for logger.
                        All MATCHED groups will be replaced by '<*masked*>'.
    :type log_mask_re: str | re.Pattern[str] | None
    """

    __slots__ = ("__alock", "__chroot_exe", "__chroot_path", "__logger", "log_mask_re")

    def __init__(self, log_mask_re: LogMaskReT = None, *, logger: logging.Logger) -> None:
        """Subprocess helper with timeouts and lock-free FIFO."""
        self.__alock: asyncio.Lock | None = None
        self.__logger: logging.Logger = logger
        self.log_mask_re: LogMaskReT = log_mask_re
        self.__chroot_path: str | None = None
        self.__chroot_exe: str | None = None

    @property
    def logger(self) -> logging.Logger:
        """Instance logger access.

        :return: Logger instance.
        :rtype: logging.Logger
        """
        return self.__logger

    @property
    def _chroot_path(self) -> str | None:
        """Path for chroot if set.

        :rtype: str | None
        .. versionadded:: 4.1.0
        """
        return self.__chroot_path

    @_chroot_path.setter
    def _chroot_path(self, new_state: ChRootPathSetT) -> None:
        """Path for chroot if set.

        :param new_state: New path.
        :type new_state: str | None
        :raises TypeError: Not supported path information.
        .. versionadded:: 4.1.0
        """
        if new_state is None or isinstance(new_state, str):
            self.__chroot_path = new_state
        elif isinstance(new_state, pathlib.Path):
            self.__chroot_path = new_state.as_posix()
        else:
            raise TypeError(f"chroot_path is expected to be string, but set {new_state!r}")

    @_chroot_path.deleter
    def _chroot_path(self) -> None:
        """Remove Path for chroot.

        .. versionadded:: 4.1.0
        """
        self.__chroot_path = None

    @property
    def _chroot_exe(self) -> str | None:
        """Exe for chroot

        :rtype: str | None
        .. versionadded:: 8.1.0
        """
        return self.__chroot_exe

    @_chroot_exe.setter
    def _chroot_exe(self, new_state: str | None) -> None:
        """Executable for chroot if set.

        :param new_state: New exe.
        :type new_state: str | None
        :raises TypeError: Not supported exe information.
        .. versionadded:: 8.1.0
        """
        if new_state is None or isinstance(new_state, str):
            self.__chroot_exe = new_state
        else:
            raise TypeError(f"chroot_exe is expected to be None or string, but set {new_state!r}")

    @_chroot_exe.deleter
    def _chroot_exe(self) -> None:
        """Restore chroot executable.

        .. versionadded:: 8.1.0
        """
        self.__chroot_exe = None

    def chroot(self, path: ChRootPathSetT, chroot_exe: str | None = None) -> _ChRootContext:
        """Context manager for changing chroot rules.

        :param path: chroot path or none for working without chroot.
        :type path: str | pathlib.Path | None
        :param chroot_exe: chroot executable.
        :type chroot_exe: str | None
        :return: Context manager with selected chroot state inside.
        :rtype: typing.ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 4.1.0
        """
        return _ChRootContext(conn=self, path=path, chroot_exe=chroot_exe)

    async def __aenter__(self) -> Self:
        """Async context manager.

        :return: exec helper Instance with async entered context manager.
        :rtype: ExecHelper
        """
        if self.__alock is None:
            self.__alock = asyncio.Lock()
        await self.__alock.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Async context manager."""
        if self.__alock is not None:
            self.__alock.release()

    def _mask_command(self, cmd: str, log_mask_re: LogMaskReT = None) -> str:
        """Log command with masking and return parsed cmd.

        :param cmd: Command.
        :type cmd: str
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :return: masked command.
        :rtype: str

        .. versionadded:: 1.2.0
        """

        return _helpers.mask_command(cmd.rstrip(), self.log_mask_re, log_mask_re)

    def _prepare_command(self, cmd: str, chroot_path: str | None = None, chroot_exe: str | None = None) -> str:
        """Prepare command: cower chroot and other cases.

        :param cmd: Main command.
        :type cmd: str
        :param chroot_path: Path to make chroot for execution.
        :type chroot_path: str | None
        :param chroot_exe: chroot exe override
        :type chroot_exe: str | None
        :return: Final command, includes chroot, if required.
        :rtype: str
        """
        return _helpers.chroot_command(
            cmd,
            chroot_path=chroot_path or self._chroot_path,
            chroot_exe=chroot_exe or self._chroot_exe,
        )

    @abc.abstractmethod
    async def _exec_command(
        self,
        command: str,
        async_result: api.ExecuteAsyncResult,
        timeout: OptionalTimeoutT,
        *,
        verbose: bool = False,
        log_mask_re: LogMaskReT = None,
        stdin: OptionalStdinT = None,
        log_stdout: bool = True,
        log_stderr: bool = True,
        **kwargs: typing.Any,
    ) -> exec_result.ExecResult:
        """Get exit status from channel with timeout.

        :param command: Command for execution.
        :type command: str
        :param async_result: execute_async result.
        :type async_result: ExecuteAsyncResult
        :param timeout: Timeout for command execution.
        :type timeout: int | float | None
        :param verbose: Produce verbose log record on command call.
        :type verbose: bool
        :param log_mask_re: Regex lookup rule to mask command for logger.
                            All MATCHED groups will be replaced by '<*masked*>'.
        :type log_mask_re: str | re.Pattern[str] | None
        :param stdin: Pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param log_stdout: Log STDOUT during read.
        :type log_stdout: bool
        :param log_stderr: Log STDERR during read.
        :type log_stderr: bool
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises OSError: Exception during process kill (and not regarding already closed process).
        :raises ExecHelperTimeoutError: Timeout exceeded.
        """

    def _log_command_execute(
        self,
        command: str,
        log_mask_re: LogMaskReT,
        log_level: int,
        chroot_path: str | None = None,
        **_: typing.Any,
    ) -> None:
        """Log command execution."""
        cmd_for_log: str = self._mask_command(cmd=command, log_mask_re=log_mask_re)
        target_path: str | None = chroot_path if chroot_path is not None else self._chroot_path
        chroot_info: str = "" if not target_path or target_path == "/" else f" (with chroot to: {target_path!r})"

        self.logger.log(level=log_level, msg=f"Executing command{chroot_info}:\n{cmd_for_log!r}\n")

    @abc.abstractmethod
    def open_execute_context(
        self,
        command: str,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: str | None = None,
        chroot_exe: str | None = None,
        **kwargs: typing.Any,
    ) -> ExecuteContext:
        """Get execution context manager.

        :param command: Command for execution.
        :type command: str | Iterable[str]
        :param stdin: Pass STDIN text to the process.
        :type stdin: bytes | str | bytearray | None
        :param open_stdout: Open STDOUT stream for read.
        :type open_stdout: bool
        :param open_stderr: Open STDERR stream for read.
        :type open_stderr: bool
        :param chroot_path: Chroot path override.
        :type chroot_path: str | None
        :param chroot_exe: Chroot exe override.
        :type chroot_exe: str | None
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        .. versionadded:: 8.0.0
        """

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
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.

        .. versionchanged:: 7.0.0 Allow command as list of arguments. Command will be joined with components escaping.
        .. versionchanged:: 8.0.0 chroot path exposed.
        .. versionchanged:: 8.1.0 chroot_exe added.
        """
        log_level: int = logging.INFO if verbose else logging.DEBUG
        cmd = _helpers.cmd_to_string(command)
        self._log_command_execute(
            command=cmd,
            log_mask_re=log_mask_re,
            log_level=log_level,
            chroot_path=chroot_path,
            **kwargs,
        )
        async with self.open_execute_context(
            cmd,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            chroot_path=chroot_path,
            chroot_exe=chroot_exe,
            **kwargs,
        ) as async_result:
            result: exec_result.ExecResult = await self._exec_command(
                command=cmd,
                async_result=async_result,
                timeout=timeout,
                verbose=verbose,
                log_mask_re=log_mask_re,
                stdin=stdin,
                log_stdout=log_stdout,
                log_stderr=log_stderr,
                **kwargs,
            )
        self.logger.log(level=log_level, msg=f"Command {result.cmd!r} exit code: {result.exit_code!s}")
        return result

    async def __call__(  # pylint: disable=invalid-overridden-method
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
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.

        .. versionadded:: 3.3.0
        """
        return await self.execute(
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
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: type[exceptions.CalledProcessError]
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.
        :raises CalledProcessError: Unexpected exit code.

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        expected_codes: Sequence[ExitCodeT] = proc_enums.exit_codes_to_enums(expected)
        result: exec_result.ExecResult = await self.execute(
            command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            log_stdout=log_stdout,
            open_stderr=open_stderr,
            log_stderr=log_stderr,
            **kwargs,
        )
        result.check_exit_code(
            expected_codes,
            raise_on_err,
            error_info=error_info,
            exception_class=exception_class,
            logger=self.logger,
        )
        return result

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
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: type[exceptions.CalledProcessError]
        :param kwargs: Additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result.
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded.
        :raises CalledProcessError: Unexpected exit code or stderr presents.

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        result: exec_result.ExecResult = await self.check_call(
            command,
            verbose=verbose,
            timeout=timeout,
            error_info=error_info,
            raise_on_err=raise_on_err,
            expected=expected,
            exception_class=exception_class,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            log_stdout=log_stdout,
            open_stderr=open_stderr,
            log_stderr=log_stderr,
            **kwargs,
        )
        return self._handle_stderr(
            result=result,
            error_info=error_info,
            raise_on_err=raise_on_err,
            expected=expected,
            exception_class=exception_class,
        )

    def _handle_stderr(
        self,
        *,
        result: exec_result.ExecResult,
        error_info: ErrorInfoT,
        raise_on_err: bool,
        expected: ExpectedExitCodesT,
        exception_class: CalledProcessErrorSubClassT,
    ) -> exec_result.ExecResult:
        """Internal check_stderr logic (synchronous).

        :param result: Execution result for validation.
        :type result: exec_result.ExecResult
        :param error_info: Optional additional error information.
        :type error_info: str | None
        :param raise_on_err: Raise `exception_class` in case of error.
        :type raise_on_err: bool
        :param expected: Iterable expected exit codes.
        :type expected: Iterable[int | ExitCodes]
        :param exception_class: Exception class for usage in case of errors (subclass of CalledProcessError).
        :type exception_class: type[exceptions.CalledProcessError]
        :return: Execution result.
        :rtype: exec_result.ExecResult
        :raises exceptions.CalledProcessError: STDERR presents and raise_on_err enabled.
        """
        append: str = error_info + "\n" if error_info else ""
        if result.stderr:
            message = (
                f"{append}Command {result.cmd!r} output contains STDERR while not expected\n"
                f"\texit code: {result.exit_code!s}"
            )
            self.logger.error(msg=message)
            if raise_on_err:
                raise exception_class(result=result, expected=expected)
        return result

    @staticmethod
    def _string_bytes_bytearray_as_bytes(src: str | bytes | bytearray) -> bytes:
        """Get bytes string from string/bytes/bytearray union.

        :param src: Source string or bytes-like object.
        :return: Byte string.
        :rtype: bytes
        :raises TypeError: unexpected source type.
        """
        return _helpers.string_bytes_bytearray_as_bytes(src)
