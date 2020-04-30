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

"""ExecHelpers global API.

.. versionadded:: 1.2.0
.. versionchanged:: 1.3.5 make API public to use as interface
"""

__all__ = (
    "ExecHelper",
    "ExecuteAsyncResult",
    "mask_command",
    "CalledProcessErrorSubClassT",
    "OptionalStdinT",
    "OptionalTimeoutT",
    "CommandT",
)

# Standard Library
import typing
from abc import ABCMeta
from abc import abstractmethod
from logging import DEBUG
from logging import INFO
from pathlib import Path
from re import finditer
from shlex import quote
from threading import RLock

# Package Implementation
from exec_helpers.constants import DEFAULT_TIMEOUT
from exec_helpers.exceptions import CalledProcessError
from exec_helpers.proc_enums import EXPECTED
from exec_helpers.proc_enums import exit_codes_to_enums

if typing.TYPE_CHECKING:
    # pylint: disable=ungrouped-imports
    from datetime import datetime
    from logging import Logger
    from exec_helpers.exec_result import ExecResult
    from exec_helpers.proc_enums import ExitCodeT

CommandT = typing.TypeVar("CommandT", str, typing.Iterable[str])
OptionalTimeoutT = typing.Union[int, float, None]
OptionalStdinT = typing.Union[bytes, str, bytearray, None]
CalledProcessErrorSubClassT = typing.Type[CalledProcessError]


class ExecuteAsyncResult(typing.NamedTuple):
    """ExecuteAsyncResult."""

    interface: typing.Any
    stdin: typing.Optional[typing.Any]
    stderr: typing.Optional[typing.Any]
    stdout: typing.Optional[typing.Any]
    started: "datetime"


# noinspection PyProtectedMember
class _ChRootContext(typing.ContextManager[None]):
    """Context manager for call commands with chroot.

    :param conn: connection instance
    :type conn: ExecHelper
    :param path: chroot path or None for no chroot
    :type path: typing.Optional[typing.Union[str, Path]]
    :raises TypeError: incorrect type of path variable

    .. versionadded:: 4.1.0
    """

    __slots__ = ("_conn", "_chroot_status", "_path")

    def __init__(self, conn: "ExecHelper", path: typing.Optional[typing.Union[str, Path]] = None) -> None:
        """Context manager for call commands with sudo.

        :raises TypeError: incorrect type of path variable
        """
        self._conn: "ExecHelper" = conn
        self._chroot_status: typing.Optional[str] = conn._chroot_path
        if path is None or isinstance(path, str):
            self._path: typing.Optional[str] = path
        elif isinstance(path, Path):
            self._path = path.as_posix()  # get absolute path
        else:
            raise TypeError(f"path={path!r} is not instance of Optional[Union[str, Path]]")

    def __enter__(self) -> None:
        self._conn.__enter__()
        self._chroot_status = self._conn._chroot_path
        self._conn._chroot_path = self._path

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        self._conn._chroot_path = self._chroot_status
        self._conn.__exit__(exc_type=exc_type, exc_val=exc_val, exc_tb=exc_tb)  # type: ignore


def mask_command(text: str, pattern: str) -> str:
    """Mask part of text using rules.

    :param text: source text
    :type text: str
    :param pattern: regex rules to mask.
    :type pattern: str
    :return: source with all MATCHED groups replaced by '<*masked*>'
    :rtype: str
    """
    masked: typing.List[str] = []

    # places to exclude
    prev = 0
    for match in finditer(pattern, text):
        for idx, _ in enumerate(match.groups(), start=1):
            start, end = match.span(idx)
            masked.append(text[prev:start])
            masked.append("<*masked*>")
            prev = end
    masked.append(text[prev:])

    return "".join(masked)


class ExecHelper(
    typing.Callable[..., "ExecResult"],  # type: ignore
    typing.ContextManager["ExecHelper"],
    metaclass=ABCMeta,
):
    """ExecHelper global API.

    :param logger: logger instance to use
    :type logger: Logger
    :param log_mask_re: regex lookup rule to mask command for logger.
                        all MATCHED groups will be replaced by '<*masked*>'
    :type log_mask_re: typing.Optional[str]

    .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
    .. versionchanged:: 1.3.5 make API public to use as interface
    .. versionchanged:: 4.1.0 support chroot
    """

    __slots__ = ("__lock", "__logger", "log_mask_re", "__chroot_path")

    def __init__(self, log_mask_re: typing.Optional[str] = None, *, logger: "Logger") -> None:
        """Global ExecHelper API."""
        self.__lock = RLock()
        self.__logger: "Logger" = logger
        self.log_mask_re: typing.Optional[str] = log_mask_re
        self.__chroot_path: typing.Optional[str] = None

    @property
    def logger(self) -> "Logger":
        """Instance logger access.

        :return: logger instance
        :rtype: Logger
        """
        return self.__logger

    @property
    def lock(self) -> RLock:
        """Lock.

        :rtype: RLock
        """
        return self.__lock

    @property
    def _chroot_path(self) -> typing.Optional[str]:
        """Path for chroot if set.

        :rtype: typing.Optional[str]
        .. versionadded:: 4.1.0
        """
        return self.__chroot_path

    @_chroot_path.setter
    def _chroot_path(self, new_state: typing.Optional[str]) -> None:
        """Path for chroot if set.

        :param new_state: new path
        :type new_state: typing.Optional[str]
        .. versionadded:: 4.1.0
        """
        self.__chroot_path = new_state

    @_chroot_path.deleter
    def _chroot_path(self) -> None:
        """Remove Path for chroot.

        .. versionadded:: 4.1.0
        """
        self.__chroot_path = None

    def chroot(self, path: typing.Union[str, Path, None]) -> "typing.ContextManager[None]":
        """Context manager for changing chroot rules.

        :param path: chroot path or none for working without chroot.
        :type path: typing.Optional[typing.Union[str, Path]]
        :return: context manager with selected chroot state inside
        :rtype: typing.ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 4.1.0
        """
        return _ChRootContext(conn=self, path=path)

    def __enter__(self) -> "ExecHelper":
        """Get context manager.

        :return: exec helper instance with entered context manager
        :rtype: ExecHelper

        .. versionchanged:: 1.1.0 lock on enter
        """
        self.lock.acquire()
        return self

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        """Context manager usage."""
        self.lock.release()

    def _mask_command(self, cmd: str, log_mask_re: typing.Optional[str] = None) -> str:
        """Log command with masking and return parsed cmd.

        :param cmd: command
        :type cmd: str
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :return: masked command
        :rtype: str

        .. versionadded:: 1.2.0
        """

        result: str = cmd.rstrip()

        if self.log_mask_re is not None:
            result = mask_command(result, self.log_mask_re)
        if log_mask_re is not None:
            result = mask_command(result, log_mask_re)

        return result

    @staticmethod
    def _cmd_to_string(command: CommandT) -> str:
        """Convert command to string for usage with shell.

        :param command: original command.
        :type command: typing.Union[str, typing.Iterable[str]]
        :return: command as single string
        :rtype: str
        """
        if isinstance(command, str):
            return command
        return " ".join(quote(elem) for elem in command)

    def _prepare_command(self, cmd: str, chroot_path: typing.Optional[str] = None) -> str:
        """Prepare command: cower chroot and other cases.

        :param cmd: main command
        :type cmd: str
        :param chroot_path: path to make chroot for execution
        :type chroot_path: typing.Optional[str]
        :return: final command, includes chroot, if required
        :rtype: str
        """
        target_path: typing.Optional[str] = chroot_path if chroot_path else self._chroot_path
        if target_path and target_path != "/":
            chroot_dst: str = quote(target_path.strip())
            quoted_command = quote(cmd)
            return f'chroot {chroot_dst} sh -c {quote(f"eval {quoted_command}")}'
        return cmd

    @abstractmethod
    def _execute_async(
        self,
        command: str,
        *,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        **kwargs: typing.Any,
    ) -> ExecuteAsyncResult:
        """Execute command in async mode and return remote interface with IO objects.

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
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: NamedTuple with control interface and file-like objects for STDIN/STDERR/STDOUT
        :rtype: typing.NamedTuple(
                    'ExecuteAsyncResult',
                    [
                        ('interface', typing.Any),
                        ('stdin', typing.Optional[typing.Any]),
                        ('stderr', typing.Optional[typing.Any]),
                        ('stdout', typing.Optional[typing.Any]),
                        ("started", datetime.datetime),
                    ]
                )

        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 stdin data
        .. versionchanged:: 2.1.0 Use typed NamedTuple as result
        .. versionchanged:: 4.1.0 support chroot
        .. versionchanged:: 6.0.0 command start log moved to execute, verbose and log_mask_re removed as unused
        """

    @abstractmethod
    def _exec_command(
        self,
        command: str,
        async_result: ExecuteAsyncResult,
        timeout: OptionalTimeoutT,
        *,
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        stdin: OptionalStdinT = None,
        **kwargs: typing.Any,
    ) -> "ExecResult":
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
        :rtype: "ExecResult"
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """

    def _log_command_execute(
        self,
        command: str,
        log_mask_re: typing.Union[str, None],
        log_level: int,
        chroot_path: typing.Optional[str] = None,
        **_: typing.Any,
    ) -> None:
        """Log command execution."""
        cmd_for_log: str = self._mask_command(cmd=command, log_mask_re=log_mask_re)
        target_path: typing.Optional[str] = chroot_path if chroot_path is not None else self._chroot_path
        chroot_info: str = "" if not target_path or target_path == "/" else f" (with chroot to: {target_path!r})"

        self.logger.log(level=log_level, msg=f"Executing command{chroot_info}:\n{cmd_for_log!r}\n")

    def execute(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = DEFAULT_TIMEOUT,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        **kwargs: typing.Any,
    ) -> "ExecResult":
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
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: "ExecResult"
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        .. versionchanged:: 7.0.0 Allow command as list of arguments. Command will be joined with components escaping.
        """
        log_level: int = INFO if verbose else DEBUG
        cmd = self._cmd_to_string(command)
        self._log_command_execute(command=cmd, log_mask_re=log_mask_re, log_level=log_level, **kwargs)
        async_result: ExecuteAsyncResult = self._execute_async(
            cmd,
            verbose=verbose,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            **kwargs,
        )

        result: "ExecResult" = self._exec_command(
            command=cmd,
            async_result=async_result,
            timeout=timeout,
            verbose=verbose,
            log_mask_re=log_mask_re,
            stdin=stdin,
            **kwargs,
        )
        self.logger.log(level=log_level, msg=f"Command {result.cmd!r} exit code: {result.exit_code!s}")
        return result

    def __call__(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = DEFAULT_TIMEOUT,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        **kwargs: typing.Any,
    ) -> "ExecResult":
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
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: "ExecResult"
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionadded:: 3.3.0
        """
        return self.execute(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            **kwargs,
        )

    def check_call(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        expected: "typing.Iterable[ExitCodeT]" = (EXPECTED,),
        raise_on_err: bool = True,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        exception_class: CalledProcessErrorSubClassT = CalledProcessError,
        **kwargs: typing.Any,
    ) -> "ExecResult":
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
        :type expected: typing.Iterable[typing.Union[int, ExitCodes]]
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
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: "ExecResult"
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        expected_codes: "typing.Sequence[ExitCodeT]" = exit_codes_to_enums(expected)
        result: "ExecResult" = self.execute(
            command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            **kwargs,
        )
        append: str = error_info + "\n" if error_info else ""
        if result.exit_code not in expected_codes:
            message = (
                f"{append}Command {result.cmd!r} returned exit code {result.exit_code!s} "
                f"while expected {expected_codes!s}"
            )
            self.logger.error(msg=message)
            if raise_on_err:
                raise exception_class(result=result, expected=expected_codes)
        return result

    def check_stderr(
        self,
        command: CommandT,
        verbose: bool = False,
        timeout: OptionalTimeoutT = DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        raise_on_err: bool = True,
        *,
        expected: "typing.Iterable[ExitCodeT]" = (EXPECTED,),
        log_mask_re: typing.Optional[str] = None,
        stdin: OptionalStdinT = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        exception_class: CalledProcessErrorSubClassT = CalledProcessError,
        **kwargs: typing.Any,
    ) -> "ExecResult":
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
        :type expected: typing.Iterable[typing.Union[int, ExitCodes]]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: "ExecResult"
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        result: "ExecResult" = self.check_call(
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
            open_stderr=open_stderr,
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
        result: "ExecResult",
        error_info: typing.Optional[str],
        raise_on_err: bool,
        expected: "typing.Iterable[ExitCodeT]",
        exception_class: CalledProcessErrorSubClassT,
    ) -> "ExecResult":
        """Internal check_stderr logic (synchronous).

        :param result: execution result for validation
        :type result: ExecResult
        :param error_info: optional additional error information
        :type error_info: typing.Optional[str]
        :param raise_on_err: raise `exception_class` in case of error
        :type raise_on_err: bool
        :param expected: iterable expected exit codes
        :type expected: typing.Iterable[ExitCodeT]
        :param exception_class: exception class for usage in case of errors (subclass of CalledProcessError)
        :type exception_class: CalledProcessErrorSubClassT
        :return: execution result
        :rtype: ExecResult
        :raises CalledProcessErrorSubClassT: stderr presents and raise_on_err enabled
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
    def _string_bytes_bytearray_as_bytes(src: typing.Union[str, bytes, bytearray]) -> bytes:
        """Get bytes string from string/bytes/bytearray union.

        :param src: source string or bytes-like object
        :return: Byte string
        :rtype: bytes
        :raises TypeError: unexpected source type.
        """
        if isinstance(src, bytes):
            return src
        if isinstance(src, bytearray):
            return bytes(src)
        if isinstance(src, str):
            return src.encode("utf-8")
        raise TypeError(f"{src!r} has unexpected type: not conform to Union[str, bytes, bytearray]")  # pragma: no cover
