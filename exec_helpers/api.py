#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.

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

__all__ = ("ExecHelper", "ExecuteAsyncResult")

# Standard Library
import abc
import datetime
import logging
import re
import threading
import typing

# Exec-Helpers Implementation
from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import exec_result
from exec_helpers import proc_enums

ExecuteAsyncResult = typing.NamedTuple(
    "ExecuteAsyncResult",
    [
        ("interface", typing.Any),
        ("stdin", typing.Optional[typing.Any]),
        ("stderr", typing.Optional[typing.Any]),
        ("stdout", typing.Optional[typing.Any]),
        ("started", datetime.datetime),
    ],
)


# noinspection PyProtectedMember
class _ChRootContext:  # pylint: disable=protected-access
    """Context manager for call commands with chroot.

    .. versionadded:: 4.1.0
    """

    __slots__ = ("_conn", "_chroot_status", "_path")

    def __init__(self, conn: "ExecHelper", path: typing.Optional[str] = None) -> None:
        """Context manager for call commands with sudo.

        :param conn: connection instance
        :type conn: ExecHelper
        :param path: chroot path or None for no chroot
        :type path: typing.Optional[str]
        """
        self._conn = conn  # type: ExecHelper
        self._chroot_status = conn._chroot_path  # type: typing.Optional[str]
        self._path = path  # type: typing.Optional[str]

    def __enter__(self) -> None:
        self._conn.__enter__()
        self._chroot_status = self._conn._chroot_path
        self._conn._chroot_path = self._path

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        self._conn._chroot_path = self._chroot_status
        self._conn.__exit__(exc_type=exc_type, exc_val=exc_val, exc_tb=exc_tb)  # type: ignore


class ExecHelper(metaclass=abc.ABCMeta):
    """ExecHelper global API."""

    __slots__ = ("__lock", "__logger", "log_mask_re", "__chroot_path")

    def __init__(self, log_mask_re: typing.Optional[str] = None, *, logger: logging.Logger) -> None:
        """Global ExecHelper API.

        :param logger: logger instance to use
        :type logger: logging.Logger
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 1.3.5 make API public to use as interface
        .. versionchanged:: 3.5.3 support chroot
        """
        self.__lock = threading.RLock()
        self.__logger = logger
        self.log_mask_re = log_mask_re
        self.__chroot_path = None  # type: typing.Optional[str]

    @property
    def logger(self) -> logging.Logger:
        """Instance logger access.

        :returns: logger instance
        """
        return self.__logger

    @property
    def lock(self) -> threading.RLock:
        """Lock.

        :rtype: threading.RLock
        """
        return self.__lock

    @property
    def _chroot_path(self) -> typing.Optional[str]:
        """Path for chroot if set.

        :rtype: typing.Optional[str]
        .. versionadded:: 3.5.3
        """
        return self.__chroot_path

    @_chroot_path.setter
    def _chroot_path(self, new_state: typing.Optional[str]) -> None:
        """Path for chroot if set.

        :param new_state: new path
        :type new_state: typing.Optional[str]
        .. versionadded:: 3.5.3
        """
        self.__chroot_path = new_state

    @_chroot_path.deleter
    def _chroot_path(self) -> None:
        """Remove Path for chroot.

        .. versionadded:: 3.5.3
        """
        self.__chroot_path = None

    def chroot(self, path: typing.Union[str, None]) -> "typing.ContextManager[None]":
        """Context manager for changing chroot rules.

        :param path: chroot path or none for working without chroot.
        :type path: typing.Optional[str]
        :return: context manager with selected chroot state inside
        :rtype: typing.ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 3.5.3
        """
        return _ChRootContext(conn=self, path=path)

    def __enter__(self) -> "ExecHelper":
        """Get context manager.

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

        def mask(text: str, rules: str) -> str:
            """Mask part of text using rules.

            :param text: source text
            :param rules: regex rules to mask.
            :returns: source with all MATCHED groups replaced by '<*masked*>'
            """
            indexes = [0]  # Start of the line
            masked = ""

            # places to exclude
            for match in re.finditer(rules, text):
                for idx, _ in enumerate(match.groups()):
                    indexes.extend(match.span(idx + 1))
            indexes.append(len(text))  # End

            # Replace inserts
            for idx in range(0, len(indexes) - 2, 2):
                start = indexes[idx]
                end = indexes[idx + 1]
                masked += text[start:end] + "<*masked*>"

            # noinspection PyPep8
            masked += text[indexes[-2] : indexes[-1]]  # final part
            return masked

        result = cmd.rstrip()  # type: str

        if self.log_mask_re is not None:
            result = mask(result, self.log_mask_re)
        if log_mask_re is not None:
            result = mask(result, log_mask_re)

        return result

    def _prepare_command(self, cmd: str, chroot_path: typing.Optional[str] = None) -> str:
        """Prepare command: cower chroot and other cases.

        :param cmd: main command
        :param chroot_path: path to make chroot for execution
        :returns: final command, includes chroot, if required
        """
        if any((chroot_path, self._chroot_path)):
            return "chroot {chroot_path} {cmd}".format(
                chroot_path=chroot_path if chroot_path else self._chroot_path, cmd=cmd
            )
        return cmd

    @abc.abstractmethod
    def execute_async(
        self,
        command: str,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        *,
        chroot_path: typing.Optional[str] = None,
        **kwargs: typing.Any
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
        :param verbose: produce verbose log record on command call
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
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
        .. versionchanged:: 3.5.3 support chroot
        """

    @abc.abstractmethod
    def _exec_command(
        self,
        command: str,
        async_result: ExecuteAsyncResult,
        timeout: typing.Union[int, float, None],
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        *,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        **kwargs: typing.Any
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
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """

    def execute(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        **kwargs: typing.Any
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
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

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        """
        async_result = self.execute_async(
            command, verbose=verbose, log_mask_re=log_mask_re, stdin=stdin, **kwargs
        )  # type: ExecuteAsyncResult

        result = self._exec_command(
            command=command,
            async_result=async_result,
            timeout=timeout,
            verbose=verbose,
            log_mask_re=log_mask_re,
            stdin=stdin,
            **kwargs
        )  # type: exec_result.ExecResult
        message = "Command {result.cmd!r} exit code: {result.exit_code!s}".format(result=result)
        self.logger.log(level=logging.INFO if verbose else logging.DEBUG, msg=message)
        return result

    def __call__(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        **kwargs: typing.Any
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
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

        .. versionadded:: 2.9.4
        """
        return self.execute(
            command=command, verbose=verbose, timeout=timeout, log_mask_re=log_mask_re, stdin=stdin, **kwargs
        )

    def check_call(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]] = (proc_enums.EXPECTED,),
        raise_on_err: bool = True,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        exception_class: "typing.Type[exceptions.CalledProcessError]" = exceptions.CalledProcessError,
        **kwargs: typing.Any
    ) -> exec_result.ExecResult:
        """Execute command and check for return code.

        :param command: Command for execution
        :type command: str
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
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[exceptions.CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.9.3 Exception class can be substituted
        .. versionchanged:: 2.10.0 Expected is not optional, defaults os dependent
        """
        expected_codes = proc_enums.exit_codes_to_enums(expected)
        result = self.execute(
            command, verbose, timeout, log_mask_re=log_mask_re, stdin=stdin, **kwargs
        )  # type: exec_result.ExecResult
        if result.exit_code not in expected_codes:
            message = (
                "{append}Command {result.cmd!r} returned exit code "
                "{result.exit_code!s} while expected {expected!s}".format(
                    append=error_info + "\n" if error_info else "", result=result, expected=expected_codes
                )
            )
            self.logger.error(msg=message)
            if raise_on_err:
                raise exception_class(result=result, expected=expected_codes)
        return result

    def check_stderr(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        raise_on_err: bool = True,
        *,
        expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]] = (proc_enums.EXPECTED,),
        log_mask_re: typing.Optional[str] = None,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        exception_class: "typing.Type[exceptions.CalledProcessError]" = exceptions.CalledProcessError,
        **kwargs: typing.Any
    ) -> exec_result.ExecResult:
        """Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution
        :type command: str
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
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[exceptions.CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.9.3 Exception class can be substituted
        .. versionchanged:: 2.10.0 Expected is not optional, defaults os dependent
        """
        result = self.check_call(
            command,
            verbose,
            timeout=timeout,
            error_info=error_info,
            raise_on_err=raise_on_err,
            expected=expected,
            exception_class=exception_class,
            log_mask_re=log_mask_re,
            stdin=stdin,
            **kwargs
        )
        append = error_info + "\n" if error_info else ""  # type: str
        if result.stderr:
            message = (
                "{append}Command {result.cmd!r} output contains STDERR while not expected\n"
                "\texit code: {result.exit_code!s}".format(append=append, result=result)
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
        raise TypeError(  # pragma: no cover
            "{!r} has unexpected type: not conform to Union[str, bytes, bytearray]".format(src)
        )
