#    Copyright 2018 Alexey Stepanov aka penguinolog.

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

import abc
import logging
import re
import threading
import typing

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
    ],
)


class ExecHelper(metaclass=abc.ABCMeta):
    """ExecHelper global API."""

    __slots__ = ("__lock", "__logger", "log_mask_re")

    def __init__(self, logger: logging.Logger, log_mask_re: typing.Optional[str] = None) -> None:
        """Global ExecHelper API.

        :param logger: logger instance to use
        :type logger: logging.Logger
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 1.3.5 make API public to use as interface
        """
        self.__lock = threading.RLock()
        self.__logger = logger
        self.log_mask_re = log_mask_re

    @property
    def logger(self) -> logging.Logger:
        """Instance logger access."""
        return self.__logger

    @property
    def lock(self) -> threading.RLock:
        """Lock.

        :rtype: threading.RLock
        """
        return self.__lock

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
            """Mask part of text using rules."""
            indexes = [0]  # Start of the line

            # places to exclude
            for match in re.finditer(rules, text):
                for idx, _ in enumerate(match.groups()):
                    indexes.extend(match.span(idx + 1))
            indexes.append(len(text))  # End

            masked = ""

            # Replace inserts
            for idx in range(0, len(indexes) - 2, 2):
                start = indexes[idx]
                end = indexes[idx + 1]
                masked += text[start:end] + "<*masked*>"

            # noinspection PyPep8
            masked += text[indexes[-2] : indexes[-1]]  # final part
            return masked

        cmd = cmd.rstrip()

        if self.log_mask_re:
            cmd = mask(cmd, self.log_mask_re)
        if log_mask_re:
            cmd = mask(cmd, log_mask_re)

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
                    ]
                )

        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 stdin data
        .. versionchanged:: 2.1.0 Use typed NamedTuple as result
        """
        raise NotImplementedError  # pragma: no cover

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
        raise NotImplementedError  # pragma: no cover

    def execute(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        **kwargs: typing.Any
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        """
        async_result = self.execute_async(command, verbose=verbose, **kwargs)  # type: ExecuteAsyncResult

        result = self._exec_command(
            command=command, async_result=async_result, timeout=timeout, verbose=verbose, **kwargs
        )
        message = "Command {result.cmd!r} exit code: {result.exit_code!s}".format(result=result)
        self.logger.log(level=logging.INFO if verbose else logging.DEBUG, msg=message)  # type: ignore
        return result

    def __call__(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        **kwargs: typing.Any
    ) -> exec_result.ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionadded:: 3.3.0
        """
        return self.execute(command=command, verbose=verbose, timeout=timeout, **kwargs)

    def check_call(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]] = None,
        raise_on_err: bool = True,
        *,
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
        :type expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
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
        """
        expected_codes = proc_enums.exit_codes_to_enums(expected)
        ret = self.execute(command, verbose, timeout, **kwargs)
        if ret.exit_code not in expected_codes:
            message = (
                "{append}Command {result.cmd!r} returned exit code "
                "{result.exit_code!s} while expected {expected!s}".format(
                    append=error_info + "\n" if error_info else "", result=ret, expected=expected_codes
                )
            )
            self.logger.error(msg=message)
            if raise_on_err:
                raise exception_class(result=ret, expected=expected_codes)
        return ret

    def check_stderr(
        self,
        command: str,
        verbose: bool = False,
        timeout: typing.Union[int, float, None] = constants.DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        raise_on_err: bool = True,
        *,
        expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]] = None,
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
        :type expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]]
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
        """
        ret = self.check_call(
            command,
            verbose,
            timeout=timeout,
            error_info=error_info,
            raise_on_err=raise_on_err,
            expected=expected,
            exception_class=exception_class,
            **kwargs
        )
        if ret.stderr:
            message = (
                "{append}Command {result.cmd!r} output contains STDERR while not expected\n"
                "\texit code: {result.exit_code!s}".format(append=error_info + "\n" if error_info else "", result=ret)
            )
            self.logger.error(msg=message)
            if raise_on_err:
                raise exception_class(result=ret, expected=expected)
        return ret

    @staticmethod
    def _string_bytes_bytearray_as_bytes(src: typing.Union[str, bytes, bytearray]) -> bytes:
        """Get bytes string from string/bytes/bytearray union.

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
