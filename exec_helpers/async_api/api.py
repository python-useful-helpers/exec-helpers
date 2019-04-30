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

"""Async API.

.. versionadded:: 3.0.0
"""

__all__ = ("ExecHelper",)

# Standard Library
import abc
import asyncio
import logging
import typing

# Exec-Helpers Implementation
from exec_helpers import api
from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import exec_result
from exec_helpers import proc_enums


# noinspection PyProtectedMember
class _ChRootContext(api._ChRootContext):  # pylint: disable=protected-access
    """Async extension for chroot."""

    def __init__(self, conn: "ExecHelper", path: typing.Optional[str] = None) -> None:
        """Context manager for call commands with sudo.

        :param conn: connection instance
        :type conn: ExecHelper
        :param path: chroot path or None for no chroot
        :type path: typing.Optional[str]
        """
        super(_ChRootContext, self).__init__(conn=conn, path=path)

    async def __aenter__(self) -> None:
        await self._conn.__aenter__()  # type: ignore
        self._chroot_status = self._conn._chroot_path  # pylint: disable=protected-access
        self._conn._chroot_path = self._path  # pylint: disable=protected-access

    async def __aexit__(  # pylint: disable=protected-access
        self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any
    ) -> None:
        self._conn._chroot_path = self._chroot_status
        await self._conn.__aexit__(exc_type=exc_type, exc_val=exc_val, exc_tb=exc_tb)  # type: ignore


class ExecHelper(api.ExecHelper, metaclass=abc.ABCMeta):
    """Subprocess helper with timeouts and lock-free FIFO."""

    __slots__ = ("__alock",)

    def __init__(self, log_mask_re: typing.Optional[str] = None, *, logger: logging.Logger) -> None:
        """Subprocess helper with timeouts and lock-free FIFO.

        :param logger: logger instance to use
        :type logger: logging.Logger
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        """
        super(ExecHelper, self).__init__(logger=logger, log_mask_re=log_mask_re)
        self.__alock = None  # type: typing.Optional[asyncio.Lock]

    async def __aenter__(self) -> "ExecHelper":
        """Async context manager."""
        if self.__alock is None:
            self.__alock = asyncio.Lock()
        await self.__alock.acquire()
        return self

    async def __aexit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None:
        """Async context manager."""
        self.__alock.release()  # type: ignore

    def chroot(self, path: typing.Union[str, None]) -> "typing.ContextManager[None]":
        """Context manager for changing chroot rules.

        :param path: chroot path or none for working without chroot.
        :type path: typing.Optional[str]
        :return: context manager with selected chroot state inside
        :rtype: typing.ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 4.1.0
        """
        return _ChRootContext(conn=self, path=path)

    @abc.abstractmethod
    async def _exec_command(  # type: ignore
        self,
        command: str,
        async_result: api.ExecuteAsyncResult,
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
        :type async_result: ExecuteAsyncResult
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
        :raises ExecHelperTimeoutError: Timeout exceeded
        """

    @abc.abstractmethod
    async def execute_async(  # type: ignore
        self,
        command: str,
        stdin: typing.Union[str, bytes, bytearray, None] = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        *,
        chroot_path: typing.Optional[str] = None,
        **kwargs: typing.Any
    ) -> api.ExecuteAsyncResult:
        """Execute command in async mode and return Popen with IO objects.

        :param command: Command for execution
        :type command: str
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[str, bytes, bytearray, None]
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
        :return: Tuple with control interface and file-like objects for STDIN/STDERR/STDOUT
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
        :raises OSError: impossible to process STDIN
        """

    async def execute(  # type: ignore
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
        """
        async_result = await self.execute_async(
            command, verbose=verbose, log_mask_re=log_mask_re, stdin=stdin, **kwargs
        )  # type: api.ExecuteAsyncResult

        result = await self._exec_command(
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

    async def __call__(  # type: ignore
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

        .. versionadded:: 3.3.0
        """
        return await self.execute(
            command=command, verbose=verbose, timeout=timeout, log_mask_re=log_mask_re, stdin=stdin, **kwargs
        )

    async def check_call(  # type: ignore
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

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        expected_codes = proc_enums.exit_codes_to_enums(expected)
        result = await self.execute(command, verbose, timeout, log_mask_re=log_mask_re, stdin=stdin, **kwargs)
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

    async def check_stderr(  # type: ignore
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
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[exceptions.CalledProcessError]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        result = await self.check_call(
            command,
            verbose,
            timeout=timeout,
            error_info=error_info,
            raise_on_err=raise_on_err,
            log_mask_re=log_mask_re,
            expected=expected,
            exception_class=exception_class,
            stdin=stdin,
            **kwargs
        )
        if result.stderr:
            message = (
                "{append}Command {result.cmd!r} output contains STDERR while not expected\n"
                "\texit code: {result.exit_code!s}".format(
                    append=error_info + "\n" if error_info else "", result=result
                )
            )
            self.logger.error(msg=message)
            if raise_on_err:
                raise exception_class(result=result, expected=expected)
        return result
