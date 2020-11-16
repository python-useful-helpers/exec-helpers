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

"""Package specific exceptions."""

from __future__ import annotations

# Standard Library
import typing

# Package Implementation
from exec_helpers import proc_enums
from exec_helpers.proc_enums import ExitCodeT

# Local Implementation
from . import _log_templates

if typing.TYPE_CHECKING:
    # Package Implementation
    from exec_helpers import exec_result  # noqa: F401  # pylint: disable=cyclic-import

__all__ = (
    "ExecHelperError",
    "ExecHelperNoKillError",
    "ExecHelperTimeoutError",
    "ExecCalledProcessError",
    "CalledProcessError",
    "ParallelCallProcessError",
    "ParallelCallExceptions",
)


class ExecHelperError(Exception):
    """Base class for all exceptions raised inside."""

    __slots__ = ()


class DeserializeValueError(ExecHelperError, ValueError):
    """Deserialize impossible."""

    __slots__ = ()


class ExecCalledProcessError(ExecHelperError):
    """Base class for process call errors."""

    __slots__ = ()


class ExecHelperTimeoutProcessError(ExecCalledProcessError):
    """Timeout based errors."""

    __slots__ = ("result", "timeout")

    def __init__(
        self,
        message: str,
        *,
        result: exec_result.ExecResult,
        timeout: typing.Union[int, float],
    ) -> None:
        """Exception for error on process calls.

        :param message: exception message
        :type message: str
        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        super().__init__(message)
        self.result: exec_result.ExecResult = result
        self.timeout: typing.Union[int, float] = timeout

    @property
    def cmd(self) -> str:
        """Failed command.

        :return: command
        """
        return self.result.cmd

    @property
    def stdout(self) -> str:
        """Command stdout.

        :return: command stdout as string
        """
        return self.result.stdout_str

    @property
    def stderr(self) -> str:
        """Command stderr.

        :return: command stderr as string
        """
        return self.result.stderr_str


class ExecHelperNoKillError(ExecHelperTimeoutProcessError):
    """Impossible to kill process.

    .. versionadded:: 3.4.0
    """

    __slots__ = ()

    def __init__(
        self,
        result: exec_result.ExecResult,
        timeout: typing.Union[int, float],
    ) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        message: str = (
            f"Wait for {result.cmd!r} during {timeout!s}s: "
            f"no return code and no response on SIGTERM + SIGKILL signals!\n"
            f"\tSTDOUT:\n"
            f"{result.stdout_brief}\n"
            f"\tSTDERR:\n"
            f"{result.stderr_brief}"
        )
        super().__init__(message, result=result, timeout=timeout)


class ExecHelperTimeoutError(ExecHelperTimeoutProcessError):
    """Execution timeout.

    .. versionchanged:: 1.3.0 provide full result and timeout inside.
    .. versionchanged:: 1.3.0 subclass ExecCalledProcessError
    """

    __slots__ = ()

    def __init__(
        self,
        result: exec_result.ExecResult,
        timeout: typing.Union[int, float],
    ) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        message: str = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        super().__init__(message, result=result, timeout=timeout)


class CalledProcessError(ExecCalledProcessError):
    """Exception for error on process calls."""

    __slots__ = ("result", "expected")

    def __init__(
        self,
        result: exec_result.ExecResult,
        expected: typing.Iterable[ExitCodeT] = (proc_enums.EXPECTED,),
    ) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param expected: expected return codes
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]

        .. versionchanged:: 1.1.1 - provide full result
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        self.result: exec_result.ExecResult = result
        self.expected: typing.Sequence[ExitCodeT] = proc_enums.exit_codes_to_enums(expected)
        message: str = (
            f"Command {result.cmd!r} returned exit code {result.exit_code} while expected {expected}\n"
            f"\tSTDOUT:\n"
            f"{result.stdout_brief}\n"
            f"\tSTDERR:\n{result.stderr_brief}"
        )
        super().__init__(message)

    @property
    def returncode(self) -> ExitCodeT:
        """Command return code.

        :return: command return code
        """
        return self.result.exit_code

    @property
    def cmd(self) -> str:
        """Failed command.

        :return: command
        """
        return self.result.cmd

    @property
    def stdout(self) -> str:
        """Command stdout.

        :return: command stdout as string
        """
        return self.result.stdout_str

    @property
    def stderr(self) -> str:
        """Command stderr.

        :return: command stderr as string
        """
        return self.result.stderr_str


class ParallelCallProcessError(ExecCalledProcessError):
    """Exception during parallel execution."""

    __slots__ = ("cmd", "errors", "results", "expected")

    def __init__(
        self,
        command: str,
        errors: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult],
        results: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult],
        expected: typing.Iterable[ExitCodeT] = (proc_enums.EXPECTED,),
        *,
        _message: typing.Optional[str] = None,
    ) -> None:
        """Exception during parallel execution.

        :param command: command
        :type command: str
        :param errors: results with errors
        :type errors: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param results: all results
        :type results: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]
        :param _message: message override
        :type _message: typing.Optional[str]

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        prep_expected: typing.Sequence[ExitCodeT] = proc_enums.exit_codes_to_enums(expected)
        errors_str: str = "\n\t".join(f"{host}:{port} - {result.exit_code} " for (host, port), result in errors.items())
        message: str = _message or (
            f"Command {command!r} returned unexpected exit codes on several hosts\n"
            f"Expected: {prep_expected}\n"
            f"Got:\n"
            f"\t{errors_str}"
        )
        super().__init__(message)
        self.cmd: str = command
        self.errors: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult] = errors
        self.results: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult] = results
        self.expected: typing.Sequence[ExitCodeT] = prep_expected


class ParallelCallExceptions(ParallelCallProcessError):
    """Exception raised during parallel call as result of exceptions."""

    __slots__ = ("cmd", "exceptions")

    def __init__(
        self,
        command: str,
        exceptions: typing.Dict[typing.Tuple[str, int], Exception],
        errors: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult],
        results: typing.Dict[typing.Tuple[str, int], exec_result.ExecResult],
        expected: typing.Iterable[ExitCodeT] = (proc_enums.EXPECTED,),
        *,
        _message: typing.Optional[str] = None,
    ) -> None:
        """Exception raised during parallel call as result of exceptions.

        :param command: command
        :type command: str
        :param exceptions: Exceptions on connections
        :type exceptions: typing.Dict[typing.Tuple[str, int], Exception]
        :param errors: results with errors
        :type errors: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param results: all results
        :type results: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]
        :param _message: message override
        :type _message: typing.Optional[str]

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        exceptions_str: str = "\n\t".join(f"{host}:{port} - {exc} " for (host, port), exc in exceptions.items())
        message: str = _message or f"Command {command!r} during execution raised exceptions: \n\t{exceptions_str}"
        super().__init__(
            command=command,
            errors=errors,
            results=results,
            expected=expected,
            _message=message,
        )
        self.cmd: str = command
        self.exceptions: typing.Dict[typing.Tuple[str, int], Exception] = exceptions
