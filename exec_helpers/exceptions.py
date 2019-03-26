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

"""Package specific exceptions."""

__all__ = (
    "ExecHelperError",
    "ExecHelperNoKillError",
    "ExecHelperTimeoutError",
    "ExecCalledProcessError",
    "CalledProcessError",
    "ParallelCallProcessError",
    "ParallelCallExceptions",
)

# Standard Library
import typing

# Exec-Helpers Implementation
from exec_helpers import _log_templates
from exec_helpers import proc_enums

if typing.TYPE_CHECKING:  # pragma: no cover
    from exec_helpers import exec_result  # noqa: F401  # pylint: disable=cyclic-import


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

    def __init__(self, message: str, *, result: "exec_result.ExecResult", timeout: typing.Union[int, float]) -> None:
        """Exception for error on process calls.

        :param message: exception message
        :type message: str
        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        super(ExecHelperTimeoutProcessError, self).__init__(message)
        self.result = result
        self.timeout = timeout

    @property
    def cmd(self) -> str:
        """Failed command.

        :returns: command
        """
        return self.result.cmd

    @property
    def stdout(self) -> str:
        """Command stdout.

        :returns: command stdout as string
        """
        return self.result.stdout_str

    @property
    def stderr(self) -> str:
        """Command stderr.

        :returns: command stderr as string
        """
        return self.result.stderr_str


class ExecHelperNoKillError(ExecHelperTimeoutProcessError):
    """Impossible to kill process.

    .. versionadded:: 2.10.0
    """

    __slots__ = ()

    def __init__(self, result: "exec_result.ExecResult", timeout: typing.Union[int, float]) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        message = _log_templates.CMD_KILL_ERROR.format(result=result, timeout=timeout)
        super(ExecHelperNoKillError, self).__init__(message, result=result, timeout=timeout)


class ExecHelperTimeoutError(ExecHelperTimeoutProcessError):
    """Execution timeout.

    .. versionchanged:: 1.3.0 provide full result and timeout inside.
    .. versionchanged:: 1.3.0 subclass ExecCalledProcessError
    """

    __slots__ = ()

    def __init__(self, result: "exec_result.ExecResult", timeout: typing.Union[int, float]) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        message = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        super(ExecHelperTimeoutError, self).__init__(message, result=result, timeout=timeout)


class CalledProcessError(ExecCalledProcessError):
    """Exception for error on process calls."""

    __slots__ = ("result", "expected")

    def __init__(
        self,
        result: "exec_result.ExecResult",
        expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]] = (proc_enums.EXPECTED,),
    ) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param expected: expected return codes
        :type expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]

        .. versionchanged:: 1.1.1 - provide full result
        .. versionchanged:: 2.10.0 Expected is not optional, defaults os dependent
        """
        self.result = result
        self.expected = proc_enums.exit_codes_to_enums(expected)
        message = (
            "Command {result.cmd!r} returned exit code {result.exit_code} "
            "while expected {expected}\n"
            "\tSTDOUT:\n"
            "{result.stdout_brief}\n"
            "\tSTDERR:\n{result.stderr_brief}".format(result=self.result, expected=self.expected)
        )
        super(CalledProcessError, self).__init__(message)

    @property
    def returncode(self) -> typing.Union[int, proc_enums.ExitCodes]:
        """Command return code.

        :returns: command return code
        """
        return self.result.exit_code

    @property
    def cmd(self) -> str:
        """Failed command.

        :returns: command
        """
        return self.result.cmd

    @property
    def stdout(self) -> str:
        """Command stdout.

        :returns: command stdout as string
        """
        return self.result.stdout_str

    @property
    def stderr(self) -> str:
        """Command stderr.

        :returns: command stderr as string
        """
        return self.result.stderr_str


class ParallelCallProcessError(ExecCalledProcessError):
    """Exception during parallel execution."""

    __slots__ = ("cmd", "errors", "results", "expected")

    def __init__(
        self,
        command: str,
        errors: typing.Dict[typing.Tuple[str, int], "exec_result.ExecResult"],
        results: typing.Dict[typing.Tuple[str, int], "exec_result.ExecResult"],
        expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]] = (proc_enums.EXPECTED,),
        *,
        _message: typing.Optional[str] = None
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

        .. versionchanged:: 2.10.0 Expected is not optional, defaults os dependent
        """
        prep_expected = proc_enums.exit_codes_to_enums(expected)
        message = _message or (
            "Command {cmd!r} "
            "returned unexpected exit codes on several hosts\n"
            "Expected: {expected}\n"
            "Got:\n"
            "\t{errors}".format(
                cmd=command,
                expected=prep_expected,
                errors="\n\t".join(
                    "{host}:{port} - {code} ".format(host=host, port=port, code=result.exit_code)
                    for (host, port), result in errors.items()
                ),
            )
        )
        super(ParallelCallProcessError, self).__init__(message)
        self.cmd = command
        self.errors = errors
        self.results = results
        self.expected = prep_expected


class ParallelCallExceptions(ParallelCallProcessError):
    """Exception raised during parallel call as result of exceptions."""

    __slots__ = ("cmd", "exceptions")

    def __init__(
        self,
        command: str,
        exceptions: typing.Dict[typing.Tuple[str, int], Exception],
        errors: typing.Dict[typing.Tuple[str, int], "exec_result.ExecResult"],
        results: typing.Dict[typing.Tuple[str, int], "exec_result.ExecResult"],
        expected: typing.Iterable[typing.Union[int, proc_enums.ExitCodes]] = (proc_enums.EXPECTED,),
        *,
        _message: typing.Optional[str] = None
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

        .. versionchanged:: 2.10.0 Expected is not optional, defaults os dependent
        """
        prep_expected = proc_enums.exit_codes_to_enums(expected)
        message = _message or (
            "Command {cmd!r} "
            "during execution raised exceptions: \n"
            "\t{exceptions}".format(
                cmd=command,
                exceptions="\n\t".join(
                    "{host}:{port} - {exc} ".format(host=host, port=port, exc=exc)
                    for (host, port), exc in exceptions.items()
                ),
            )
        )
        super(ParallelCallExceptions, self).__init__(
            command=command, errors=errors, results=results, expected=prep_expected, _message=message
        )
        self.cmd = command
        self.exceptions = exceptions
