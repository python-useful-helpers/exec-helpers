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

"""Package specific exceptions."""

import typing

from exec_helpers import proc_enums
from exec_helpers import _log_templates

if typing.TYPE_CHECKING:  # pragma: no cover
    from exec_helpers import exec_result  # noqa: F401  # pylint: disable=cyclic-import

__all__ = (
    "ExecHelperError",
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


class ExecHelperTimeoutError(ExecCalledProcessError):
    """Execution timeout.

    .. versionchanged:: 1.3.0 provide full result and timeout inside.
    .. versionchanged:: 1.3.0 subclass ExecCalledProcessError
    """

    __slots__ = ("result", "timeout")

    def __init__(self, result: "exec_result.ExecResult", timeout: typing.Union[int, float]) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]
        """
        message = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        super(ExecHelperTimeoutError, self).__init__(message)
        self.result = result
        self.timeout = timeout

    @property
    def cmd(self) -> str:
        """Failed command."""
        return self.result.cmd

    @property
    def stdout(self) -> str:
        """Command stdout."""
        return self.result.stdout_str

    @property
    def stderr(self) -> str:
        """Command stderr."""
        return self.result.stderr_str


class CalledProcessError(ExecCalledProcessError):
    """Exception for error on process calls."""

    __slots__ = ("result", "expected")

    def __init__(
        self,
        result: "exec_result.ExecResult",
        expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]] = None,
    ) -> None:
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param expected: expected return codes
        :type expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]]

        .. versionchanged:: 1.1.1 - provide full result
        """
        self.result = result
        expected = expected or [proc_enums.ExitCodes.EX_OK]
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
        """Command return code."""
        return self.result.exit_code

    @property
    def cmd(self) -> str:
        """Failed command."""
        return self.result.cmd

    @property
    def stdout(self) -> str:
        """Command stdout."""
        return self.result.stdout_str

    @property
    def stderr(self) -> str:
        """Command stderr."""
        return self.result.stderr_str


class ParallelCallProcessError(ExecCalledProcessError):
    """Exception during parallel execution."""

    __slots__ = ("cmd", "errors", "results", "expected")

    def __init__(
        self,
        command: str,
        errors: typing.Dict[typing.Tuple[str, int], "exec_result.ExecResult"],
        results: typing.Dict[typing.Tuple[str, int], "exec_result.ExecResult"],
        expected: typing.Optional[typing.List[typing.Union[int, proc_enums.ExitCodes]]] = None,
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
        :type expected: typing.Optional[typing.List[typing.Union[int, proc_enums.ExitCodes]]]
        :param _message: message override
        :type _message: typing.Optional[str]
        """
        expected = expected or [proc_enums.ExitCodes.EX_OK]
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
        expected: typing.Optional[typing.List[typing.Union[int, proc_enums.ExitCodes]]] = None,
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
        :type expected: typing.Optional[typing.List[typing.Union[int, proc_enums.ExitCodes]]]
        :param _message: message override
        :type _message: typing.Optional[str]
        """
        expected = expected or [proc_enums.ExitCodes.EX_OK]
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
