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

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import typing

from exec_helpers import proc_enums

__all__ = (
    'ExecHelperError',
    'ExecHelperTimeoutError',
    'ExecCalledProcessError',
    'CalledProcessError',
    'ParallelCallProcessError',
    'ParallelCallExceptions',
)

_type_exit_codes = typing.Union[int, proc_enums.ExitCodes]
_type_multiple_results = typing.Dict[typing.Tuple[str, int], typing.Any]


class ExecHelperError(Exception):
    """Base class for all exceptions raised inside."""

    __slots__ = ()


class DeserializeValueError(ExecHelperError, ValueError):
    """Deserialize impossible."""

    __slots__ = ()


class ExecHelperTimeoutError(ExecHelperError):
    """Execution timeout."""

    __slots__ = ()


class ExecCalledProcessError(ExecHelperError):
    """Base class for process call errors."""

    __slots__ = ()


class CalledProcessError(ExecCalledProcessError):
    """Exception for error on process calls."""

    __slots__ = (
        'result',
        'expected',
    )

    def __init__(
        self,
        result=None,  # type: exec_result.ExecResult
        expected=None,  # type: typing.Optional[typing.List[_type_exit_codes]]
    ):  # type: (...) -> None
        """Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param expected: expected return codes
        :type expected: typing.Optional[
            typing.List[typing.Union[int, proc_enums.ExitCodes]]
        ]

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
            "\tSTDERR:\n{result.stderr_brief}".format(
                result=result,
                expected=self.expected
            )
        )
        super(CalledProcessError, self).__init__(message)

    @property
    def returncode(
        self
    ):  # type: () -> typing.Union[int, proc_enums.ExitCodes]
        """Command return code."""
        return self.result.exit_code

    @property
    def cmd(self):  # type: () -> str
        """Failed command."""
        return self.result.cmd

    @property
    def stdout(self):  # type: () -> str
        """Command stdout."""
        return self.result.stdout_str

    @property
    def stderr(self):  # type: () -> str
        """Command stderr."""
        return self.result.stderr_str


class ParallelCallExceptions(ExecCalledProcessError):
    """Exception raised during parallel call as result of exceptions."""

    __slots__ = (
        'cmd',
        'exceptions',
        'errors',
        'results',
        'expected'
    )

    def __init__(
        self,
        command,  # type: str
        exceptions,  # type: typing.Dict[typing.Tuple[str, int], Exception]
        errors,  # type: _type_multiple_results
        results,  # type: _type_multiple_results
        expected=None,  # type: typing.Optional[typing.List[_type_exit_codes]]
    ):  # type: (...) -> None
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
        :type expected: typing.Optional[typing.List[
            typing.List[typing.Union[int, proc_enums.ExitCodes]]
        ]
        """
        expected = expected or [proc_enums.ExitCodes.EX_OK]
        self.expected = proc_enums.exit_codes_to_enums(expected)
        self.cmd = command
        self.exceptions = exceptions
        self.errors = errors
        self.results = results
        message = (
            "Command {self.cmd!r} "
            "during execution raised exceptions: \n"
            "\t{exceptions}".format(
                self=self,
                exceptions="\n\t".join(
                    "{host}:{port} - {exc} ".format(
                        host=host, port=port, exc=exc
                    )
                    for (host, port), exc in exceptions.items()
                )
            )
        )
        super(ParallelCallExceptions, self).__init__(message)


class ParallelCallProcessError(ExecCalledProcessError):
    """Exception during parallel execution."""

    __slots__ = (
        'cmd',
        'errors',
        'results',
        'expected'
    )

    def __init__(
        self,
        command,  # type: str
        errors,  # type: _type_multiple_results
        results,  # type: _type_multiple_results
        expected=None,  # type: typing.Optional[typing.List[_type_exit_codes]]
    ):  # type: (...) -> None
        """Exception during parallel execution.

        :param command: command
        :type command: str
        :param errors: results with errors
        :type errors: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param results: all results
        :type results: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: typing.Optional[typing.List[
            typing.List[typing.Union[int, proc_enums.ExitCodes]]
        ]
        """
        expected = expected or [proc_enums.ExitCodes.EX_OK]
        self.expected = proc_enums.exit_codes_to_enums(expected)
        self.cmd = command
        self.errors = errors
        self.results = results
        message = (
            "Command {self.cmd!r} "
            "returned unexpected exit codes on several hosts\n"
            "Expected: {self.expected}\n"
            "Got:\n"
            "\t{errors}".format(
                self=self,
                errors="\n\t".join(
                    "{host}:{port} - {code} ".format(
                        host=host, port=port, code=result.exit_code
                    )
                    for (host, port), result in errors.items()
                )
            )
        )
        super(ParallelCallProcessError, self).__init__(message)
