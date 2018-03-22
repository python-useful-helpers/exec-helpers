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

import typing

import six

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


class ExecHelperTimeoutError(ExecHelperError):
    """Execution timeout."""

    __slots__ = ()


class ExecCalledProcessError(ExecHelperError):
    """Base class for process call errors."""

    __slots__ = ()

    @staticmethod
    def _makestr(data):  # type: (typing.Any) -> six.text_type
        """Make string from object."""
        if isinstance(data, six.binary_type):
            return data.decode('utf-8', errors='backslashreplace')
        elif isinstance(data, six.text_type):
            return data
        return repr(data)


class CalledProcessError(ExecCalledProcessError):
    """Exception for error on process calls."""

    __slots__ = (
        'cmd',
        'returncode',
        'expected',
        'stdout',
        'stderr'
    )

    def __init__(
        self,
        command,  # type: str
        returncode,  # type: typing.Union[int, proc_enums.ExitCodes]
        expected=None,  # type: typing.Optional[typing.List[_type_exit_codes]]
        stdout=None,  # type: typing.Any
        stderr=None  # type: typing.Any
    ):
        """Exception for error on process calls.

        :param command: command
        :type command: str
        :param returncode: return code
        :type returncode: typing.Union[int, proc_enums.ExitCodes]
        :param expected: expected return codes
        :type expected: typing.Optional[
            typing.List[typing.Union[int, proc_enums.ExitCodes]]
        ]
        :param stdout: stdout string or brief string
        :type stdout: typing.Any
        :param stderr: stderr string or brief string
        :type stderr: typing.Any
        """
        self.returncode = returncode
        expected = expected or [proc_enums.ExitCodes.EX_OK]
        self.expected = proc_enums.exit_codes_to_enums(expected)
        self.cmd = command
        self.stdout = stdout
        self.stderr = stderr
        message = (
            "Command {cmd!r} returned exit code {code} while "
            "expected {expected}".format(
                cmd=self._makestr(self.cmd),
                code=self.returncode,
                expected=self.expected
            ))
        if self.stdout:
            message += "\n\tSTDOUT:\n{}".format(self._makestr(self.stdout))
        if self.stderr:
            message += "\n\tSTDERR:\n{}".format(self._makestr(self.stderr))
        super(CalledProcessError, self).__init__(message)


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
        errors,  # type: _type_multiple_results,
        results,  # type: _type_multiple_results,
        expected=None,  # type: typing.Optional[typing.List[_type_exit_codes]]
    ):
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
        errors,  # type: _type_multiple_results,
        results,  # type: _type_multiple_results,
        expected=None,  # type: typing.Optional[typing.List[_type_exit_codes]]
    ):
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
