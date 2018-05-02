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
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging
import re
import threading
import typing

import six  # noqa  # pylint: disable=unused-import

from exec_helpers import constants
from exec_helpers import exceptions
from exec_helpers import exec_result  # noqa  # pylint: disable=unused-import
from exec_helpers import proc_enums
from exec_helpers import _log_templates

_type_exit_codes = typing.Union[int, proc_enums.ExitCodes]
_type_expected = typing.Optional[typing.Iterable[_type_exit_codes]]


class ExecHelper(object):
    """ExecHelper global API."""

    __slots__ = (
        '__lock',
        '__logger',
        'log_mask_re'
    )

    def __init__(
        self,
        logger,  # type: logging.Logger
        log_mask_re=None,  # type: typing.Optional[str]
    ):  # type: (...) -> None
        """ExecHelper global API.

        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        self.__lock = threading.RLock()
        self.__logger = logger
        self.log_mask_re = log_mask_re

    @property
    def logger(self):  # type: () -> logging.Logger
        """Instance logger access."""
        return self.__logger

    @property
    def lock(self):  # type: () -> threading.RLock
        """Lock.

        :rtype: threading.RLock
        """
        return self.__lock

    def __enter__(self):
        """Get context manager.

        .. versionchanged:: 1.1.0 lock on enter
        """
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):  # pragma: no cover
        """Context manager usage."""
        self.lock.release()

    def _mask_command(
        self,
        cmd,  # type: str
        log_mask_re=None,  # type: typing.Optional[str]
    ):  # type: (...) -> str
        """Log command with masking and return parsed cmd.

        :type cmd: str
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]

        .. versionadded:: 1.2.0
        """
        def mask(text, rules):  # type: (str, str) -> str
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
                masked += text[start: end] + '<*masked*>'

            masked += text[indexes[-2]: indexes[-1]]  # final part
            return masked

        cmd = cmd.rstrip()

        if self.log_mask_re:
            cmd = mask(cmd, self.log_mask_re)
        if log_mask_re:
            cmd = mask(cmd, log_mask_re)

        return cmd

    def execute_async(
        self,
        command,  # type: str
        stdin=None,  # type: typing.Union[six.text_type, six.binary_type, bytearray, None]
        open_stdout=True,  # type: bool
        open_stderr=True,  # type: bool
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs
    ):
        """Execute command in async mode and return remote interface with IO objects.

        :param command: Command for execution
        :type command: str
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[six.text_type, six.binary_type, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param verbose: produce verbose log record on command call
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :rtype: typing.Tuple[
            typing.Any,
            typing.Any,
            typing.Any,
            typing.Any,
        ]

        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 stdin data
        """
        raise NotImplementedError  # pragma: no cover

    def _exec_command(
        self,
        command,  # type: str
        interface,  # type: typing.Any
        stdout,  # type: typing.Any
        stderr,  # type: typing.Any
        timeout,  # type: int
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Get exit status from channel with timeout.

        :param command: Command for execution
        :type command: str
        :param interface: Control interface
        :type interface: typing.Any
        :param stdout: STDOUT pipe or file-like object
        :type stdout: typing.Any
        :param stderr: STDERR pipe or file-like object
        :type stderr: typing.Any
        :param timeout: Timeout for command execution
        :type timeout: int
        :param verbose: produce verbose log record on command call
        :type verbose: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        raise NotImplementedError  # pragma: no cover

    def execute(
        self,
        command,  # type: str
        verbose=False,  # type: bool
        timeout=constants.DEFAULT_TIMEOUT,  # type: typing.Optional[int]
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command and wait for return code.

        Timeout limitation: read tick is 100 ms.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Optional[int]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        """
        with self.lock:
            (
                iface,
                _,
                stderr,
                stdout,
            ) = self.execute_async(
                command,
                verbose=verbose,
                **kwargs
            )

            result = self._exec_command(
                command=command,
                interface=iface,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                verbose=verbose,
                **kwargs
            )
            message = _log_templates.CMD_RESULT.format(result=result)
            self.logger.log(
                level=logging.INFO if verbose else logging.DEBUG,
                msg=message
            )
            return result

    def check_call(
        self,
        command,  # type: str
        verbose=False,  # type: bool
        timeout=constants.DEFAULT_TIMEOUT,  # type: typing.Optional[int]
        error_info=None,  # type: typing.Optional[str]
        expected=None,  # type: _type_expected
        raise_on_err=True,  # type: bool
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command and check for return code.

        Timeout limitation: read tick is 100 ms.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Optional[int]
        :param error_info: Text for error details, if fail happens
        :type error_info: typing.Optional[str]
        :param expected: expected return codes (0 by default)
        :type expected: typing.Optional[typing.Iterable[int]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.2.0 default timeout 1 hour
        """
        expected = proc_enums.exit_codes_to_enums(expected)
        ret = self.execute(command, verbose, timeout, **kwargs)
        if ret['exit_code'] not in expected:
            message = (
                _log_templates.CMD_UNEXPECTED_EXIT_CODE.format(
                    append=error_info + '\n' if error_info else '',
                    result=ret,
                    expected=expected
                ))
            self.logger.error(message)
            if raise_on_err:
                raise exceptions.CalledProcessError(
                    result=ret,
                    expected=expected,
                )
        return ret

    def check_stderr(
        self,
        command,  # type: str
        verbose=False,  # type: bool
        timeout=constants.DEFAULT_TIMEOUT,  # type: typing.Optional[int]
        error_info=None,  # type: typing.Optional[str]
        raise_on_err=True,  # type: bool
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Execute command expecting return code 0 and empty STDERR.

        Timeout limitation: read tick is 100 ms.

        :param command: Command for execution
        :type command: str
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Optional[int]
        :param error_info: Text for error details, if fail happens
        :type error_info: typing.Optional[str]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.2.0 default timeout 1 hour
        """
        ret = self.check_call(
            command, verbose, timeout=timeout,
            error_info=error_info, raise_on_err=raise_on_err, **kwargs)
        if ret['stderr']:
            message = (
                _log_templates.CMD_UNEXPECTED_STDERR.format(
                    append=error_info + '\n' if error_info else '',
                    result=ret,
                ))
            self.logger.error(message)
            if raise_on_err:
                raise exceptions.CalledProcessError(
                    result=ret,
                    expected=kwargs.get('expected'),
                )
        return ret
