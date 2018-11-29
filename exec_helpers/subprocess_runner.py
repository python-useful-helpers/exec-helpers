#    Copyright 2018 Alexey Stepanov aka penguinolog.

#    Copyright 2016 Mirantis, Inc.
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

"""Python subprocess.Popen wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# noinspection PyCompatibility
import concurrent.futures
import errno
import logging
import os
import subprocess  # nosec  # Expected usage
import typing  # noqa: F401  # pylint: disable=unused-import

import six
import threaded

from exec_helpers import api
from exec_helpers import exec_result
from exec_helpers import exceptions
from exec_helpers import metaclasses  # pylint: disable=unused-import
from exec_helpers import _log_templates
from exec_helpers import _subprocess_helpers

logger = logging.getLogger(__name__)  # type: logging.Logger
# noinspection PyUnresolvedReferences
devnull = open(os.devnull)  # subprocess.DEVNULL is py3.3+


# noinspection PyTypeHints
class SubprocessExecuteAsyncResult(api.ExecuteAsyncResult):
    """Override original NamedTuple with proper typing."""

    @property
    def interface(self):  # type: () -> subprocess.Popen
        """Override original NamedTuple with proper typing."""
        return super(SubprocessExecuteAsyncResult, self).interface


class Subprocess(six.with_metaclass(metaclasses.SingleLock, api.ExecHelper)):
    """Subprocess helper with timeouts and lock-free FIFO."""

    def __init__(self, log_mask_re=None):  # type: (typing.Optional[str]) -> None
        """Subprocess helper with timeouts and lock-free FIFO.

        For excluding race-conditions we allow to run 1 command simultaneously

        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 1.9.0 Not singleton anymore. Only lock is shared between all instances.
        """
        super(Subprocess, self).__init__(logger=logger, log_mask_re=log_mask_re)

    def _exec_command(  # type: ignore
        self,
        command,  # type: str
        async_result,  # type: SubprocessExecuteAsyncResult
        timeout,  # type: typing.Union[int, float, None]
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs  # type: typing.Any
    ):  # type: (...) -> exec_result.ExecResult
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
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises OSError: exception during process kill (and not regarding to already closed process)
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionadded:: 1.2.0
        """

        @threaded.threadpooled
        def poll_stdout():  # type: () -> None
            """Sync stdout poll."""
            result.read_stdout(src=async_result.stdout, log=self.logger, verbose=verbose)
            async_result.interface.wait()  # wait for the end of execution

        @threaded.threadpooled
        def poll_stderr():  # type: () -> None
            """Sync stderr poll."""
            result.read_stderr(src=async_result.stderr, log=self.logger, verbose=verbose)

        def close_streams():  # type: () -> None
            """Enforce FIFO closure."""
            if async_result.stdout is not None and not async_result.stdout.closed:
                async_result.stdout.close()
            if async_result.stderr is not None and not async_result.stderr.closed:
                async_result.stderr.close()

        # Store command with hidden data
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        result = exec_result.ExecResult(cmd=cmd_for_log, stdin=kwargs.get("stdin"))

        # pylint: disable=assignment-from-no-return
        # noinspection PyNoneFunctionAssignment
        stdout_future = poll_stdout()  # type: concurrent.futures.Future
        # noinspection PyNoneFunctionAssignment
        stderr_future = poll_stderr()  # type: concurrent.futures.Future
        # pylint: enable=assignment-from-no-return

        concurrent.futures.wait([stdout_future, stderr_future], timeout=timeout)  # Wait real timeout here
        exit_code = async_result.interface.poll()  # Update exit code

        # Process closed?
        if exit_code is not None:
            result.exit_code = exit_code
            close_streams()
            return result
        # Kill not ended process and wait for close
        try:
            # kill -9 for all subprocesses
            _subprocess_helpers.kill_proc_tree(async_result.interface.pid)
            async_result.interface.kill()  # kill -9
            # Force stop cycle if no exit code after kill
        except OSError:
            exit_code = async_result.interface.poll()
            if exit_code is not None:  # Nothing to kill
                self.logger.warning(
                    "{!s} has been completed just after timeout: please validate timeout.".format(command)
                )
                concurrent.futures.wait([stdout_future, stderr_future], timeout=0.1)
                result.exit_code = exit_code
                return result
            raise  # Some other error
        finally:
            stdout_future.cancel()
            stderr_future.cancel()
            _, not_done = concurrent.futures.wait([stdout_future, stderr_future], timeout=1)
            if not_done:
                if async_result.interface.returncode:
                    self.logger.critical(
                        "Process {!s} was closed with exit code {!s}, but FIFO buffers are still open".format(
                            command, async_result.interface.returncode
                        )
                    )
            close_streams()

        wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(result=result, timeout=timeout)

    def execute_async(
        self,
        command,  # type: str
        stdin=None,  # type: typing.Union[str, bytes, bytearray, None]
        open_stdout=True,  # type: bool
        open_stderr=True,  # type: bool
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs  # type: typing.Any
    ):  # type: (...) -> SubprocessExecuteAsyncResult
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
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Tuple with control interface and file-like objects for STDIN/STDERR/STDOUT
        :rtype: typing.NamedTuple(
                    'SubprocessExecuteAsyncResult',
                    [
                        ('interface', subprocess.Popen),
                        ('stdin', typing.Optional[typing.IO]),
                        ('stderr', typing.Optional[typing.IO]),
                        ('stdout', typing.Optional[typing.IO]),
                    ]
                )
        :raises OSError: impossible to process STDIN

        .. versionadded:: 1.2.0
        .. versionchanged:: 1.4.0 Use typed NamedTuple as result
        """
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        self.logger.log(  # type: ignore
            level=logging.INFO if verbose else logging.DEBUG, msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        process = subprocess.Popen(
            args=[command],
            stdout=subprocess.PIPE if open_stdout else devnull,
            stderr=subprocess.PIPE if open_stderr else devnull,
            stdin=subprocess.PIPE,
            shell=True,
            cwd=kwargs.get("cwd", None),
            env=kwargs.get("env", None),
            universal_newlines=False,
            **_subprocess_helpers.subprocess_kw
        )

        if stdin is None:
            process_stdin = process.stdin
        else:
            stdin_str = self._string_bytes_bytearray_as_bytes(stdin)
            try:
                process.stdin.write(stdin_str)
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    # bpo-19612, bpo-30418: On Windows, stdin.write() fails
                    # with EINVAL if the child process exited or if the child
                    # process is still running but closed the pipe.
                    self.logger.warning("STDIN Send failed: closed PIPE")
                elif exc.errno in (errno.EPIPE, errno.ESHUTDOWN):
                    self.logger.warning("STDIN Send failed: broken PIPE")
                else:
                    _subprocess_helpers.kill_proc_tree(process.pid)
                    process.kill()
                    raise
            try:
                process.stdin.close()
            except OSError as exc:
                if exc.errno in (errno.EINVAL, errno.EPIPE, errno.ESHUTDOWN):
                    pass
                else:
                    process.kill()
                    raise

            process_stdin = None  # type: ignore

        return SubprocessExecuteAsyncResult(process, process_stdin, process.stderr, process.stdout)
