#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.

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

__all__ = ("Subprocess", "SubprocessExecuteAsyncResult")

# Standard Library
import concurrent.futures
import datetime
import errno
import logging
import subprocess  # nosec  # Expected usage
import typing

# External Dependencies
import threaded

# Exec-Helpers Implementation
from exec_helpers import _log_templates
from exec_helpers import _subprocess_helpers
from exec_helpers import api
from exec_helpers import exceptions
from exec_helpers import exec_result


# noinspection PyTypeHints
class SubprocessExecuteAsyncResult(api.ExecuteAsyncResult):
    """Override original NamedTuple with proper typing."""

    @property
    def interface(self) -> subprocess.Popen:
        """Override original NamedTuple with proper typing."""
        return super(SubprocessExecuteAsyncResult, self).interface

    @property
    def stdin(self) -> typing.Optional[typing.IO]:  # type: ignore
        """Override original NamedTuple with proper typing."""
        return super(SubprocessExecuteAsyncResult, self).stdin

    @property
    def stderr(self) -> typing.Optional[typing.IO]:  # type: ignore
        """Override original NamedTuple with proper typing."""
        return super(SubprocessExecuteAsyncResult, self).stderr

    @property
    def stdout(self) -> typing.Optional[typing.IO]:  # type: ignore
        """Override original NamedTuple with proper typing."""
        return super(SubprocessExecuteAsyncResult, self).stdout


class Subprocess(api.ExecHelper):
    """Subprocess helper with timeouts and lock-free FIFO."""

    def __init__(
        self,
        log_mask_re: typing.Optional[str] = None,
        *,
        logger: logging.Logger = logging.getLogger(__name__)  # noqa: B008
    ) -> None:
        """Subprocess helper with timeouts and lock-free FIFO.

        For excluding race-conditions we allow to run 1 command simultaneously

        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param logger: logger instance to use
        :type logger: logging.Logger

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 3.1.0 Not singleton anymore. Only lock is shared between all instances.
        .. versionchanged:: 3.2.0 Logger can be enforced.
        .. versionchanged:: 4.1.0 support chroot
        .. versionchanged:: 4.3.0 Lock is not shared anymore: allow parallel call of different instances.
        """
        super(Subprocess, self).__init__(logger=logger, log_mask_re=log_mask_re)

    def _exec_command(  # type: ignore
        self,
        command: str,
        async_result: SubprocessExecuteAsyncResult,
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
        :raises OSError: exception during process kill (and not regarding to already closed process)
        :raises ExecHelperNoKillError: Process not dies on SIGTERM & SIGKILL
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionadded:: 1.2.0
        """

        @threaded.threadpooled
        def poll_stdout() -> None:
            """Sync stdout poll."""
            result.read_stdout(src=async_result.stdout, log=self.logger, verbose=verbose)

        @threaded.threadpooled
        def poll_stderr() -> None:
            """Sync stderr poll."""
            result.read_stderr(src=async_result.stderr, log=self.logger, verbose=verbose)

        def close_streams() -> None:
            """Enforce FIFO closure."""
            if async_result.stdout is not None and not async_result.stdout.closed:
                async_result.stdout.close()
            if async_result.stderr is not None and not async_result.stderr.closed:
                async_result.stderr.close()

        # Store command with hidden data
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)  # type: str

        result = exec_result.ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)

        # noinspection PyNoneFunctionAssignment
        stdout_future = poll_stdout()  # type: concurrent.futures.Future[None]
        # noinspection PyNoneFunctionAssignment
        stderr_future = poll_stderr()  # type: concurrent.futures.Future[None]

        try:
            # Wait real timeout here
            exit_code = async_result.interface.wait(timeout=timeout)  # type: int
            concurrent.futures.wait([stdout_future, stderr_future], timeout=0.1)  # Minimal timeout to complete polling
            result.exit_code = exit_code
            return result
        except subprocess.TimeoutExpired:
            # kill -9 for all subprocesses
            _subprocess_helpers.kill_proc_tree(async_result.interface.pid)
            exit_signal = async_result.interface.poll()  # type: typing.Optional[int]
            if exit_signal is None:
                raise exceptions.ExecHelperNoKillError(result=result, timeout=timeout)  # type: ignore
            result.exit_code = exit_signal
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
            result.set_timestamp()
            close_streams()

        wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(result=result, timeout=timeout)  # type: str
        self.logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(result=result, timeout=timeout)  # type: ignore

    # noinspection PyMethodOverriding
    def execute_async(  # pylint: disable=arguments-differ
        self,
        command: str,
        stdin: typing.Union[str, bytes, bytearray, None] = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        *,
        chroot_path: typing.Optional[str] = None,
        cwd: typing.Optional[typing.Union[str, bytes]] = None,
        env: typing.Optional[
            typing.Union[typing.Mapping[bytes, typing.Union[bytes, str]], typing.Mapping[str, typing.Union[bytes, str]]]
        ] = None,
        **kwargs: typing.Any
    ) -> SubprocessExecuteAsyncResult:
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
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
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
                        ("started", datetime.datetime),
                    ]
                )
        :raises OSError: impossible to process STDIN

        .. versionadded:: 1.2.0
        .. versionchanged:: 2.1.0 Use typed NamedTuple as result
        .. versionchanged:: 3.2.0 Expose cwd and env as optional keyword-only arguments
        .. versionchanged:: 3.5.3 support chroot
        """
        cmd_for_log = self._mask_command(cmd=command, log_mask_re=log_mask_re)  # type: str

        self.logger.log(
            level=logging.INFO if verbose else logging.DEBUG, msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        started = datetime.datetime.utcnow()

        process = subprocess.Popen(
            args=[self._prepare_command(cmd=command, chroot_path=chroot_path)],
            stdout=subprocess.PIPE if open_stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE if open_stderr else subprocess.DEVNULL,
            stdin=subprocess.PIPE,
            shell=True,
            cwd=cwd,
            env=env,
            universal_newlines=False,
            **_subprocess_helpers.SUBPROCESS_KW
        )

        if stdin is None:
            process_stdin = process.stdin  # type: typing.Optional[typing.IO[typing.Any]]
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

            process_stdin = None

        return SubprocessExecuteAsyncResult(process, process_stdin, process.stderr, process.stdout, started)
