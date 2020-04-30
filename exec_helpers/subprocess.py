#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.

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

__all__ = ("Subprocess", "SubprocessExecuteAsyncResult", "EnvT", "CwdT")

# Standard Library
import typing
from concurrent.futures import wait
from copy import deepcopy
from datetime import datetime
from errno import EINVAL
from errno import EPIPE
from errno import ESHUTDOWN
from logging import getLogger
from os import environ
from pathlib import Path
from subprocess import DEVNULL  # nosec  # Expected usage
from subprocess import PIPE  # nosec  # Expected usage
from subprocess import Popen  # nosec  # Expected usage
from subprocess import TimeoutExpired  # nosec  # Expected usage

# External Dependencies
from threaded import threadpooled

# Package Implementation
from exec_helpers.api import ExecHelper
from exec_helpers.api import ExecuteAsyncResult
from exec_helpers.constants import DEFAULT_TIMEOUT
from exec_helpers.exceptions import CalledProcessError
from exec_helpers.exceptions import ExecHelperNoKillError
from exec_helpers.exceptions import ExecHelperTimeoutError
from exec_helpers.exec_result import ExecResult
from exec_helpers.proc_enums import EXPECTED

# Local Implementation
from ._log_templates import CMD_WAIT_ERROR
from ._subprocess_helpers import kill_proc_tree
from ._subprocess_helpers import subprocess_kw

if typing.TYPE_CHECKING:
    # pylint: disable=ungrouped-imports
    from concurrent.futures import Future
    from exec_helpers.api import CalledProcessErrorSubClassT
    from exec_helpers.api import CommandT
    from exec_helpers.api import OptionalStdinT
    from exec_helpers.api import OptionalTimeoutT
    from exec_helpers.proc_enums import ExitCodeT

    _OptionalIOBytes = typing.Optional[typing.IO[bytes]]

EnvT = typing.Optional[
    typing.Union[typing.Mapping[bytes, typing.Union[bytes, str]], typing.Mapping[str, typing.Union[bytes, str]]]
]
CwdT = typing.Optional[typing.Union[str, bytes, Path]]


# noinspection PyTypeHints
class SubprocessExecuteAsyncResult(ExecuteAsyncResult):
    """Override original NamedTuple with proper typing."""

    __slots__ = ()

    @property
    def interface(self) -> "Popen[bytes]":
        """Override original NamedTuple with proper typing.

        :return: control interface
        :rtype: Popen[bytes]
        """
        return super().interface  # type: ignore

    @property
    def stdin(self) -> "_OptionalIOBytes":  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDIN interface
        :rtype: typing.Optional[typing.IO[bytes]]
        """
        return super().stdin

    @property
    def stderr(self) -> "_OptionalIOBytes":  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDERR interface
        :rtype: typing.Optional[typing.IO[bytes]]
        """
        return super().stderr

    @property
    def stdout(self) -> "_OptionalIOBytes":  # type: ignore
        """Override original NamedTuple with proper typing.

        :return: STDOUT interface
        :rtype: typing.Optional[typing.IO[bytes]]
        """
        return super().stdout


class Subprocess(ExecHelper):
    """Subprocess helper with timeouts and lock-free FIFO.

    For excluding race-conditions we allow to run 1 command simultaneously

    :param log_mask_re: regex lookup rule to mask command for logger.
                        all MATCHED groups will be replaced by '<*masked*>'
    :type log_mask_re: typing.Optional[str]

    .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
    .. versionchanged:: 3.1.0 Not singleton anymore. Only lock is shared between all instances.
    .. versionchanged:: 3.2.0 Logger can be enforced.
    .. versionchanged:: 4.1.0 support chroot
    .. versionchanged:: 4.3.0 Lock is not shared anymore: allow parallel call of different instances.
    """

    def __init__(self, log_mask_re: typing.Optional[str] = None,) -> None:
        """Subprocess helper with timeouts and lock-free FIFO."""
        mod_name = "exec_helpers" if self.__module__.startswith("exec_helpers") else self.__module__
        super(Subprocess, self).__init__(
            logger=getLogger(f"{mod_name}.{self.__class__.__name__}"), log_mask_re=log_mask_re
        )

    def __enter__(self) -> "Subprocess":  # pylint: disable=useless-super-delegation
        """Get context manager.

        :return: exec helper instance with entered context manager
        :rtype: Subprocess
        """
        # noinspection PyTypeChecker
        return super().__enter__()

    def _exec_command(  # type: ignore
        self,
        command: str,
        async_result: SubprocessExecuteAsyncResult,
        timeout: "OptionalTimeoutT",
        *,
        verbose: bool = False,
        log_mask_re: typing.Optional[str] = None,
        stdin: "OptionalStdinT" = None,
        **kwargs: typing.Any,
    ) -> ExecResult:
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

        @threadpooled
        def poll_stdout() -> None:
            """Sync stdout poll."""
            result.read_stdout(src=async_result.stdout, log=self.logger, verbose=verbose)

        @threadpooled
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
        cmd_for_log: str = self._mask_command(cmd=command, log_mask_re=log_mask_re)

        result = ExecResult(cmd=cmd_for_log, stdin=stdin, started=async_result.started)

        # noinspection PyNoneFunctionAssignment,PyTypeChecker
        stdout_future: "Future[None]" = poll_stdout()
        # noinspection PyNoneFunctionAssignment,PyTypeChecker
        stderr_future: "Future[None]" = poll_stderr()

        try:
            exit_code: int = async_result.interface.wait(timeout=timeout)  # Wait real timeout here
            wait([stdout_future, stderr_future], timeout=0.1)  # Minimal timeout to complete polling
            result.exit_code = exit_code
            return result
        except TimeoutExpired:
            # kill -9 for all subprocesses
            kill_proc_tree(async_result.interface.pid)
            exit_signal: typing.Optional[int] = async_result.interface.poll()
            if exit_signal is None:
                raise ExecHelperNoKillError(result=result, timeout=timeout)  # type: ignore
            result.exit_code = exit_signal
        finally:
            stdout_future.cancel()
            stderr_future.cancel()
            _, not_done = wait([stdout_future, stderr_future], timeout=1)
            if not_done and async_result.interface.returncode:
                self.logger.critical(
                    f"Process {command!s} was closed with exit code {async_result.interface.returncode!s}, "
                    f"but FIFO buffers are still open"
                )
            result.set_timestamp()
            close_streams()

        wait_err_msg: str = CMD_WAIT_ERROR.format(result=result, timeout=timeout)
        self.logger.debug(wait_err_msg)
        raise ExecHelperTimeoutError(result=result, timeout=timeout)  # type: ignore

    # noinspection PyMethodOverriding
    def _execute_async(  # pylint: disable=arguments-differ
        self,
        command: str,
        *,
        stdin: typing.Union[str, bytes, bytearray, None] = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        chroot_path: typing.Optional[str] = None,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
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
        :param chroot_path: chroot path override
        :type chroot_path: typing.Optional[str]
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Tuple with control interface and file-like objects for STDIN/STDERR/STDOUT
        :rtype: typing.NamedTuple(
                    'SubprocessExecuteAsyncResult',
                    [
                        ('interface', Popen[bytes]),
                        ('stdin', typing.Optional[typing.IO[bytes]]),
                        ('stderr', typing.Optional[typing.IO[bytes]]),
                        ('stdout', typing.Optional[typing.IO[bytes]]),
                        ("started", datetime),
                    ]
                )
        :raises OSError: impossible to process STDIN

        .. versionadded:: 1.2.0
        .. versionchanged:: 2.1.0 Use typed NamedTuple as result
        .. versionchanged:: 3.2.0 Expose cwd and env as optional keyword-only arguments
        .. versionchanged:: 4.1.0 support chroot
        """
        started = datetime.utcnow()

        if env_patch is not None:
            # make mutable copy
            env = dict(deepcopy(environ) if env is None else deepcopy(env))  # type: ignore
            env.update(env_patch)  # type: ignore

        process: "Popen[bytes]" = Popen(
            args=[self._prepare_command(cmd=command, chroot_path=chroot_path)],
            stdout=PIPE if open_stdout else DEVNULL,
            stderr=PIPE if open_stderr else DEVNULL,
            stdin=PIPE,
            shell=True,  # nosec  # Expected usage
            cwd=cwd,
            env=env,
            universal_newlines=False,
            **subprocess_kw,
        )

        if stdin is None:
            process_stdin: "_OptionalIOBytes" = process.stdin
        elif process.stdin is None:
            self.logger.warning("STDIN pipe is not set, but STDIN data is available to send.")
            process_stdin = None
        else:
            stdin_str: bytes = self._string_bytes_bytearray_as_bytes(stdin)
            try:
                process.stdin.write(stdin_str)
            except OSError as exc:
                if exc.errno == EINVAL:
                    # bpo-19612, bpo-30418: On Windows, stdin.write() fails
                    # with EINVAL if the child process exited or if the child
                    # process is still running but closed the pipe.
                    self.logger.warning("STDIN Send failed: closed PIPE")
                elif exc.errno in (EPIPE, ESHUTDOWN):
                    self.logger.warning("STDIN Send failed: broken PIPE")
                else:
                    kill_proc_tree(process.pid)
                    process.kill()
                    raise
            try:
                process.stdin.close()
            except OSError as exc:
                if exc.errno in (EINVAL, EPIPE, ESHUTDOWN):
                    pass  # PIPE already closed
                else:
                    process.kill()
                    raise

            process_stdin = None

        # noinspection PyArgumentList
        return SubprocessExecuteAsyncResult(process, process_stdin, process.stderr, process.stdout, started)

    def execute(  # pylint: disable=arguments-differ
        self,
        command: "CommandT",
        verbose: bool = False,
        timeout: "OptionalTimeoutT" = DEFAULT_TIMEOUT,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: "OptionalStdinT" = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        .. versionchanged:: 7.0.0 Allow command as list of arguments. Command will be joined with components escaping.
        """
        return super().execute(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            **kwargs,
        )

    def __call__(
        self,
        command: "CommandT",
        verbose: bool = False,
        timeout: "OptionalTimeoutT" = DEFAULT_TIMEOUT,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: "OptionalStdinT" = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        **kwargs: typing.Any,
    ) -> ExecResult:
        """Execute command and wait for return code.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 2.1.0 Allow parallel calls
        """
        return super().__call__(
            command=command,
            verbose=verbose,
            timeout=timeout,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            **kwargs,
        )

    def check_call(  # pylint: disable=arguments-differ
        self,
        command: "CommandT",
        verbose: bool = False,
        timeout: "OptionalTimeoutT" = DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        expected: "typing.Iterable[ExitCodeT]" = (EXPECTED,),
        raise_on_err: bool = True,
        *,
        log_mask_re: typing.Optional[str] = None,
        stdin: "OptionalStdinT" = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        exception_class: "CalledProcessErrorSubClassT" = CalledProcessError,
        **kwargs: typing.Any,
    ) -> ExecResult:
        """Execute command and check for return code.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param error_info: Text for error details, if fail happens
        :type error_info: typing.Optional[str]
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        return super().check_call(
            command=command,
            verbose=verbose,
            timeout=timeout,
            error_info=error_info,
            expected=expected,
            raise_on_err=raise_on_err,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            exception_class=exception_class,
            **kwargs,
        )

    def check_stderr(  # pylint: disable=arguments-differ
        self,
        command: "CommandT",
        verbose: bool = False,
        timeout: "OptionalTimeoutT" = DEFAULT_TIMEOUT,
        error_info: typing.Optional[str] = None,
        raise_on_err: bool = True,
        *,
        expected: "typing.Iterable[ExitCodeT]" = (EXPECTED,),
        log_mask_re: typing.Optional[str] = None,
        stdin: "OptionalStdinT" = None,
        open_stdout: bool = True,
        open_stderr: bool = True,
        cwd: CwdT = None,
        env: EnvT = None,
        env_patch: EnvT = None,
        exception_class: "CalledProcessErrorSubClassT" = CalledProcessError,
        **kwargs: typing.Any,
    ) -> ExecResult:
        """Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution
        :type command: typing.Union[str, typing.Iterable[str]]
        :param verbose: Produce log.info records for command call and output
        :type verbose: bool
        :param timeout: Timeout for command execution.
        :type timeout: typing.Union[int, float, None]
        :param error_info: Text for error details, if fail happens
        :type error_info: typing.Optional[str]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: bool
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, ExitCodes]]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param stdin: pass STDIN text to the process
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes, Path]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[CalledProcessError]
        :param kwargs: additional parameters for call.
        :type kwargs: typing.Any
        :return: Execution result
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        """
        return super().check_stderr(
            command=command,
            verbose=verbose,
            timeout=timeout,
            error_info=error_info,
            raise_on_err=raise_on_err,
            expected=expected,
            log_mask_re=log_mask_re,
            stdin=stdin,
            open_stdout=open_stdout,
            open_stderr=open_stderr,
            cwd=cwd,
            env=env,
            env_patch=env_patch,
            exception_class=exception_class,
            **kwargs,
        )
