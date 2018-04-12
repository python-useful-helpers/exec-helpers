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

import collections
import logging
import os
import select
import sys
import subprocess  # nosec  # Expected usage
import threading
import time
import typing

import six
import threaded

from exec_helpers import _api
from exec_helpers import constants
from exec_helpers import exec_result
from exec_helpers import exceptions
from exec_helpers import proc_enums
from exec_helpers import _log_templates

logger = logging.getLogger(__name__)
# noinspection PyUnresolvedReferences
devnull = open(os.devnull)  # subprocess.DEVNULL is py3.3+

_win = sys.platform == "win32"
_posix = 'posix' in sys.builtin_module_names
_type_exit_codes = typing.Union[int, proc_enums.ExitCodes]
_type_expected = typing.Optional[typing.Iterable[_type_exit_codes]]

if _posix:  # pragma: no cover
    import fcntl  # pylint: disable=import-error

elif _win:  # pragma: no cover
    # noinspection PyUnresolvedReferences
    import msvcrt  # pylint: disable=import-error
    import ctypes
    from ctypes import wintypes  # pylint: disable=import-error
    from ctypes import windll  # pylint: disable=import-error


class SingletonMeta(type):
    """Metaclass for Singleton.

    Main goals: not need to implement __new__ in singleton classes
    """

    _instances = {}
    _lock = threading.RLock()

    def __call__(cls, *args, **kwargs):
        """Singleton."""
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super(
                    SingletonMeta, cls
                ).__call__(*args, **kwargs)
        return cls._instances[cls]

    @classmethod
    def __prepare__(
        mcs,
        name,
        bases,
        **kwargs
    ):  # pylint: disable=unused-argument
        """Metaclass magic for object storage.

        .. versionadded:: 1.2.0
        """
        return collections.OrderedDict()


def set_nonblocking_pipe(pipe):  # type: (os.pipe) -> None
    """Set PIPE unblocked to allow polling of all pipes in parallel."""
    descriptor = pipe.fileno()

    if _posix:  # pragma: no cover
        # Get flags
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)

        # Set nonblock mode
        fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    elif _win:  # pragma: no cover
        # noinspection PyPep8Naming
        SetNamedPipeHandleState = windll.kernel32.SetNamedPipeHandleState
        SetNamedPipeHandleState.argtypes = [
            wintypes.HANDLE,
            wintypes.LPDWORD,
            wintypes.LPDWORD,
            wintypes.LPDWORD
        ]
        SetNamedPipeHandleState.restype = wintypes.BOOL
        # noinspection PyPep8Naming
        PIPE_NOWAIT = wintypes.DWORD(0x00000001)
        handle = msvcrt.get_osfhandle(descriptor)

        windll.kernel32.SetNamedPipeHandleState(
            handle,
            ctypes.byref(PIPE_NOWAIT), None, None
        )


class Subprocess(six.with_metaclass(SingletonMeta, _api.ExecHelper)):
    """Subprocess helper with timeouts and lock-free FIFO."""

    __slots__ = (
        '__process',
    )

    def __init__(
        self,
        log_mask_re=None,  # type: typing.Optional[str]
    ):
        """Subprocess helper with timeouts and lock-free FIFO.

        For excluding race-conditions we allow to run 1 command simultaneously

        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        super(Subprocess, self).__init__(
            logger=logger,
            log_mask_re=log_mask_re
        )
        self.__process = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager usage."""
        if self.__process:
            self.__process.kill()
        self.lock.release()

    def __del__(self):
        """Destructor. Kill running subprocess, if it running."""
        if self.__process:
            self.__process.kill()

    def __exec_command(
        self,
        command,  # type: str
        cwd=None,  # type: typing.Optional[str]
        env=None,  # type: typing.Optional[typing.Dict[str, typing.Any]]
        timeout=constants.DEFAULT_TIMEOUT,  # type: typing.Optional[int]
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        open_stdout=True,  # type: bool
        open_stderr=True,  # type: bool
    ):
        """Command executor helper.

        :type command: str
        :type cwd: str
        :type env: dict
        :type timeout: int
        :param verbose: use INFO log level instead of DEBUG
        :type verbose: str
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: bool
        :param open_stderr: open STDERR stream for read
        :type open_stderr: bool
        :rtype: ExecResult

        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        """
        def poll_streams(
            result,  # type: exec_result.ExecResult
            stdout,  # type: io.TextIOWrapper
            stderr,  # type: io.TextIOWrapper
        ):
            """Poll streams to the result object."""
            if _win:  # pragma: no cover
                # select.select is not supported on windows
                result.read_stdout(src=stdout, log=logger, verbose=verbose)
                result.read_stderr(src=stderr, log=logger, verbose=verbose)
            else:  # pragma: no cover
                rlist, _, _ = select.select(
                    [item for item in (stdout, stderr) if item is not None],
                    [],
                    [])
                if rlist:
                    if stdout in rlist:
                        result.read_stdout(
                            src=stdout,
                            log=logger,
                            verbose=verbose
                        )
                    if stderr in rlist:
                        result.read_stderr(
                            src=stderr,
                            log=logger,
                            verbose=verbose
                        )

        @threaded.threaded(started=True, daemon=True)
        def poll_pipes(
            result,  # type: exec_result.ExecResult
            stop  # type: threading.Event
        ):
            """Polling task for FIFO buffers.

            :type result: exec_result.ExecResult
            :type stop: threading.Event
            """
            while not stop.isSet():
                time.sleep(0.1)
                if open_stdout or open_stderr:
                    poll_streams(
                        result=result,
                        stdout=self.__process.stdout,
                        stderr=self.__process.stderr,
                    )

                self.__process.poll()

                if self.__process.returncode is not None:
                    result.read_stdout(
                        src=self.__process.stdout,
                        log=logger,
                        verbose=verbose
                    )
                    result.read_stderr(
                        src=self.__process.stderr,
                        log=logger,
                        verbose=verbose
                    )
                    result.exit_code = self.__process.returncode

                    stop.set()

        # 1 Command per run
        with self.lock:
            cmd_for_log = self._mask_command(
                cmd=command,
                log_mask_re=log_mask_re
            )

            # Store command with hidden data
            result = exec_result.ExecResult(cmd=cmd_for_log)
            stop_event = threading.Event()

            logger.log(
                level=logging.INFO if verbose else logging.DEBUG,
                msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
            )

            # Run
            self.__process = subprocess.Popen(
                args=[command],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE if open_stdout else devnull,
                stderr=subprocess.PIPE if open_stderr else devnull,
                shell=True, cwd=cwd, env=env,
                universal_newlines=False,
            )

            # Poll output

            if open_stdout:
                set_nonblocking_pipe(self.__process.stdout)
            if open_stderr:
                set_nonblocking_pipe(self.__process.stderr)
            # pylint: disable=assignment-from-no-return
            poll_thread = poll_pipes(
                result,
                stop_event
            )  # type: threading.Thread
            # pylint: enable=assignment-from-no-return
            # wait for process close
            stop_event.wait(timeout)

            # Process closed?
            if stop_event.isSet():
                stop_event.clear()
                self.__process = None
                return result
            # Kill not ended process and wait for close
            try:
                self.__process.kill()  # kill -9
                stop_event.wait(5)
                # Force stop cycle if no exit code after kill
                stop_event.set()
                poll_thread.join(5)
            except OSError:
                # Nothing to kill
                logger.warning(
                    u"{!s} has been completed just after timeout: "
                    "please validate timeout.".format(command))
            self.__process = None

            wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(
                result=result,
                timeout=timeout
            )
            logger.debug(wait_err_msg)
            raise exceptions.ExecHelperTimeoutError(wait_err_msg)

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
        result = self.__exec_command(command=command, timeout=timeout,
                                     verbose=verbose, **kwargs)
        message = _log_templates.CMD_RESULT.format(result=result)
        logger.log(
            level=logging.INFO if verbose else logging.DEBUG,
            msg=message
        )

        return result
