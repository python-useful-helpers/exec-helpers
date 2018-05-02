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
import errno
import logging
import os
import select
import sys
import subprocess  # nosec  # Expected usage
import threading
import time
import typing  # noqa  # pylint: disable=unused-import

import six
import threaded

from exec_helpers import _api
from exec_helpers import exec_result
from exec_helpers import exceptions
from exec_helpers import _log_templates

logger = logging.getLogger(__name__)
# noinspection PyUnresolvedReferences
devnull = open(os.devnull)  # subprocess.DEVNULL is py3.3+

_win = sys.platform == "win32"
_posix = 'posix' in sys.builtin_module_names

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

    _instances = {}  # type: typing.Dict[typing.Type, typing.Any]
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
        return collections.OrderedDict()  # pragma: no cover


def set_nonblocking_pipe(pipe):  # type: (typing.Any) -> None
    """Set PIPE unblocked to allow polling of all pipes in parallel."""
    descriptor = pipe.fileno()  # pragma: no cover

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

    def __init__(
        self,
        log_mask_re=None,  # type: typing.Optional[str]
    ):  # type: (...) -> None
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

    def _exec_command(
        self,
        command,  # type: str
        interface,  # type: subprocess.Popen
        stdout,  # type: typing.Optional[typing.IO]
        stderr,  # type: typing.Optional[typing.IO]
        timeout,  # type: int
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs
    ):  # type: (...) -> exec_result.ExecResult
        """Get exit status from channel with timeout.

        :param command: Command for execution
        :type command: str
        :param interface: Control interface
        :type interface: subprocess.Popen
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

        .. versionadded:: 1.2.0
        """
        def poll_streams(
            result,  # type: exec_result.ExecResult
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

        @threaded.threaded(started=True)
        def poll_pipes(
            result,  # type: exec_result.ExecResult
            stop,  # type: threading.Event
        ):
            """Polling task for FIFO buffers.

            :type result: ExecResult
            :type stop: Event
            """
            while not stop.is_set():
                time.sleep(0.1)
                if stdout or stderr:
                    poll_streams(result=result)

                interface.poll()

                if interface.returncode is not None:
                    result.read_stdout(
                        src=stdout,
                        log=logger,
                        verbose=verbose
                    )
                    result.read_stderr(
                        src=stderr,
                        log=logger,
                        verbose=verbose
                    )
                    result.exit_code = interface.returncode

                    stop.set()

        # Store command with hidden data
        cmd_for_log = self._mask_command(
            cmd=command,
            log_mask_re=log_mask_re
        )

        result = exec_result.ExecResult(cmd=cmd_for_log)
        stop_event = threading.Event()

        # pylint: disable=assignment-from-no-return
        poll_thread = poll_pipes(
            result,
            stop_event
        )  # type: threading.Thread
        # pylint: enable=assignment-from-no-return
        # wait for process close
        stop_event.wait(timeout)

        # Process closed?
        if stop_event.is_set():
            poll_thread.join(0.1)
            stop_event.clear()
            return result
        # Kill not ended process and wait for close
        try:
            interface.kill()  # kill -9
            stop_event.wait(5)
            # Force stop cycle if no exit code after kill
            stop_event.set()
            poll_thread.join(5)
        except OSError:
            # Nothing to kill
            logger.warning(
                u"{!s} has been completed just after timeout: "
                "please validate timeout.".format(command))
            return result

        wait_err_msg = _log_templates.CMD_WAIT_ERROR.format(
            result=result,
            timeout=timeout
        )
        logger.debug(wait_err_msg)
        raise exceptions.ExecHelperTimeoutError(wait_err_msg)

    def execute_async(
        self,
        command,  # type: str
        stdin=None,  # type: typing.Union[six.text_type, six.binary_type, bytearray, None]
        open_stdout=True,  # type: bool
        open_stderr=True,  # type: bool
        verbose=False,  # type: bool
        log_mask_re=None,  # type: typing.Optional[str]
        **kwargs
    ):  # type: (...) -> typing.Tuple[subprocess.Popen, None, typing.Optional[typing.IO], typing.Optional[typing.IO], ]
        """Execute command in async mode and return Popen with IO objects.

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
            subprocess.Popen,
            None,
            typing.Optional[typing.IO],
            typing.Optional[typing.IO],
        ]

        .. versionadded:: 1.2.0
        """
        cmd_for_log = self._mask_command(
            cmd=command,
            log_mask_re=log_mask_re
        )

        self.logger.log(
            level=logging.INFO if verbose else logging.DEBUG,
            msg=_log_templates.CMD_EXEC.format(cmd=cmd_for_log)
        )

        process = subprocess.Popen(
            args=[command],
            stdout=subprocess.PIPE if open_stdout else devnull,
            stderr=subprocess.PIPE if open_stderr else devnull,
            stdin=subprocess.PIPE,
            shell=True,
            cwd=kwargs.get('cwd', None),
            env=kwargs.get('env', None),
            universal_newlines=False,
        )

        if stdin is not None:
            if isinstance(stdin, six.text_type):
                stdin = stdin.encode(encoding='utf-8')
            elif isinstance(stdin, bytearray):
                stdin = bytes(stdin)
            try:
                process.stdin.write(stdin)
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    # bpo-19612, bpo-30418: On Windows, stdin.write() fails
                    # with EINVAL if the child process exited or if the child
                    # process is still running but closed the pipe.
                    self.logger.warning('STDIN Send failed: closed PIPE')
                elif exc.errno in (errno.EPIPE, errno.ESHUTDOWN):  # pragma: no cover
                    self.logger.warning('STDIN Send failed: broken PIPE')
                else:
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

        if open_stdout:
            set_nonblocking_pipe(process.stdout)
        if open_stderr:
            set_nonblocking_pipe(process.stderr)

        return process, None, process.stderr, process.stdout
