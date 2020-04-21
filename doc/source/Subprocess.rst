.. Subprocess

API: Subprocess
===============

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:class:: Subprocess()

    .. py:method:: __init__(logger, log_mask_re=None)

        ExecHelper global API.

        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: Optional[str]

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 3.1.0 Not singleton anymore. Only lock is shared between all instances.
        .. versionchanged:: 3.2.0 Logger can be enforced.
        .. versionchanged:: 4.1.0 support chroot
        .. versionchanged:: 4.3.0 Lock is not shared anymore: allow parallel call of different instances

    .. py:attribute:: log_mask_re

        ``Optional[str]``

        regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'

    .. py:attribute:: lock

        ``threading.RLock``

    .. py:method:: __enter__()

        Open context manager

        .. versionchanged:: 1.1.0 lock on enter

    .. py:method:: __exit__(self, exc_type, exc_val, exc_tb)

        Close context manager

        .. versionchanged:: 1.1.0 release lock on exit

    .. py:method:: chroot(path)

        Context manager for changing chroot rules.

        :param path: chroot path or none for working without chroot.
        :type path: Optional[Union[str, pathlib.Path]]
        :return: context manager with selected chroot state inside
        :rtype: ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 4.1.0

    .. py:method:: execute(command, verbose=False, timeout=1*60*60, *, log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, cwd=None, env=None, env_patch=None, **kwargs)

        Execute command and wait for return code.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: ``Optional[Union[str, bytes, pathlib.Path]]``
        :param env: Defines the environment variables for the new process.
        :type env: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. note:: stdin channel is closed after the input processing
        .. versionchanged:: 1.1.0 make method
        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 stdin data

    .. py:method:: __call__(command, verbose=False, timeout=1*60*60, *, log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, cwd=None, env=None, env_patch=None, **kwargs)

        Execute command and wait for return code.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: ``Optional[Union[str, bytes, pathlib.Path]]``
        :param env: Defines the environment variables for the new process.
        :type env: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. note:: stdin channel is closed after the input processing
        .. versionadded:: 3.3.0

    .. py:method:: check_call(command, verbose=False, timeout=1*60*60, error_info=None, expected=(0,), raise_on_err=True, *, log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, cwd=None, env=None, env_patch=None, exception_class=CalledProcessError, **kwargs)

        Execute command and check for return code.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param error_info: Text for error details, if fail happens
        :type error_info: ``Optional[str]``
        :param expected: expected return codes (0 by default)
        :type expected: Iterable[Union[int, ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: ``Optional[Union[str, bytes, pathlib.Path]]``
        :param env: Defines the environment variables for the new process.
        :type env: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: Type[CalledProcessError]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.1.0 make method
        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent

    .. py:method:: check_stderr(command, verbose=False, timeout=1*60*60, error_info=None, raise_on_err=True, *, expected=(0,), log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, cwd=None, env=None, env_patch=None, exception_class=CalledProcessError, **kwargs)

        Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param error_info: Text for error details, if fail happens
        :type error_info: ``Optional[str]``
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param expected: expected return codes (0 by default)
        :type expected: Iterable[Union[int, ExitCodes]]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: ``Optional[Union[str, bytes, pathlib.Path]]``
        :param env: Defines the environment variables for the new process.
        :type env: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :param env_patch: Defines the environment variables to ADD for the new process.
        :type env_patch: ``Optional[Mapping[Union[str, bytes], Union[str, bytes]]]``
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: Type[CalledProcessError]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.1.0 make method
        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent


.. py:class:: SubprocessExecuteAsyncResult

    Typed NamedTuple

    .. py:attribute:: interface

        ``subprocess.Popen[bytes]``

    .. py:attribute:: stdin

        ``Optional[IO[bytes]]``

    .. py:attribute:: stderr

        ``Optional[IO[bytes]]``

    .. py:attribute:: stdout

        ``Optional[IO[bytes]]``

    .. py:attribute:: started

        ``datetime.datetime``

        .. versionadded:: 3.4.1
