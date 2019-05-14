.. Subprocess

API: Subprocess
===============

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:class:: Subprocess()

    .. py:method:: __init__(logger, log_mask_re=None, *, logger=logging.getLogger("exec_helpers.subprocess_runner"))

        ExecHelper global API.

        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: typing.Optional[str]
        :param logger: logger instance to use
        :type logger: logging.Logger

        .. versionchanged:: 1.2.0 log_mask_re regex rule for masking cmd
        .. versionchanged:: 3.1.0 Not singleton anymore. Only lock is shared between all instances.
        .. versionchanged:: 3.2.0 Logger can be enforced.
        .. versionchanged:: 4.1.0 support chroot
        .. versionchanged:: 4.3.0 Lock is not shared anymore: allow parallel call of different instances

    .. py:attribute:: log_mask_re

        ``typing.Optional[str]``

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
        :type path: typing.Optional[str]
        :return: context manager with selected chroot state inside
        :rtype: typing.ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 4.1.0

    .. py:method:: execute_async(command, stdin=None, open_stdout=True, open_stderr=True, verbose=False, log_mask_re=None, *, chroot_path=None, cwd=None, env=None, **kwargs)

        Execute command in async mode and return Popen with IO objects.

        :param command: Command for execution
        :type command: str
        :param stdin: pass STDIN text to the process
        :type stdin: ``typing.Union[str, bytes, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param verbose: produce verbose log record on command call
        :type verbose: ``bool``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``typing.Optional[str]``
        :param chroot_path: chroot path override
        :type chroot_path: ``typing.Optional[str]``
        :param cwd: Sets the current directory before the child is executed.
        :type cwd: typing.Optional[typing.Union[str, bytes]]
        :param env: Defines the environment variables for the new process.
        :type env: typing.Optional[typing.Mapping[typing.Union[str, bytes], typing.Union[str, bytes]]]
        :rtype: SubprocessExecuteAsyncResult
        :raises OSError: impossible to process STDIN

        .. versionadded:: 1.2.0
        .. versionchanged:: 2.1.0 Use typed NamedTuple as result
        .. versionchanged:: 3.2.0 Expose cwd and env as optional keyword-only arguments

    .. py:method:: execute(command, verbose=False, timeout=1*60*60, *, log_mask_re=None, stdin=None, **kwargs)

        Execute command and wait for return code.

        :param command: Command for execution
        :type command: ``str``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``typing.Union[int, float, None]``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``typing.Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``typing.Union[bytes, str, bytearray, None]``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. note:: stdin channel is closed after the input processing
        .. versionchanged:: 1.1.0 make method
        .. versionchanged:: 1.2.0 open_stdout and open_stderr flags
        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 1.2.0 stdin data

    .. py:method:: __call__(command, verbose=False, timeout=1*60*60, *, log_mask_re=None, stdin=None, **kwargs)

        Execute command and wait for return code.

        :param command: Command for execution
        :type command: ``str``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``typing.Union[int, float, None]``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``typing.Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``typing.Union[bytes, str, bytearray, None]``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. note:: stdin channel is closed after the input processing
        .. versionadded:: 3.3.0

    .. py:method:: check_call(command, verbose=False, timeout=1*60*60, error_info=None, expected=(0,), raise_on_err=True, *, log_mask_re=None, stdin=None, exception_class=CalledProcessError, **kwargs)

        Execute command and check for return code.

        :param command: Command for execution
        :type command: ``str``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``typing.Union[int, float, None]``
        :param error_info: Text for error details, if fail happens
        :type error_info: ``typing.Optional[str]``
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``typing.Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``typing.Union[bytes, str, bytearray, None]``
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[CalledProcessError]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.1.0 make method
        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent

    .. py:method:: check_stderr(command, verbose=False, timeout=1*60*60, error_info=None, raise_on_err=True, *, expected=(0,), log_mask_re=None, stdin=None, exception_class=CalledProcessError, **kwargs)

        Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution
        :type command: ``str``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``typing.Union[int, float, None]``
        :param error_info: Text for error details, if fail happens
        :type error_info: ``typing.Optional[str]``
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param expected: expected return codes (0 by default)
        :type expected: typing.Iterable[typing.Union[int, ExitCodes]]
        :param log_mask_re: regex lookup rule to mask command for logger.
                            all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``typing.Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``typing.Union[bytes, str, bytearray, None]``
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: typing.Type[CalledProcessError]
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

        ``subprocess.Popen``

    .. py:attribute:: stdin

        ``typing.Optional[typing.IO]``

    .. py:attribute:: stderr

        ``typing.Optional[typing.IO]``

    .. py:attribute:: stdout

        ``typing.Optional[typing.IO]``

    .. py:attribute:: started

        ``datetime.datetime``

        .. versionadded:: 3.4.1
