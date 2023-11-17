.. ExecResult

API: ExecResult
===============

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:class:: ExecResult()

    Command execution result.

    .. py:method:: __init__(cmd, stdin=None, stdout=None, stderr=None, exit_code=0xDEADBEEF, *, started=None)

        :param cmd: command
        :type cmd: ``str``
        :param stdin: STDIN
        :type stdin: ``bytes | str | bytearray | None``
        :param stdout: binary STDOUT
        :type stdout: ``Iterable[bytes] | None``
        :param stderr: binary STDERR
        :type stderr: ``Iterable[bytes] | None``
        :param exit_code: Exit code. If integer - try to convert to BASH enum.
        :type exit_code: int | ExitCodes
        :param started: Timestamp of command start
        :type started: ``datetime.datetime | None``

    .. py:attribute:: stdout_lock

        ``threading.RLock``
        Lock object for thread-safe operation.

        .. versionadded:: 2.2.0

    .. py:attribute:: stderr_lock

        ``threading.RLock``
        Lock object for thread-safe operation.

        .. versionadded:: 2.2.0

    .. py:attribute:: timestamp

        ``datetime.datetime | None``
        Timestamp

    .. py:method:: set_timestamp()

        Set timestamp if empty.

        This will block future object changes.

        .. versionadded:: 4.0.0

    .. py:attribute:: cmd

        ``str``
        Command

    .. py:attribute:: stdin

        ``str | None``
        Stdin input as string.

    .. py:attribute:: stdout

        ``tuple[bytes, ...]``
        Stdout output as list of binaries.

    .. py:attribute:: stderr

        ``tuple[bytes, ...]``
        Stderr output as list of binaries.

    .. py:attribute:: stdout_bin

        ``bytearray``
        Stdout in binary format.

    .. py:attribute:: stderr_bin

        ``bytearray``
        Stderr in binary format.

    .. py:attribute:: stdout_str

        ``str``
        Stdout output as string.

    .. py:attribute:: stderr_str

        ``str``
        Stderr output as string.

    .. py:attribute:: stdout_brief

        ``str``
        Brief stdout output (mostly for exceptions).

    .. py:attribute:: stderr_brief

        ``str``
        Brief stderr output (mostly for exceptions).

    .. py:attribute:: stdout_lines

        Get lines by indexes

        :rtype: LinesAccessProxy

        Usage example:

        .. code-block:: python

            lines: str = res.stdout_lines[<line_number>, <index_start>:<index_end>, ...]

    .. py:attribute:: stderr_lines

        Get lines by indexes

        :rtype: LinesAccessProxy

    .. py:attribute:: exit_code

        Return(exit) code of command.

        :rtype: int | ExitCodes

    .. py:attribute:: ok

        ``bool``

        Exit code is EX_OK

    .. py:method:: check_exit_code(expected_codes=(0,), raise_on_err=True, error_info=None, exception_class=CalledProcessError, logger=LOGGER, verbose=False)

        Check exit code and log/raise for unexpected code.

        :param error_info: optional additional error information
        :type error_info: str | None
        :param raise_on_err: raise `exception_class` in case of error
        :type raise_on_err: bool
        :param expected_codes: iterable expected exit codes
        :type expected_codes: Iterable[int | ExitCodes]
        :param exception_class: exception class for usage in case of errors (subclass of CalledProcessError)
        :type exception_class: type[exceptions.CalledProcessError]
        :param logger: logger instance for error log
        :type logger: logging.Logger
        :param verbose: produce verbose log in case of failure
        :type verbose: bool
        :raises exceptions.CalledProcessError: unexpected exit code and raise_on_err enabled

    .. py:method:: raise_for_status(expected_codes=(0,), exception_class=CalledProcessError)

        Requests-like exit code checker.

        :param expected_codes: iterable expected exit codes
        :type expected_codes: Iterable[int | ExitCodes]
        :param exception_class: exception class for usage in case of errors (subclass of CalledProcessError)
        :type exception_class: type[exceptions.CalledProcessError]
        :raises exceptions.CalledProcessError: unexpected exit code and raise_on_err enabled

    .. py:attribute:: started

        ``datetime.datetime``
        Timestamp of command start.

        .. versionadded:: 4.0.0

    .. py:attribute:: stdout_json

        JSON from stdout.

        :rtype: ``Any``
        :raises DeserializeValueError: STDOUT can not be deserialized as JSON

    .. py:attribute:: stdout_yaml

        YAML from stdout.

        :rtype: ``Any``
        :raises DeserializeValueError: STDOUT can not be deserialized as YAML
        :raises AttributeError: no any yaml parser installed

    .. py:attribute:: stdout_xml

        XML from stdout

        :rtype: ``xml.etree.ElementTree.Element``
        :raises DeserializeValueError: STDOUT can not be deserialized as XML
        :raises AttributeError: defusedxml is not installed

    .. py:attribute:: stdout_lxml

        XML from stdout using lxml.

        :rtype: ``lxml.etree.Element``
        :raises DeserializeValueError: STDOUT can not be deserialized as XML
        :raises AttributeError: lxml is not installed

        .. note:: Can be insecure.

    .. py:method:: read_stdout(src=None, log=None, verbose=False)

        Read stdout file-like object to stdout.

        :param src: source
        :type src: ``Iterable[bytes] | None``
        :param log: logger
        :type log: ``logging.Logger | None``
        :param verbose: use log.info instead of log.debug
        :type verbose: ``bool``

        .. versionchanged:: 1.2.0 - src can be None

    .. py:method:: read_stderr(src=None, log=None, verbose=False)

        Read stderr file-like object to stderr.

        :param src: source
        :type src: ``Iterable[bytes] | None``
        :param log: logger
        :type log: ``logging.Logger | None``
        :param verbose: use log.info instead of log.debug
        :type verbose: ``bool``

        .. versionchanged:: 1.2.0 - src can be None


.. py:class:: LinesAccessProxy()

    Lines access proxy.

    .. py:method:: __init__(self, data)

        Lines access proxy.

        :param data: data to work with.
        :type data: ``Sequence[bytes]``

    .. py:method:: __getitem__(self, item)

        Access magic.

        :param item: index
        :type item: ``int | slice | Iterable[int | slice | ellipsis]``
        :return: Joined selected lines
        :rtype: ``str``
        :raises TypeError: Unexpected key

    .. py:method:: __str__(self)

        Get string for debug purposes.

    .. py:method:: __len__(self)

        Data len.
