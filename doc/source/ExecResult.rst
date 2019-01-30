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
        :type stdin: ``typing.Union[bytes, str, bytearray, None]``
        :param stdout: binary STDOUT
        :type stdout: ``typing.Optional[typing.Iterable[bytes]]``
        :param stderr: binary STDERR
        :type stderr: ``typing.Optional[typing.Iterable[bytes]]``
        :param exit_code: Exit code. If integer - try to convert to BASH enum.
        :type exit_code: typing.Union[int, ExitCodes]
        :param started: Timestamp of command start
        :type started: typing.Optional[datetime.datetime]

    .. py:attribute:: stdout_lock

        ``threading.RLock``
        Lock object for thread-safe operation.

        .. versionadded:: 2.2.0

    .. py:attribute:: stderr_lock

        ``threading.RLock``
        Lock object for thread-safe operation.

        .. versionadded:: 2.2.0

    .. py:attribute:: timestamp

        ``typing.Optional(datetime.datetime)``
        Timestamp

    .. py:method:: set_timestamp()

        Set timestamp if empty.

        This will block future object changes.

        .. versionadded:: 2.11.0

    .. py:attribute:: cmd

        ``str``
        Command

    .. py:attribute:: stdin

        ``typing.Optional[str]``
        Stdin input as string.

    .. py:attribute:: stdout

        ``typing.Tuple[bytes, ...]``
        Stdout output as list of binaries.

    .. py:attribute:: stderr

        ``typing.Tuple[bytes, ...]``
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

        :rtype: typing.Union[int, ExitCodes]

    .. py:attribute:: started

        ``datetime.datetime``
        Timestamp of command start.

        .. versionadded:: 2.11.0

    .. py:attribute:: stdout_json

        JSON from stdout.

        :rtype: ``typing.Any``
        :raises DeserializeValueError: STDOUT can not be deserialized as JSON

    .. py:attribute:: stdout_yaml

        YAML from stdout.

        :rtype: ``typing.Any``
        :raises DeserializeValueError: STDOUT can not be deserialized as YAML

    .. py:method:: read_stdout(src=None, log=None, verbose=False)

        Read stdout file-like object to stdout.

        :param src: source
        :type src: ``typing.Optional[typing.Iterable]``
        :param log: logger
        :type log: ``typing.Optional[logging.Logger]``
        :param verbose: use log.info instead of log.debug
        :type verbose: ``bool``

        .. versionchanged:: 1.2.0 - src can be None

    .. py:method:: read_stderr(src=None, log=None, verbose=False)

        Read stderr file-like object to stderr.

        :param src: source
        :type src: ``typing.Optional[typing.Iterable]``
        :param log: logger
        :type log: ``typing.Optional[logging.Logger]``
        :param verbose: use log.info instead of log.debug
        :type verbose: ``bool``

        .. versionchanged:: 1.2.0 - src can be None


.. py:class:: LinesAccessProxy()

    Lines access proxy.

    .. py:method:: __init__(self, data)

        Lines access proxy.

        :param data: data to work with.
        :type data: typing.Sequence[bytes]

    .. py:method:: __getitem__(self, item)

        Access magic.

        :param item: index
        :type item: typing.Union[int, slice, typing.Iterable[typing.Union[int, slice, ellipsis]]]
        :returns: Joined selected lines
        :rtype: str
        :raises TypeError: Unexpected key

    .. py:method:: __str__(self)

        Get string for debug purposes.

    .. py:method:: __len__(self)

        Data len.
