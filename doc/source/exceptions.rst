.. exceptions

API: exceptions
===============

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:exception:: ExecHelperError(Exception)

    Base class for all exceptions raised inside.

.. py:exception:: DeserializeValueError(ExecHelperError, ValueError)

    Deserialize impossible.

.. py:exception:: ExecCalledProcessError(ExecHelperError)

    Base class for process call errors.

.. py:exception:: ExecHelperTimeoutError(ExecCalledProcessError)

    Execution timeout.

    .. versionchanged:: 1.3.0 provide full result and timeout inside.
    .. versionchanged:: 1.3.0 subclass ExecCalledProcessError

    .. py:method:: __init__(self, result, timeout)

        Exception for error on process calls.

        :param result: execution result
        :type result: exec_result.ExecResult
        :param timeout: timeout for command
        :type timeout: typing.Union[int, float]

    .. py:attribute:: timeout

        ``typing.Union[int, float]``

    .. py:attribute:: result

        Execution result

        :rtype: ExecResult

    .. py:attribute:: stdout

        ``str``
        stdout string or brief string

    .. py:attribute:: stderr

        ``str``
        stdout string or brief string

.. py:exception:: CalledProcessError(ExecCalledProcessError)

    Exception for error on process calls.

    .. versionchanged:: 1.1.1 - provide full result

    .. py:method:: __init__(result, expected=None)

        :param result: execution result
        :type result: ExecResult
        :param returncode: return code
        :type returncode: typing.Union[int, ExitCodes]

    .. py:attribute:: result

        Execution result

        :rtype: ExecResult

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: returncode

        return code

        :rtype: typing.Union[int, ExitCodes]

    .. py:attribute:: expected

        expected return codes

        :rtype: typing.List[typing.Union[int, ExitCodes]]

    .. py:attribute:: stdout

        ``str``
        stdout string or brief string

    .. py:attribute:: stderr

        ``str``
        stdout string or brief string

.. py:exception:: ParallelCallProcessError(ExecCalledProcessError)

    Exception during parallel execution.

    .. py:method:: __init__(command, errors, results, expected=None, )

        :param command: command
        :type command: ``str``
        :param errors: results with errors
        :type errors: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param results: all results
        :type results: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: typing.Optional[typing.List[typing.List[typing.Union[int, ExitCodes]]]

        .. versionchanged:: 1.0 - fixed inheritance

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: errors

        results with errors

        :rtype: typing.Dict[typing.Tuple[str, int], ExecResult]

    .. py:attribute:: results

        all results

        :rtype: typing.Dict[typing.Tuple[str, int], ExecResult]

    .. py:attribute:: expected

        expected return codes

        :rtype: typing.List[typing.Union[int, ExitCodes]]

.. py:exception:: ParallelCallExceptions(ParallelCallProcessError)

    Exception raised during parallel call as result of exceptions.

    .. py:method:: __init__(command, exceptions, errors, results, expected=None, )

        :param command: command
        :type command: ``str``
        :param exceptions: Exception on connections
        :type exceptions: ``typing.Dict[typing.Tuple[str, int], Exception]``
        :param errors: results with errors
        :type errors: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param results: all results
        :type results: typing.Dict[typing.Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: typing.Optional[typing.List[typing.List[typing.Union[int, ExitCodes]]]

        .. versionchanged:: 1.0 - fixed inheritance

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: exceptions

        ``typing.Dict[typing.Tuple[str, int], Exception]``
        Exception on connections

    .. py:attribute:: errors

        results with errors

        :rtype: typing.Dict[typing.Tuple[str, int], ExecResult]

    .. py:attribute:: results

        all results

        :rtype: typing.Dict[typing.Tuple[str, int], ExecResult]

    .. py:attribute:: expected

        expected return codes

        :rtype: typing.List[typing.Union[int, ExitCodes]]
