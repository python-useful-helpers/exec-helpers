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

class ExecHelperTimeoutProcessError(ExecCalledProcessError):

    Timeout based errors.

    .. versionadded:: 3.4.0

    .. py:attribute:: timeout

        ``Union[int, float]``

    .. py:attribute:: result

        Execution result

        :rtype: ExecResult

    .. py:attribute:: stdout

        ``str``
        stdout string or brief string

    .. py:attribute:: stderr

        ``str``
        stdout string or brief string


.. py:exception:: ExecHelperNoKillError(ExecHelperTimeoutProcessError)

    Impossible to kill process.

    .. versionadded:: 3.4.0

    .. py:method:: __init__(self, result, timeout)

        Exception for error on process calls.

        :param result: execution result
        :type result: ExecResult
        :param timeout: timeout for command
        :type timeout: ``Union[int, float]``


.. py:exception:: ExecHelperTimeoutError(ExecHelperTimeoutProcessError)

    Execution timeout.

    .. versionchanged:: 1.3.0 provide full result and timeout inside.
    .. versionchanged:: 1.3.0 subclass ExecCalledProcessError

    .. py:method:: __init__(self, result, timeout)

        Exception for error on process calls.

        :param result: execution result
        :type result: ExecResult
        :param timeout: timeout for command
        :type timeout: ``Union[int, float]``


.. py:exception:: CalledProcessError(ExecCalledProcessError)

    Exception for error on process calls.

    .. versionchanged:: 1.1.1 - provide full result

    .. py:method:: __init__(result, expected=(0,))

        :param result: execution result
        :type result: ExecResult
        :param expected: expected return codes
        :type expected: Iterable[Union[int, ExitCodes]]

        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent

    .. py:attribute:: result

        Execution result

        :rtype: ExecResult

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: returncode

        return code

        :rtype: Union[int, ExitCodes]

    .. py:attribute:: expected

        expected return codes

        :rtype: List[Union[int, ExitCodes]]

    .. py:attribute:: stdout

        ``str``
        stdout string or brief string

    .. py:attribute:: stderr

        ``str``
        stdout string or brief string

.. py:exception:: ParallelCallProcessError(ExecCalledProcessError)

    Exception during parallel execution.

    .. py:method:: __init__(command, errors, results, expected=(0,), )

        :param command: command
        :type command: ``str``
        :param errors: results with errors
        :type errors: Dict[Tuple[str, int], ExecResult]
        :param results: all results
        :type results: Dict[Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: Iterable[Union[int, ExitCodes]]

        .. versionchanged:: 1.0 - fixed inheritance
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: errors

        results with errors

        :rtype: Dict[Tuple[str, int], ExecResult]

    .. py:attribute:: results

        all results

        :rtype: Dict[Tuple[str, int], ExecResult]

    .. py:attribute:: expected

        expected return codes

        :rtype: List[Union[int, ExitCodes]]

.. py:exception:: ParallelCallExceptions(ParallelCallProcessError)

    Exception raised during parallel call as result of exceptions.

    .. py:method:: __init__(command, exceptions, errors, results, expected=(0,), )

        :param command: command
        :type command: ``str``
        :param exceptions: Exception on connections
        :type exceptions: ``Dict[Tuple[str, int], Exception]``
        :param errors: results with errors
        :type errors: Dict[Tuple[str, int], ExecResult]
        :param results: all results
        :type results: Dict[Tuple[str, int], ExecResult]
        :param expected: expected return codes
        :type expected: Iterable[Union[int, ExitCodes]]

        .. versionchanged:: 1.0 - fixed inheritance
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: exceptions

        ``Dict[Tuple[str, int], Exception]``
        Exception on connections

    .. py:attribute:: errors

        results with errors

        :rtype: Dict[Tuple[str, int], ExecResult]

    .. py:attribute:: results

        all results

        :rtype: Dict[Tuple[str, int], ExecResult]

    .. py:attribute:: expected

        expected return codes

        :rtype: List[Union[int, ExitCodes]]
