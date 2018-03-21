.. exceptions

API: exceptions
===============

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:exception:: ExecHelperError

    Base class for all exceptions raised inside.

.. py:exception:: ExecHelperTimeoutError

    Execution timeout.

.. py:exception:: ExecCalledProcessError

    Base class for process call errors.

.. py:exception:: CalledProcessError(command, returncode, expected=None, stdout=None, stderr=None)

    Exception for error on process calls.

    :param command: command
    :type command: str
    :param returncode: return code
    :type returncode: typing.Union[int, proc_enums.ExitCodes]
    :param expected: expected return codes
    :type expected: typing.Optional[typing.List[typing.Union[int, proc_enums.ExitCodes]]]
    :param stdout: stdout string or brief string
    :type stdout: typing.Any
    :param stderr: stderr string or brief string
    :type stderr: typing.Any

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: returncode

        ``typing.Union[int, proc_enums.ExitCodes]``
        return code

    .. py:attribute:: expected

        ``typing.List[typing.Union[int, proc_enums.ExitCodes]]``
        expected return codes

    .. py:attribute:: stdout

        ``typing.Any``
        stdout string or brief string

    .. py:attribute:: stderr

        ``typing.Any``
        stdout string or brief string

.. py:exception:: ParallelCallExceptions(command, exceptions, errors, results, expected=None, )

    Exception raised during parallel call as result of exceptions.

    :param command: command
    :type command: ``str``
    :param exceptions: Exception on connections
    :type exceptions: ``typing.Dict[typing.Tuple[str, int], Exception]``
    :param errors: results with errors
    :type errors: ``typing.Dict[typing.Tuple[str, int], ExecResult]``
    :param results: all results
    :type results: ``typing.Dict[typing.Tuple[str, int], ExecResult]``
    :param expected: expected return codes
    :type expected: ``typing.Optional[typing.List[typing.List[typing.Union[int, proc_enums.ExitCodes]]]``

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: exceptions

        ``typing.Dict[typing.Tuple[str, int], Exception]``
        Exception on connections

    .. py:attribute:: errors

        ``typing.Dict[typing.Tuple[str, int], ExecResult]``
        results with errors

    .. py:attribute:: results

        ``typing.Dict[typing.Tuple[str, int], ExecResult]``
        all results

    .. py:attribute:: expected

        ``typing.List[typing.Union[int, proc_enums.ExitCodes]]``
        expected return codes

.. py:exception:: ParallelCallProcessError(command, errors, results, expected=None, )

    Exception during parallel execution.

    :param command: command
    :type command: ``str``
    :param errors: results with errors
    :type errors: ``typing.Dict[typing.Tuple[str, int], ExecResult]``
    :param results: all results
    :type results: ``typing.Dict[typing.Tuple[str, int], ExecResult]``
    :param expected: expected return codes
    :type expected: ``typing.Optional[typing.List[typing.List[typing.Union[int, proc_enums.ExitCodes]]]``

    .. py:attribute:: cmd

        ``str``
        command

    .. py:attribute:: errors

        ``typing.Dict[typing.Tuple[str, int], ExecResult]``
        results with errors

    .. py:attribute:: results

        ``typing.Dict[typing.Tuple[str, int], ExecResult]``
        all results

    .. py:attribute:: expected

        ``typing.List[typing.Union[int, proc_enums.ExitCodes]]``
        expected return codes
