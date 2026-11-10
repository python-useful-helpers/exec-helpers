.. MaskedArg

API: MaskedArg
===========================

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:class:: MaskedArg(arg, arg_for_log)

    Command argument hidden from the logs, the result and the exceptions.

    The process gets ``arg``, everything else shows ``arg_for_log``.
    The masking happens per argument, before the command is joined, so shell quoting does not matter.
    ``log_mask_re`` still applies to the joined command on top of it.
    Only a command given as a list of arguments can carry it.

    .. versionadded:: 8.3.0

    .. py:attribute:: arg

        ``str``
        Argument passed to the process. Not shown by ``repr``.

    .. py:attribute:: arg_for_log

        ``str``
        Argument shown in the logs, ``ExecResult.cmd`` and the exceptions.

    .. py:classmethod:: secret(arg)

        Hide the whole argument: it is shown as ``<*masked*>``.

        :param arg: Argument passed to the process.
        :type arg: str
        :rtype: MaskedArg

    .. py:classmethod:: option(name, value)

        Show the option name, hide its value, following the usual CLI conventions.

        A long name gives the GNU form ``--name=value``: ``option("pass", v)`` is shown as ``--pass=<*masked*>``.
        A single character gives the POSIX form ``-nvalue``: ``option("p", v)`` is shown as ``-p<*masked*>``.
        For the option and the value as separate arguments, use ``["--pass", MaskedArg.secret(v)]``.

        :param name: Option name without the leading dashes.
        :type name: str
        :param value: Secret value.
        :type value: str
        :rtype: MaskedArg
        :raises ValueError: The name is empty, starts with a dash or has characters other than alphanumerics and dashes.

    .. py:classmethod:: regex(arg, rule)

        Hide the groups that a regex matches in this argument alone, like ``log_mask_re``.

        :param arg: Argument passed to the process.
        :type arg: str
        :param rule: Regex rule, all MATCHED groups are replaced by '<*masked*>'.
        :type rule: str | re.Pattern[str]
        :rtype: MaskedArg

.. code-block:: python

    from exec_helpers import MaskedArg, Subprocess

    result = Subprocess().check_call(["mysql-setup", MaskedArg.option("pass", password), "--verbose"])
    assert result.cmd == "mysql-setup '--pass=<*masked*>' --verbose"
