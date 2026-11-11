"""Shared helpers."""

from __future__ import annotations

import dataclasses
import functools
import re
import shlex
import typing

from exec_helpers import exceptions

if typing.TYPE_CHECKING:
    from collections.abc import Iterable
    from collections.abc import Mapping
    from typing import Self


class _ExceptionInfo(typing.Protocol):
    """The part of ``pytest.ExceptionInfo`` that :func:`hide_traceback` reads."""

    @property
    def value(self) -> BaseException:
        """Get the exception being reported."""


def hide_traceback(excinfo: _ExceptionInfo | None) -> bool:
    """Tell pytest whether to leave a frame of this package out of a failure report.

    A module sets its ``__tracebackhide__`` global to this function, and pytest calls it for every frame of that module.
    An error this package raises on purpose - a timeout, an unexpected exit code - already names the command
    and carries its output, so the report shows the caller's line and the message.
    Any other exception keeps the frames, because they show where it was raised.

    :param excinfo: The exception pytest is reporting, or ``None`` when it filters frames without one.
    :returns: Whether the frame is left out of the report.

    >>> hide_traceback(None)
    False
    """
    return excinfo is not None and isinstance(excinfo.value, exceptions.ExecHelperError)


def string_bytes_bytearray_as_bytes(src: str | bytes | bytearray) -> bytes:
    """Get byte string from string/bytes/bytearray union.

    :param src: Source string or bytes-like object.
    :return: Byte string.
    :rtype: bytes
    :raises TypeError: unexpected source type.
    """
    if isinstance(src, bytes):
        return src
    if isinstance(src, bytearray):
        return bytes(src)
    if isinstance(src, str):
        return src.encode("utf-8")
    raise TypeError(f"{src!r} has unexpected type: not conform to Union[str, bytes, bytearray]")  # pragma: no cover


def _mask_command(text: str, rules: str | re.Pattern[str]) -> str:
    """Mask part of text using rules.

    :param text: Source text.
    :type text: str
    :param rules: Regex rules to mask.
    :type rules: str | re.Pattern
    :return: Source with all MATCHED groups replaced by '<*masked*>'.
        Groups that did not participate in a match (other branch of `|`, optional group) are left alone.
    :rtype: str
    """
    masked: list[str] = []

    # places to exclude
    prev = 0
    for match in re.finditer(rules, text):
        for idx, _ in enumerate(match.groups(), start=1):
            start, end = match.span(idx)
            if start == -1:  # `span` is (-1, -1) for a group that did not participate
                continue
            masked.extend((text[prev:start], "<*masked*>"))
            prev = end
    masked.append(text[prev:])

    return "".join(masked)


def mask_command(text: str, *rules: str | re.Pattern[str] | None) -> str:
    """Apply all rules to command.

    :param text: Source text.
    :type text: str
    :param rules: Regex rules to mask.
    :type rules: str | re.Pattern[str] | None
    :return: Source with all MATCHED groups replaced by '<*masked*>'.
    :rtype: str
    """
    return functools.reduce(_mask_command, (rule for rule in rules if rule is not None), text)


_MASK: typing.Final = "<*masked*>"
# GNU long option names are alphanumerics and dashes, POSIX short ones a single alphanumeric.
_OPTION_NAME: typing.Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


@dataclasses.dataclass(frozen=True, slots=True)
class MaskedArg:
    """Command argument hidden from the logs, the result and the exceptions.

    The process gets `arg`, everything else shows `arg_for_log`.
    The masking happens per argument, before the command is joined, so shell quoting does not matter.
    `log_mask_re` still applies to the joined command on top of it.

    :param arg: Argument passed to the process.
    :type arg: str
    :param arg_for_log: Argument shown in the logs, ``ExecResult.cmd`` and the exceptions.
    :type arg_for_log: str

    >>> MaskedArg.secret("two secret words")
    MaskedArg(arg_for_log='<*masked*>')
    >>> MaskedArg.key_value("if", "/secret/path")
    MaskedArg(arg_for_log='if=<*masked*>')
    >>> MaskedArg.option("pass", "two secret words")
    MaskedArg(arg_for_log='--pass=<*masked*>')
    >>> MaskedArg.regex("user:p@ss", r":(.*)")
    MaskedArg(arg_for_log='user:<*masked*>')

    .. versionadded:: 8.3.0
    """

    arg: str = dataclasses.field(repr=False)
    arg_for_log: str

    @classmethod
    def secret(cls, arg: str) -> Self:
        """Hide the whole argument.

        :param arg: Argument passed to the process.
        :type arg: str
        :return: Argument shown as '<*masked*>'.
        :rtype: MaskedArg
        """
        return cls(arg, _MASK)

    @classmethod
    def key_value(cls, key: str, value: str, *, sep: str = "=") -> Self:
        """Show the key, hide the value, written exactly as given: ``key=<*masked*>``.

        No dashes are added, so it fits ``dd if=...``, ``make VAR=...`` or ``-Dname=...``.

        :param key: Key as written on the command line, any dashes included.
        :type key: str
        :param value: Secret value.
        :type value: str
        :param sep: Separator between the key and the value inside the one argument.
        :type sep: str
        :return: Argument ``{key}{sep}{value}`` shown as ``{key}{sep}<*masked*>``.
        :rtype: MaskedArg
        :raises ValueError: The key is empty.

        >>> MaskedArg.key_value("if", "/secret/path")
        MaskedArg(arg_for_log='if=<*masked*>')
        """
        if not key:
            raise ValueError("Key is expected to be non-empty")
        return cls(f"{key}{sep}{value}", f"{key}{sep}{_MASK}")

    @classmethod
    def option(cls, name: str, value: str) -> Self:
        """Show the option name, hide its value, following the usual CLI conventions.

        A long name gives the GNU form ``--name=value``.
        A single character gives the POSIX form ``-nvalue``, the option and its value in one argument.
        For the option and the value as separate arguments, use ``["--name", MaskedArg.secret(value)]``.
        For a key without dashes, such as ``dd if=...``, use `key_value`.

        :param name: Option name without the leading dashes: ``pass``, ``p``.
        :type name: str
        :param value: Secret value.
        :type value: str
        :return: Argument shown as ``--name=<*masked*>`` or ``-n<*masked*>``.
        :rtype: MaskedArg
        :raises ValueError: The name is empty, starts with a dash or has characters other than alphanumerics and dashes.

        >>> MaskedArg.option("p", "two secret words")
        MaskedArg(arg_for_log='-p<*masked*>')
        """
        if not _OPTION_NAME.fullmatch(name):
            raise ValueError(f"Option name is expected without leading dashes, as alphanumerics and dashes: {name!r}")
        if len(name) == 1:
            return cls.key_value(f"-{name}", value, sep="")
        return cls.key_value(f"--{name}", value)

    @classmethod
    def regex(cls, arg: str, rule: str | re.Pattern[str]) -> Self:
        """Hide the groups that a regex matches in this argument alone, like `log_mask_re`.

        :param arg: Argument passed to the process.
        :type arg: str
        :param rule: Regex rule, all MATCHED groups are replaced by '<*masked*>'.
        :type rule: str | re.Pattern[str]
        :return: Argument shown with the matched groups masked.
        :rtype: MaskedArg
        """
        return cls(arg, mask_command(arg, rule))


def cmd_to_string(command: str | Iterable[str | MaskedArg]) -> str:
    """Convert command to string for usage with shell.

    :param command: Original command.
    :type command: str | Iterable[str | MaskedArg]
    :return: Command as single string.
    :rtype: str

    .. versionchanged:: 8.3.0 Accept MaskedArg arguments.
    """
    if isinstance(command, str):
        return command
    return shlex.join(arg.arg if isinstance(arg, MaskedArg) else arg for arg in command)


def cmd_to_log_string(command: str | Iterable[str | MaskedArg]) -> str:
    """Convert command to string for the logs: MaskedArg arguments are hidden.

    :param command: Original command.
    :type command: str | Iterable[str | MaskedArg]
    :return: Command as single string, before `log_mask_re` is applied.
    :rtype: str

    .. versionadded:: 8.3.0
    """
    if isinstance(command, str):
        return command
    return shlex.join(arg.arg_for_log if isinstance(arg, MaskedArg) else arg for arg in command)


def chroot_command(command: str, chroot_path: str | None = None, chroot_exe: str | None = None) -> str:
    """Prepare command for chroot execution.

    :param command: Original command.
    :type command: str
    :param chroot_path: chroot path.
    :type chroot_path: str | None
    :param chroot_exe: chroot executable.
    :type chroot_exe: str | None
    :return: Command to be executed with chroot rules if applicable.
    :rtype: str
    """
    chroot_exe = chroot_exe or "chroot"
    if chroot_path and chroot_path != "/":
        chroot_dst: str = shlex.quote(chroot_path.strip())
        quoted_command = shlex.quote(command)
        return f"{chroot_exe} {chroot_dst} sh -c {shlex.quote(f'eval {quoted_command}')}"
    return command


def chroot_argv_command(command: str, chroot_path: str | None = None, chroot_exe: str | None = None) -> str:
    """Prepare command for chroot execution without a shell, only the arguments are joined.

    :param command: Original command, a result of `shlex.join`.
    :type command: str
    :param chroot_path: chroot path.
    :type chroot_path: str | None
    :param chroot_exe: chroot executable, may carry its own arguments.
    :type chroot_exe: str | None
    :return: Command to be executed with chroot rules if applicable.
    :rtype: str
    """
    if chroot_path and chroot_path != "/":
        return shlex.join([*shlex.split(chroot_exe or "chroot"), chroot_path.strip(), *shlex.split(command)])
    return command


def repr_stdin(stdin: bytes | None) -> str:
    """Describe STDIN data for a debug string without exposing it.

    :param stdin: Data for STDIN.
    :type stdin: bytes | None
    :return: Size of the data, as the content can hold secrets.
    :rtype: str
    """
    return "None" if stdin is None else f"<{len(stdin)} bytes>"


def repr_env(env: Mapping[str, str] | None) -> str:
    """Describe an environment for a debug string without exposing the values.

    :param env: Process environment.
    :type env: Mapping[str, str] | None
    :return: Variable names only, as the values can hold secrets.
    :rtype: str
    """
    return "None" if env is None else f"<names: {sorted(env, key=repr)}>"
