"""Shared helpers."""

from __future__ import annotations

# Standard Library
import functools
import re
import shlex
import typing


def string_bytes_bytearray_as_bytes(src: typing.Union[str, bytes, bytearray]) -> bytes:
    """Get bytes string from string/bytes/bytearray union.

    :param src: source string or bytes-like object
    :return: Byte string
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


def _mask_command(text: str, rules: str) -> str:
    """Mask part of text using rules.

    :param text: source text
    :type text: str
    :param rules: regex rules to mask.
    :type rules: str
    :return: source with all MATCHED groups replaced by '<*masked*>'
    :rtype: str
    """
    masked: typing.List[str] = []

    # places to exclude
    prev = 0
    for match in re.finditer(rules, text):
        for idx, _ in enumerate(match.groups(), start=1):
            start, end = match.span(idx)
            masked.append(text[prev:start])
            masked.append("<*masked*>")
            prev = end
    masked.append(text[prev:])

    return "".join(masked)


def mask_command(text: str, *rules: typing.Optional[str]) -> str:
    """Apply all rules to command.

    :param text: source text
    :type text: str
    :param rules: regex rules to mask.
    :type rules: typing.Optional[str]
    :return: source with all MATCHED groups replaced by '<*masked*>'
    :rtype: str
    """
    return functools.reduce(_mask_command, (rule for rule in rules if rule is not None), text)


def cmd_to_string(command: typing.Union[str, typing.Iterable[str]]) -> str:
    """Convert command to string for usage with shell.

    :param command: original command.
    :type command: typing.Union[str, typing.Iterable[str]]
    :return: command as single string
    :rtype: str
    """
    if isinstance(command, str):
        return command
    return " ".join(shlex.quote(elem) for elem in command)


def chroot_command(command: str, chroot_path: typing.Optional[str] = None) -> str:
    """Prepare command for chroot execution.

    :param command: original command.
    :type command: str
    :param chroot_path: chroot path
    :type chroot_path: typing.Optional[str]
    :return: command to be executed with chroot rules if applicable
    :rtype: str
    """
    if chroot_path and chroot_path != "/":
        chroot_dst: str = shlex.quote(chroot_path.strip())
        quoted_command = shlex.quote(command)
        return f'chroot {chroot_dst} sh -c {shlex.quote(f"eval {quoted_command}")}'
    return command
