#    Copyright 2018 - 2023 Aleksei Stepanov aka penguinolog.

#    Copyright 2016 Mirantis, Inc.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Execution result."""

from __future__ import annotations

import contextlib
import datetime
import functools
import json
import logging
import threading
import typing

from exec_helpers import exceptions
from exec_helpers import proc_enums

try:
    # noinspection PyPackageRequirements
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]
try:
    from ruamel import yaml as ruamel_yaml
except ImportError:
    ruamel_yaml = None  # type: ignore[assignment]
try:
    # noinspection PyPackageRequirements
    import defusedxml.ElementTree
except ImportError:
    defusedxml = None  # pylint: disable=invalid-name
try:
    # noinspection PyPackageRequirements
    import lxml.etree  # nosec
except ImportError:
    lxml = None  # pylint: disable=invalid-name

if typing.TYPE_CHECKING:
    import xml.etree.ElementTree as ET  # nosec  # for typing only
    from collections.abc import Callable
    from collections.abc import Collection
    from collections.abc import Iterable
    from collections.abc import Sequence

    # noinspection PyPackageRequirements
    import logwrap

    from exec_helpers.proc_enums import ExitCodeT

    _T = typing.TypeVar("_T")

__all__ = ("ExecResult", "OptionalStdinT")

LOGGER: logging.Logger = logging.getLogger(__name__)

OptionalStdinT = typing.Union[bytes, str, bytearray, None]


def _handle_deserialize(
    fmt: str,
) -> Callable[[Callable[[ExecResult], _T]], Callable[[ExecResult], _T]]:
    """Decorator fabric for decoder getters.

    :return: real decorator
    """

    def decorator(method: Callable[[ExecResult], _T]) -> Callable[[ExecResult], _T]:
        """Decorator for decoder getter.

        :return: Wrapped to try/except getter.
        """

        @functools.wraps(method)
        def wrapper(self: ExecResult) -> _T:
            """Getter wrapper.

            :return: Getter output.
            """
            try:
                return method(self)
            except Exception as exc:
                tmpl: str = f"{{self.cmd}} stdout is not valid {fmt}:\n{{stdout!r}}\n"
                LOGGER.exception(tmpl.format(self=self, stdout=self.stdout_str))

                raise exceptions.DeserializeValueError(tmpl.format(self=self, stdout=self.stdout_brief)).with_traceback(
                    exc.__traceback__
                ) from exc

        return wrapper

    return decorator


def _get_str_from_bin(src: bytearray) -> str:
    """Join data in a list to the string.

    :param src: Source to process.
    :type src: bytearray
    :return: Decoded string.
    :rtype: str
    """
    return src.rstrip().decode(encoding="utf-8", errors="backslashreplace")


def _get_bytearray_from_array(src: Iterable[bytes]) -> bytearray:
    """Get bytearray from an array of bytes blocks.

    :param src: Source to process.
    :type src: list[bytes]
    :return: bytearray.
    :rtype: bytearray
    """
    return bytearray(b"".join(src))


class LinesAccessProxy:
    """Lines access proxy."""

    __slots__ = ("_data",)

    def __init__(self, data: Sequence[bytes]) -> None:
        """Lines access proxy.

        :param data: Data to work with.
        :type data: Sequence[bytes]
        """
        self._data: tuple[bytes, ...] = tuple(data)

    # pylint: disable=undefined-variable
    def __getitem__(
        self,
        item: int | slice | Iterable[int | slice | ellipsis],  # noqa: F821
    ) -> str:
        """Access magic.

        :param item: Index.
        :type item: int | slice | Iterable[int | slice | ellipsis]
        :return: Joined selected lines.
        :rtype: str
        :raises TypeError: Unexpected key.
        """
        if isinstance(item, int):
            return _get_str_from_bin(_get_bytearray_from_array([self._data[item]]))
        if isinstance(item, slice):
            return _get_str_from_bin(_get_bytearray_from_array(self._data[item]))
        if isinstance(item, tuple):
            buf: list[bytes] = []
            for rule in item:
                if isinstance(rule, int):
                    buf.append(self._data[rule])
                elif isinstance(rule, slice):
                    buf.extend(self._data[rule])
                elif rule is Ellipsis:
                    buf.append(b"...\n")
                else:
                    raise TypeError(f"Unexpected key type: {rule!r} (from {item!r})")
            return _get_str_from_bin(_get_bytearray_from_array(buf))
        raise TypeError(f"Unexpected key type: {item!r}")

    def __len__(self) -> int:  # pragma: no cover
        """Data len.

        :return: Strings count.
        :rtype: int
        """
        return len(self._data)

    def __str__(self) -> str:  # pragma: no cover
        """Get string for debug purposes.

        :return: String representation for full content.
        :rtype: str
        """
        return self[:]

    def __repr__(self) -> str:
        """Repr for debug purposes.

        :return: Full representation for debug purposes.
        :rtype: str
        """
        return f"{self.__class__.__name__}(data={self._data!r})"


class ExecResult:
    """Execution result."""

    __slots__ = (
        "__cmd",
        "__exit_code",
        "__started",
        "__stderr_lock",
        "__stdin",
        "__stdout_lock",
        "__timestamp",
        "_stderr",
        "_stderr_brief",
        "_stderr_str",
        "_stdout",
        "_stdout_brief",
        "_stdout_str",
    )

    def __init__(
        self,
        cmd: str,
        stdin: OptionalStdinT = None,
        stdout: Iterable[bytes] | None = None,
        stderr: Iterable[bytes] | None = None,
        exit_code: ExitCodeT = proc_enums.INVALID,
        *,
        started: datetime.datetime | None = None,
    ) -> None:
        """Command execution result.

        :param cmd: Command.
        :type cmd: str
        :param stdin: String STDIN.
        :type stdin: bytes | str | bytearray | None
        :param stdout: Binary STDOUT.
        :type stdout: Iterable[bytes] | None
        :param stderr: Binary STDERR.
        :type stderr: Iterable[bytes] | None
        :param exit_code: Exit code. If integer - try to convert to BASH enum.
        :type exit_code: int | proc_enums.ExitCodes
        :param started: Timestamp of command start.
        :type started: datetime.datetime | None
        """
        self.__stdout_lock = threading.RLock()
        self.__stderr_lock = threading.RLock()

        self.__cmd: str = cmd
        if isinstance(stdin, bytes):
            self.__stdin: str | None = _get_str_from_bin(bytearray(stdin))
        elif isinstance(stdin, bytearray):
            self.__stdin = _get_str_from_bin(stdin)
        else:
            self.__stdin = stdin

        if stdout is not None:
            self._stdout: tuple[bytes, ...] = tuple(stdout)
        else:
            self._stdout = ()

        if stderr is not None:
            self._stderr: tuple[bytes, ...] = tuple(stderr)
        else:
            self._stderr = ()

        self.__exit_code: ExitCodeT = proc_enums.INVALID
        self.__timestamp: datetime.datetime | None = None
        self.exit_code = exit_code

        self.__started: datetime.datetime | None = started

        # By default is none:
        self._stdout_str: str | None = None
        self._stderr_str: str | None = None
        self._stdout_brief: str | None = None
        self._stderr_brief: str | None = None

    @property
    def stdout_lock(self) -> threading.RLock:
        """Lock object for thread-safe operation.

        :return: Internal lock for stdout.
        :rtype: threading.RLock

        .. versionadded:: 2.2.0
        """
        return self.__stdout_lock

    @property
    def stderr_lock(self) -> threading.RLock:
        """Lock object for thread-safe operation.

        :return: Internal lock for stderr.
        :rtype: threading.RLock

        .. versionadded:: 2.2.0
        """
        return self.__stderr_lock

    @property
    def timestamp(self) -> datetime.datetime | None:
        """Timestamp.

        :return: Exit code timestamp.
        :rtype: datetime.datetime | None
        """
        return self.__timestamp

    def set_timestamp(self) -> None:
        """Set timestamp if empty.

        This will block future object changes.

        .. versionadded:: 4.0.0
        """
        if self.timestamp is None:
            self.__timestamp = datetime.datetime.now(tz=datetime.timezone.utc)

    @classmethod
    def _get_brief(cls, data: tuple[bytes, ...]) -> str:
        """Get brief output: 7 lines maximum (3 first + ... + 3 last).

        :param data: Source to process.
        :type data: tuple[bytes, ...]
        :return: Brief from source.
        :rtype: str
        """
        if len(data) <= 7:
            return _get_str_from_bin(_get_bytearray_from_array(data))
        return LinesAccessProxy(data)[:3, ..., -3:]

    @property
    def cmd(self) -> str:
        """Executed command.

        :return: Command string.
        :rtype: str
        """
        return self.__cmd

    @property
    def stdin(self) -> str | None:
        """Stdin input as string.

        :return: STDIN content if applicable.
        :rtype: str | None
        """
        return self.__stdin

    @property
    def stdout(self) -> tuple[bytes, ...]:
        """Stdout output as list of binaries.

        :return: STDOUT as tuple of binary strings.
        :rtype: tuple[bytes, ...]
        """
        return self._stdout

    @property
    def stderr(self) -> tuple[bytes, ...]:
        """Stderr output as list of binaries.

        :return: STDERR as tuple of binary strings.
        :rtype: tuple[bytes, ...]
        """
        return self._stderr

    @staticmethod
    def _poll_stream(
        src: Iterable[bytes],
        log: logging.Logger | None = None,
        verbose: bool = False,
    ) -> list[bytes]:
        """Stream poll helper.

        :param src: Source to read from.
        :param log: Logger instance, if line per-line logging is expected.
        :param verbose: Use INFO level for logging.
        :return: A read result as a list of byte strings.
        :rtype: list[bytes]
        """
        dst: list[bytes] = []
        with contextlib.suppress(IOError):
            for line in src:
                dst.append(line)
                if log:
                    log.log(
                        level=logging.INFO if verbose else logging.DEBUG,
                        msg=line.decode("utf-8", errors="backslashreplace").rstrip(),
                    )
        return dst

    def read_stdout(
        self,
        src: Iterable[bytes] | None = None,
        log: logging.Logger | None = None,
        verbose: bool = False,
    ) -> None:
        """Read stdout file-like object to stdout.

        :param src: Source.
        :type src: Iterable[bytes] | None
        :param log: Logger.
        :type log: logging.Logger | None
        :param verbose: Use log.info instead of `log.debug`.
        :type verbose: bool
        :raises RuntimeError: Exit code is already received.

        .. versionchanged:: 1.2.0 - src can be None
        """
        if not src:
            return
        if self.timestamp:
            raise RuntimeError("Final exit code received.")

        with self.stdout_lock:
            self._stdout_str = self._stdout_brief = None
            self._stdout += tuple(self._poll_stream(src, log, verbose))

    def read_stderr(
        self,
        src: Iterable[bytes] | None = None,
        log: logging.Logger | None = None,
        verbose: bool = False,
    ) -> None:
        """Read stderr file-like object to stdout.

        :param src: Source.
        :type src: Iterable[bytes] | None
        :param log: Logger.
        :type log: logging.Logger | None
        :param verbose: Use log.info instead of `log.debug`.
        :type verbose: bool
        :raises RuntimeError: Exit code is already received.

        .. versionchanged:: 1.2.0 - src can be None
        """
        if not src:
            return
        if self.timestamp:
            raise RuntimeError("Final exit code received.")

        with self.stderr_lock:
            self._stderr_str = self._stderr_brief = None
            self._stderr += tuple(self._poll_stream(src, log, verbose))

    @property
    def stdout_bin(self) -> bytearray:
        """Stdout in binary format.

        Sometimes logging is used to log binary objects too (example: Session),
        and for debug we can use this as a data source.
        :return: Full STDOUT output as bytearray.
        :rtype: bytearray
        """
        with self.stdout_lock:
            return _get_bytearray_from_array(self.stdout)

    @property
    def stderr_bin(self) -> bytearray:
        """Stderr in binary format.

        :return: Full STDERR output as bytearray.
        :rtype: bytearray
        """
        with self.stderr_lock:
            return _get_bytearray_from_array(self.stderr)

    @property
    def stdout_str(self) -> str:
        """Stdout output as string.

        :return: Full STDOUT output.
        :rtype: str
        """
        with self.stdout_lock:
            if self._stdout_str is None:
                self._stdout_str = _get_str_from_bin(self.stdout_bin)
            return self._stdout_str

    @property
    def stderr_str(self) -> str:
        """Stderr output as string.

        :return: Full STDERR output.
        :rtype: str
        """
        with self.stderr_lock:
            if self._stderr_str is None:
                self._stderr_str = _get_str_from_bin(self.stderr_bin)
            return self._stderr_str

    @property
    def stdout_brief(self) -> str:
        """Brief stdout output (mostly for exceptions).

        :return: Up to 3 first and 3 last lines of output.
        :rtype: str
        """
        with self.stdout_lock:
            if self._stdout_brief is None:
                self._stdout_brief = self._get_brief(self.stdout)
            return self._stdout_brief

    @property
    def stderr_brief(self) -> str:
        """Brief stderr output (mostly for exceptions).

        :return: Up to 3 first and 3 last lines of output.
        :rtype: str
        """
        with self.stderr_lock:
            if self._stderr_brief is None:
                self._stderr_brief = self._get_brief(self.stderr)
            return self._stderr_brief

    @property
    def stdout_lines(self) -> LinesAccessProxy:
        """Get lines by indexes.

        :return: Proxy object for lines join by line indexes.
        :rtype: LinesAccessProxy

        Usage example:

        .. code-block::python

            res.stdout_lines[<line_number>, <index_start>:<index_end>, ...]
        """
        return LinesAccessProxy(self.stdout)

    @property
    def stderr_lines(self) -> LinesAccessProxy:
        """Magic to get lines human-friendly way.

        :return: Proxy object for lines join by line indexes.
        :rtype: LinesAccessProxy
        """
        return LinesAccessProxy(self.stderr)

    @property
    def exit_code(self) -> ExitCodeT:
        """Return(exit) code of command.

        :return: Exit code.
        :rtype: int | proc_enums.ExitCodes
        """
        return self.__exit_code

    @exit_code.setter
    def exit_code(self, new_val: ExitCodeT) -> None:
        """Return(exit) code of command.

        :param new_val: New exit code.
        :type new_val: int | proc_enums.ExitCodes
        :raises RuntimeError: Exit code is already received.
        :raises TypeError: Exit code is not `int` instance.

        If valid exit code is set - object became read-only.
        """
        if self.timestamp:
            raise RuntimeError("Exit code is already received.")
        if not isinstance(new_val, int):
            raise TypeError(f"Exit code is strictly int, received: {new_val!r}")
        with self.stdout_lock, self.stderr_lock:
            self.__exit_code = proc_enums.exit_code_to_enum(new_val)
            if self.__exit_code != proc_enums.INVALID:
                self.__timestamp = datetime.datetime.now(tz=datetime.timezone.utc)

    @property
    def ok(self) -> bool:
        """Exit code is EX_OK.

        :return: Exit code is EX_OK.
        :rtype: bool
        """
        return self.exit_code == 0  # pylint: disable=use-implicit-booleaness-not-comparison-to-zero

    def check_exit_code(
        self,
        expected_codes: Iterable[ExitCodeT] = (0,),
        raise_on_err: bool = True,
        *,
        error_info: str | None = None,
        exception_class: type[exceptions.CalledProcessError] = exceptions.CalledProcessError,
        logger: logging.Logger = LOGGER,
        verbose: bool = False,
    ) -> None:
        """Check exit code and log/raise for unexpected code.

        :param error_info: Optional additional error information.
        :type error_info: str | None
        :param raise_on_err: Raise `exception_class` in case of error.
        :type raise_on_err: bool
        :param expected_codes: Iterable expected exit codes.
        :type expected_codes: Iterable[int | ExitCodes]
        :param exception_class: Exception class for usage in case of errors (subclass of CalledProcessError).
        :type exception_class: type[exceptions.CalledProcessError]
        :param logger: Logger instance for error log.
        :type logger: logging.Logger
        :param verbose: Produce verbose log in case of failure.
        :type verbose: bool
        :raises exceptions.CalledProcessError: Unexpected exit code and raise_on_err enabled.
        """
        append: str = error_info + "\n" if error_info else ""
        expected = tuple(frozenset(expected_codes))
        if self.exit_code not in expected:
            message = f"{append}Command {self.cmd!r} returned exit code {self.exit_code!s} while expected {expected!s}"
            if verbose:
                message += f"\nSTDOUT:\n{self.stdout_str}\n\nSTDERR:\n{self.stderr_str}"
            else:
                message += f"\nBrief STDOUT:\n{self.stdout_brief}\n\nBrief STDERR:\n{self.stderr_brief}"
            logger.error(msg=message)
            if raise_on_err:
                self.raise_for_status(expected_codes=expected, exception_class=exception_class)

    def raise_for_status(
        self,
        expected_codes: Collection[ExitCodeT] = (0,),
        *,
        exception_class: type[exceptions.CalledProcessError] = exceptions.CalledProcessError,
    ) -> None:
        """Requests-like exit code checker.

        :param expected_codes: Iterable expected exit codes.
        :type expected_codes: Iterable[int | ExitCodes]
        :param exception_class: Exception class for usage in case of errors (subclass of CalledProcessError).
        :type exception_class: type[exceptions.CalledProcessError]
        :raises exceptions.CalledProcessError: Unexpected exit code and raise_on_err enabled.
        """
        if self.exit_code in expected_codes:
            return

        raise exception_class(self, expected_codes)

    @property
    def started(self) -> datetime.datetime | None:
        """Timestamp of command start.

        :return: Timestamp from command start, if applicable.
        :rtype: datetime.datetime | None
        .. versionadded:: 4.0.0
        """
        return self.__started

    @property
    @_handle_deserialize("json")
    def stdout_json(
        self,
    ) -> typing.Any:
        """JSON from stdout.

        :return: Decoded JSON document.
        :rtype: typing.Any
        :raises DeserializeValueError: STDOUT cannot be deserialized as JSON.
        """
        with self.stdout_lock:
            return json.loads(self.stdout_str)

    if yaml is not None or ruamel_yaml is not None:

        @property
        @_handle_deserialize("yaml")
        def stdout_yaml(self) -> typing.Any:
            """YAML from stdout.

            :return: Decoded YAML document.
            :rtype: typing.Any
            :raises DeserializeValueError: STDOUT cannot be deserialized as YAML.
            """
            with self.stdout_lock:
                if yaml is not None:
                    if yaml.__with_libyaml__:  # pragma: no cover
                        return yaml.load(self.stdout_str, Loader=yaml.CSafeLoader)  # nosec  # Safe
                    return yaml.safe_load(self.stdout_str)  # pragma: no cover
                return ruamel_yaml.YAML(typ="safe").load(self.stdout_str)  # nosec  # Safe

    if defusedxml is not None:
        # noinspection PyUnresolvedReferences
        @property
        @_handle_deserialize("xml")
        def stdout_xml(self) -> ET.Element:
            """XML from stdout.

            :return: Decoded XML document.
            :rtype: xml.etree.ElementTree.Element
            :raises DeserializeValueError: STDOUT cannot be deserialized as XML.
            """
            with self.stdout_lock:
                return defusedxml.ElementTree.fromstring(b"".join(self.stdout))  # type: ignore[no-any-return]

    if lxml is not None:

        @property
        @_handle_deserialize("lxml")
        def stdout_lxml(self) -> lxml.etree.Element:
            """XML from stdout using lxml.

            :return: Decoded XML document.
            :rtype: lxml.etree.Element
            :raises DeserializeValueError: STDOUT cannot be deserialized as XML.

            .. note:: Can be insecure.
            """
            with self.stdout_lock:
                return lxml.etree.fromstring(b"".join(self.stdout))  # nosec[blacklist]

    def __dir__(self) -> list[str]:
        """Override dir for IDE and as source for getitem checks.

        :return: list with public attributes and methods
        :rtype: list[str]
        """
        content = [
            "cmd",
            "stdout",
            "stderr",
            "exit_code",
            "stdout_bin",
            "stderr_bin",
            "stdout_str",
            "stderr_str",
            "stdout_brief",
            "stderr_brief",
            "stdout_lines",
            "stderr_lines",
            "stdout_json",
            "lock",
        ]
        if yaml is not None or ruamel_yaml is not None:
            content.append("stdout_yaml")
        if defusedxml is not None:
            content.append("stdout_xml")
        if lxml is not None:
            content.append("stdout_lxml")
        return content

    def __getitem__(self, item: str) -> typing.Any:
        """Dict like get data.

        :param item: Key.
        :type item: str
        :return: Item if attribute exists.
        :rtype: typing.Any
        :raises IndexError: No attribute exists or not allowed to get (not in dir()).
        """
        if item in dir(self):
            return getattr(self, item)
        raise IndexError(f'"{item}" not found in {dir(self)}')

    def __repr__(self) -> str:
        """Representation for debugging.

        :return: full representation for debug purposes
        :rtype: str
        """
        if self.started:
            started = f" started={self.started!r},"
        else:
            started = ""
        return (
            f"{self.__class__.__name__}("
            f"cmd={self.cmd!r}, stdout={self.stdout!r}, stderr={self.stderr!r}, exit_code={self.exit_code!s},{started})"
        )

    def __pretty_repr__(
        self,
        log_wrap: logwrap.PrettyRepr,
        indent: int = 0,
        no_indent_start: bool = False,
    ) -> str:
        """Make human-readable representation of object.

        :param log_wrap: Logwrap instance.
        :type log_wrap: logwrap.PrettyRepr
        :param indent: Start indentation.
        :type indent: int
        :param no_indent_start: Do not indent open bracket and simple parameters.
        :type no_indent_start: bool
        :return: Formatted string.
        :rtype: str
        """
        next_indent = log_wrap.next_indent(indent)
        started = f"{'':<{next_indent}}started={self.started!r},\n" if self.started else ""
        stdout = log_wrap.process_element(self.stdout, indent=next_indent, no_indent_start=True)
        stderr = log_wrap.process_element(self.stderr, indent=next_indent, no_indent_start=True)
        msg = (
            f"{'':<{0 if no_indent_start else indent}}{self.__class__.__name__}(\n"
            f"{'':<{next_indent}}cmd={self.cmd!r},\n"
            f"{'':<{next_indent}}stdout={stdout},\n"
            f"{'':<{next_indent}}stderr={stderr},\n"
            f"{'':<{next_indent}}exit_code={self.exit_code!s},\n"
            f"{started}"
            f"{'':<{0 if no_indent_start else indent}})"
        )
        return msg

    def __str__(self) -> str:
        """Representation for logging.

        :return: String representation with brief information.
        :rtype: str
        """
        if self.started:
            started = f"\tstarted={self.started.strftime('%Y-%m-%d %H:%M:%S')},\n"
            if self.timestamp:
                _spent = (self.timestamp - self.started).seconds
                spent = f"\tspent={_spent // (60 * 60):02d}:{_spent // 60:02d}:{_spent % 60:02d},\n"
            else:
                spent = ""
        else:
            started = ""
            spent = ""
        return (
            f"{self.__class__.__name__}(\n"
            f"\tcmd={self.cmd!r},\n"
            f"\tstdout=\n"
            f"{self.stdout_brief!r},\n"
            f"\tstderr=\n"
            f"{self.stderr_brief!r}, \n"
            f"\texit_code={self.exit_code!s},\n"
            f"{started}{spent})"
        )

    def __eq__(self, other: object) -> bool:
        """Comparison.

        :param other: Other ExecResult instance.
        :type other: typing.Any
        :return: Current object equals other.
        :rtype: bool
        """
        return (
            self.__class__ is other.__class__
            or issubclass(self.__class__, other.__class__)
            or issubclass(other.__class__, self.__class__)
        ) and (
            self.cmd == other.cmd  # type: ignore[attr-defined]
            and self.stdin == other.stdin  # type: ignore[attr-defined]
            and self.stdout == other.stdout  # type: ignore[attr-defined]
            and self.stderr == other.stderr  # type: ignore[attr-defined]
            and self.exit_code == other.exit_code  # type: ignore[attr-defined]
        )

    def __ne__(self, other: object) -> bool:
        """Comparison.

        :param other: Other ExecResult instance.
        :type other: typing.Any
        :return: Current object doesn't equal other.
        :rtype: bool
        """
        return not self.__eq__(other)

    def __hash__(self) -> int:
        """Hash for usage as dict key and in sets.

        :return: Calculated hash value.
        :rtype: int
        """
        return hash((self.__class__, self.cmd, self.stdin, self.stdout, self.stderr, self.exit_code))
