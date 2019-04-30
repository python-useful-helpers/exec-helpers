#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.

#    Copyright 2016 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Execution result."""

__all__ = ("ExecResult",)

# Standard Library
import datetime
import json
import logging
import threading
import typing

# External Dependencies
import yaml

# Exec-Helpers Implementation
from exec_helpers import exceptions
from exec_helpers import proc_enums

LOGGER = logging.getLogger(__name__)


def _get_str_from_bin(src: bytearray) -> str:
    """Join data in list to the string.

    :param src: source to process
    :type src: bytearray
    :return: decoded string
    :rtype: str
    """
    return src.strip().decode(encoding="utf-8", errors="backslashreplace")


def _get_bytearray_from_array(src: typing.Iterable[bytes]) -> bytearray:
    """Get bytearray from array of bytes blocks.

    :param src: source to process
    :type src: typing.List[bytes]
    :return: bytearray
    :rtype: bytearray
    """
    return bytearray(b"".join(src))


class LinesAccessProxy:
    """Lines access proxy."""

    __slots__ = ("_data",)

    def __init__(self, data: typing.Sequence[bytes]) -> None:
        """Lines access proxy.

        :param data: data to work with.
        :type data: typing.Sequence[bytes]
        """
        self._data = tuple(data)  # type: typing.Tuple[bytes, ...]

    def __getitem__(self, item: typing.Union[int, slice, typing.Iterable[typing.Union[int, slice, "ellipsis"]]]) -> str:
        """Access magic.

        :param item: index
        :type item: typing.Union[int, slice, typing.Iterable[typing.Union[int, slice, ellipsis]]]
        :returns: Joined selected lines
        :rtype: str
        :raises TypeError: Unexpected key
        """
        if isinstance(item, int):
            return _get_str_from_bin(_get_bytearray_from_array([self._data[item]]))
        if isinstance(item, slice):
            return _get_str_from_bin(_get_bytearray_from_array(self._data[item]))
        if isinstance(item, tuple):
            buf = []  # type: typing.List[bytes]
            for rule in item:
                if isinstance(rule, int):
                    buf.append(self._data[rule])
                elif isinstance(rule, slice):
                    buf.extend(self._data[rule])
                elif rule is Ellipsis:
                    buf.append(b"...\n")
                else:
                    raise TypeError("Unexpected key type: {rule!r} (from {item!r})".format(rule=rule, item=item))
            return _get_str_from_bin(_get_bytearray_from_array(buf))
        raise TypeError("Unexpected key type: {item!r}".format(item=item))

    def __len__(self) -> int:  # pragma: no cover
        """Data len."""
        return len(self._data)

    def __str__(self) -> str:  # pragma: no cover
        """Get string for debug purposes."""
        return self[:]

    def __repr__(self) -> str:
        """Repr for debug purposes."""
        return "{cls}(data={self._data!r})".format(cls=self.__class__.__name__, self=self)


class ExecResult:
    """Execution result."""

    __slots__ = [
        "__cmd",
        "__stdin",
        "_stdout",
        "_stderr",
        "__exit_code",
        "__timestamp",
        "_stdout_str",
        "_stderr_str",
        "_stdout_brief",
        "_stderr_brief",
        "__stdout_lock",
        "__stderr_lock",
        "__started",
    ]

    def __init__(
        self,
        cmd: str,
        stdin: typing.Union[bytes, str, bytearray, None] = None,
        stdout: typing.Optional[typing.Iterable[bytes]] = None,
        stderr: typing.Optional[typing.Iterable[bytes]] = None,
        exit_code: typing.Union[int, proc_enums.ExitCodes] = proc_enums.INVALID,
        *,
        started: typing.Optional[datetime.datetime] = None
    ) -> None:
        """Command execution result.

        :param cmd: command
        :type cmd: str
        :param stdin: string STDIN
        :type stdin: typing.Union[bytes, str, bytearray, None]
        :param stdout: binary STDOUT
        :type stdout: typing.Optional[typing.Iterable[bytes]]
        :param stderr: binary STDERR
        :type stderr: typing.Optional[typing.Iterable[bytes]]
        :param exit_code: Exit code. If integer - try to convert to BASH enum.
        :type exit_code: typing.Union[int, proc_enums.ExitCodes]
        :param started: Timestamp of command start
        :type started: typing.Optional[datetime.datetime]
        """
        self.__stdout_lock = threading.RLock()
        self.__stderr_lock = threading.RLock()

        self.__cmd = cmd
        if isinstance(stdin, bytes):
            self.__stdin = _get_str_from_bin(bytearray(stdin))  # type: typing.Optional[str]
        elif isinstance(stdin, bytearray):
            self.__stdin = _get_str_from_bin(stdin)
        else:
            self.__stdin = stdin

        if stdout is not None:
            self._stdout = tuple(stdout)  # type: typing.Tuple[bytes, ...]
        else:
            self._stdout = ()

        if stderr is not None:
            self._stderr = tuple(stderr)  # type: typing.Tuple[bytes, ...]
        else:
            self._stderr = ()

        self.__exit_code = proc_enums.INVALID  # type: typing.Union[int, proc_enums.ExitCodes]
        self.__timestamp = None  # type: typing.Optional[datetime.datetime]
        self.exit_code = exit_code

        self.__started = started  # type: typing.Optional[datetime.datetime]

        # By default is none:
        self._stdout_str = None  # type: typing.Optional[str]
        self._stderr_str = None  # type: typing.Optional[str]
        self._stdout_brief = None  # type: typing.Optional[str]
        self._stderr_brief = None  # type: typing.Optional[str]

    @property
    def stdout_lock(self) -> threading.RLock:
        """Lock object for thread-safe operation.

        :return: internal lock for stdout
        :rtype: threading.RLock

        .. versionadded:: 2.2.0
        """
        return self.__stdout_lock

    @property
    def stderr_lock(self) -> threading.RLock:
        """Lock object for thread-safe operation.

        :return: internal lock for stderr
        :rtype: threading.RLock

        .. versionadded:: 2.2.0
        """
        return self.__stderr_lock

    @property
    def timestamp(self) -> typing.Optional[datetime.datetime]:
        """Timestamp.

        :return: exit code timestamp
        :rtype: typing.Optional[datetime.datetime]
        """
        return self.__timestamp

    def set_timestamp(self) -> None:
        """Set timestamp if empty.

        This will block future object changes.

        .. versionadded:: 3.5.0
        """
        if self.timestamp is None:
            self.__timestamp = datetime.datetime.utcnow()

    @classmethod
    def _get_brief(cls, data: typing.Tuple[bytes, ...]) -> str:
        """Get brief output: 7 lines maximum (3 first + ... + 3 last).

        :param data: source to process
        :type data: typing.Tuple[bytes, ...]
        :return: brief from source
        :rtype: str
        """
        if len(data) <= 7:
            return _get_str_from_bin(_get_bytearray_from_array(data))
        return LinesAccessProxy(data)[:3, ..., -3:]

    @property
    def cmd(self) -> str:
        """Executed command.

        :rtype: str
        """
        return self.__cmd

    @property
    def stdin(self) -> typing.Optional[str]:
        """Stdin input as string.

        :rtype: typing.Optional[str]
        """
        return self.__stdin

    @property
    def stdout(self) -> typing.Tuple[bytes, ...]:
        """Stdout output as list of binaries.

        :rtype: typing.Tuple[bytes, ...]
        """
        return self._stdout

    @property
    def stderr(self) -> typing.Tuple[bytes, ...]:
        """Stderr output as list of binaries.

        :rtype: typing.Tuple[bytes, ...]
        """
        return self._stderr

    @staticmethod
    def _poll_stream(
        src: typing.Iterable[bytes], log: typing.Optional[logging.Logger] = None, verbose: bool = False
    ) -> typing.List[bytes]:
        """Stream poll helper.

        :param src: source to read from
        :param log: logger instance, if line per line logging expected
        :param verbose: use INFO level for logging
        :returns: read result as list of bytes strings
        """
        dst = []  # type: typing.List[bytes]
        try:
            for line in src:
                dst.append(line)
                if log:
                    log.log(
                        level=logging.INFO if verbose else logging.DEBUG,
                        msg=line.decode("utf-8", errors="backslashreplace").rstrip(),
                    )
        except IOError:
            pass
        return dst

    def read_stdout(
        self,
        src: typing.Optional[typing.Iterable[bytes]] = None,
        log: typing.Optional[logging.Logger] = None,
        verbose: bool = False,
    ) -> None:
        """Read stdout file-like object to stdout.

        :param src: source
        :type src: typing.Optional[typing.Iterable]
        :param log: logger
        :type log: typing.Optional[logging.Logger]
        :param verbose: use log.info instead of log.debug
        :type verbose: bool
        :raises RuntimeError: Exit code is already received

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
        src: typing.Optional[typing.Iterable[bytes]] = None,
        log: typing.Optional[logging.Logger] = None,
        verbose: bool = False,
    ) -> None:
        """Read stderr file-like object to stdout.

        :param src: source
        :type src: typing.Optional[typing.Iterable]
        :param log: logger
        :type log: typing.Optional[logging.Logger]
        :param verbose: use log.info instead of log.debug
        :type verbose: bool
        :raises RuntimeError: Exit code is already received

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
        and for debug purposes we can use this as data source.
        :rtype: bytearray
        """
        with self.stdout_lock:
            return _get_bytearray_from_array(self.stdout)

    @property
    def stderr_bin(self) -> bytearray:
        """Stderr in binary format.

        :rtype: bytearray
        """
        with self.stderr_lock:
            return _get_bytearray_from_array(self.stderr)

    @property
    def stdout_str(self) -> str:
        """Stdout output as string.

        :rtype: str
        """
        with self.stdout_lock:
            if self._stdout_str is None:
                self._stdout_str = _get_str_from_bin(self.stdout_bin)
            return self._stdout_str

    @property
    def stderr_str(self) -> str:
        """Stderr output as string.

        :rtype: str
        """
        with self.stderr_lock:
            if self._stderr_str is None:
                self._stderr_str = _get_str_from_bin(self.stderr_bin)
            return self._stderr_str

    @property
    def stdout_brief(self) -> str:
        """Brief stdout output (mostly for exceptions).

        :rtype: str
        """
        with self.stdout_lock:
            if self._stdout_brief is None:
                self._stdout_brief = self._get_brief(self.stdout)
            return self._stdout_brief

    @property
    def stderr_brief(self) -> str:
        """Brief stderr output (mostly for exceptions).

        :rtype: str
        """
        with self.stderr_lock:
            if self._stderr_brief is None:
                self._stderr_brief = self._get_brief(self.stderr)
            return self._stderr_brief

    @property
    def stdout_lines(self) -> LinesAccessProxy:
        """Get lines by indexes.

        :rtype: LinesAccessProxy

        Usage example:

        .. code-block::python

            res.stdout_lines[<line_number>, <index_start>:<index_end>, ...]
        """
        return LinesAccessProxy(self.stdout)

    @property
    def stderr_lines(self) -> LinesAccessProxy:
        """Magic to get lines human-friendly way.

        :rtype: LinesAccessProxy
        """
        return LinesAccessProxy(self.stderr)

    @property
    def exit_code(self) -> typing.Union[int, proc_enums.ExitCodes]:
        """Return(exit) code of command.

        :return: exit code
        :rtype: typing.Union[int, proc_enums.ExitCodes]
        """
        return self.__exit_code

    @exit_code.setter
    def exit_code(self, new_val: typing.Union[int, proc_enums.ExitCodes]) -> None:
        """Return(exit) code of command.

        :param new_val: new exit code
        :type new_val: typing.Union[int, proc_enums.ExitCodes]
        :raises RuntimeError: Exit code is already received
        :raises TypeError: exit code is not int instance

        If valid exit code is set - object became read-only.
        """
        if self.timestamp:
            raise RuntimeError("Exit code is already received.")
        if not isinstance(new_val, int):
            raise TypeError("Exit code is strictly int, received: {code!r}".format(code=new_val))
        with self.stdout_lock, self.stderr_lock:
            self.__exit_code = proc_enums.exit_code_to_enum(new_val)
            if self.__exit_code != proc_enums.INVALID:
                self.__timestamp = datetime.datetime.utcnow()

    @property
    def started(self) -> typing.Optional[datetime.datetime]:
        """Timestamp of command start.

        :returns: timestamp from command start, if applicable
        .. versionadded:: 3.5.0
        """
        return self.__started

    def __deserialize(self, fmt: str) -> typing.Any:
        """Deserialize stdout as data format.

        :param fmt: format to decode from
        :type fmt: str
        :return: decoded object
        :rtype: typing.Any
        :raises NotImplementedError: fmt deserialization not implemented
        :raises DeserializeValueError: Not valid source format
        """
        try:
            if fmt == "json":
                return json.loads(self.stdout_str, encoding="utf-8")
            if fmt == "yaml":
                if yaml.__with_libyaml__:
                    return yaml.load(self.stdout_str, Loader=yaml.CSafeLoader)  # nosec  # Safe
                return yaml.safe_load(self.stdout_str)
        except Exception as e:
            tmpl = "{{self.cmd}} stdout is not valid {fmt}:\n" "{{stdout!r}}\n".format(fmt=fmt)
            LOGGER.exception(tmpl.format(self=self, stdout=self.stdout_str))

            raise exceptions.DeserializeValueError(tmpl.format(self=self, stdout=self.stdout_brief)).with_traceback(
                e.__traceback__
            ) from e

        msg = "{fmt} deserialize target is not implemented".format(fmt=fmt)
        LOGGER.error(msg)
        raise NotImplementedError(msg)

    @property
    def stdout_json(self) -> typing.Any:
        """JSON from stdout.

        :rtype: typing.Any
        """
        with self.stdout_lock:
            return self.__deserialize(fmt="json")

    @property
    def stdout_yaml(self) -> typing.Any:
        """YAML from stdout.

        :rtype: typing.Any
        """
        with self.stdout_lock:
            return self.__deserialize(fmt="yaml")

    def __dir__(self) -> typing.List[str]:
        """Override dir for IDE and as source for getitem checks."""
        return [
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
            "stdout_yaml",
            "lock",
        ]

    def __getitem__(self, item: str) -> typing.Any:
        """Dict like get data.

        :param item: key
        :type item: str
        :return: item if attribute exists
        :rtype: typing.Any
        :raises IndexError: no attribute exists or not allowed to get (not in dir())
        """
        if item in dir(self):
            return getattr(self, item)
        raise IndexError('"{item}" not found in {dir}'.format(item=item, dir=dir(self)))

    def __repr__(self) -> str:
        """Representation for debugging."""
        if self.started:
            started = ", started={self.started},\n".format(self=self)
        else:
            started = ""
        return (
            "{cls}(cmd={self.cmd!r}, stdout={self.stdout}, stderr={self.stderr}, "
            "exit_code={self.exit_code!s}{started},)".format(cls=self.__class__.__name__, self=self, started=started)
        )

    def __str__(self) -> str:
        """Representation for logging."""
        if self.started:
            started = "\tstarted={started},\n".format(started=self.started.strftime("%Y-%m-%d %H:%M:%S"))
            if self.timestamp:
                _spent = (self.timestamp - self.started).seconds
                spent = "\tspent={hours:02d}:{minutes:02d}:{seconds:02d},\n".format(
                    hours=_spent // (60 * 60), minutes=_spent // 60, seconds=_spent % 60
                )
            else:
                spent = ""
        else:
            started = ""
            spent = ""
        return (
            "{cls}(\n\tcmd={cmd!r},"
            "\n\tstdout=\n'{stdout_brief}',"
            "\n\tstderr=\n'{stderr_brief}', "
            "\n\texit_code={exit_code!s},"
            "\n{started}{spent})".format(
                cls=self.__class__.__name__,
                cmd=self.cmd,
                stdout_brief=self.stdout_brief,
                stderr_brief=self.stderr_brief,
                exit_code=self.exit_code,
                started=started,
                spent=spent,
            )
        )

    def __eq__(self, other: typing.Any) -> bool:
        """Comparision.

        :param other: other ExecResult instance.
        :returns: current object equals other
        """
        return (
            self.__class__ is other.__class__
            or issubclass(self.__class__, other.__class__)
            or issubclass(other.__class__, self.__class__)
        ) and (
            self.cmd == other.cmd
            and self.stdin == other.stdin
            and self.stdout == other.stdout
            and self.stderr == other.stderr
            and self.exit_code == other.exit_code
        )

    def __ne__(self, other: typing.Any) -> bool:
        """Comparision.

        :param other: other ExecResult instance.
        :returns: current object not equals other
        """
        return not self.__eq__(other)

    def __hash__(self) -> int:
        """Hash for usage as dict key and in sets."""
        return hash((self.__class__, self.cmd, self.stdin, self.stdout, self.stderr, self.exit_code))
