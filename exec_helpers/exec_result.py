#    Copyright 2018 Alexey Stepanov aka penguinolog.

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

"""Execution restult."""

from __future__ import absolute_import
from __future__ import unicode_literals

import datetime
import json
import logging
import threading
import typing

import six
import yaml

from exec_helpers import exceptions
from exec_helpers import proc_enums

__all__ = ('ExecResult', )

logger = logging.getLogger(__name__)
_type_exit_codes = typing.Union[int, proc_enums.ExitCodes]


class ExecResult(object):
    """Execution result."""

    __slots__ = [
        '__cmd', '__stdout', '__stderr', '__exit_code',
        '__timestamp',
        '__stdout_str', '__stderr_str', '__stdout_brief', '__stderr_brief',
        '__lock'
    ]

    def __init__(
        self,
        cmd,  # type: str
        stdout=None,  # type: typing.Optional[typing.Container[bytes]]
        stderr=None,  # type: typing.Optional[typing.Container[bytes]]
        exit_code=proc_enums.ExitCodes.EX_INVALID  # type: _type_exit_codes
    ):
        """Command execution result.

        :type cmd: str
        :type stdout: typing.Optional[typing.Container[bytes]]
        :type stderr: typing.Optional[typing.Container[bytes]]
        :type exit_code: typing.Union[int, proc_enums.ExitCodes]
        """
        self.__lock = threading.RLock()

        self.__cmd = cmd
        self.__stdout = tuple(stdout) if stdout is not None else ()
        self.__stderr = tuple(stderr) if stderr is not None else ()

        self.__exit_code = None
        self.__timestamp = None
        self.exit_code = exit_code

        # By default is none:
        self.__stdout_str = None
        self.__stderr_str = None
        self.__stdout_brief = None
        self.__stderr_brief = None

    @property
    def lock(self):  # type: () -> threading.RLock
        """Lock object for thread-safe operation.

        :rtype: threading.RLock
        """
        return self.__lock

    @property
    def timestamp(self):  # type: () -> typing.Optional(datetime.datetime)
        """Timestamp.

        :rtype: typing.Optional(datetime.datetime)
        """
        return self.__timestamp

    @staticmethod
    def _get_bytearray_from_array(
        src  # type: typing.Iterable[bytes]
    ):  # type: (...) -> bytearray
        """Get bytearray from array of bytes blocks.

        :type src: typing.List[bytes]
        :rtype: bytearray
        """
        return bytearray(b''.join(src))

    @staticmethod
    def _get_str_from_bin(src):  # type: (bytearray) -> str
        """Join data in list to the string, with python 2&3 compatibility.

        :type src: bytearray
        :rtype: str
        """
        return src.strip().decode(
            encoding='utf-8',
            errors='backslashreplace'
        )

    @classmethod
    def _get_brief(cls, data):  # type: (typing.Tuple[bytes]) -> str
        """Get brief output: 7 lines maximum (3 first + ... + 3 last).

        :type data: typing.List[bytes]
        :rtype: str
        """
        src = data if len(data) <= 7 else data[:3] + (b'...\n',) + data[-3:]
        return cls._get_str_from_bin(
            cls._get_bytearray_from_array(src)
        )

    @property
    def cmd(self):  # type: () -> str
        """Executed command.

        :rtype: str
        """
        return self.__cmd

    @property
    def stdout(self):  # type: () -> typing.Tuple[bytes]
        """Stdout output as list of binaries.

        :rtype: typing.Tuple[bytes]
        """
        return self.__stdout

    @property
    def stderr(self):  # type: () -> typing.Tuple[bytes]
        """Stderr output as list of binaries.

        :rtype: typing.Tuple[bytes]
        """
        return self.__stderr

    @staticmethod
    def __poll_stream(
        src,  # type: typing.Iterable[bytes]
        log=None,  # type: typing.Optional[logging.Logger]
        verbose=False  # type: bool
    ):  # type: (...) -> typing.List[bytes]
        dst = []
        try:
            for line in src:
                dst.append(line)
                if log:
                    log.log(
                        level=logging.INFO if verbose else logging.DEBUG,
                        msg=line.decode(
                            'utf-8',
                            errors='backslashreplace'
                        ).rstrip()
                    )
        except IOError:
            pass
        return dst

    def read_stdout(
        self,
        src,  # type: typing.Iterable
        log=None,  # type: typing.Optional[logging.Logger]
        verbose=False  # type: bool
    ):
        """Read stdout file-like object to stdout."""
        if self.timestamp:
            raise RuntimeError('Final exit code received.')
        with self.lock:
            self.__stdout_str = self.__stdout_brief = None
            self.__stdout += tuple(self.__poll_stream(src, log, verbose))

    def read_stderr(
        self,
        src,  # type: typing.Iterable
        log=None,  # type: typing.Optional[logging.Logger]
        verbose=False  # type: bool
    ):
        """Read stderr file-like object to stdout."""
        if self.timestamp:
            raise RuntimeError('Final exit code received.')
        with self.lock:
            self.__stderr_str = self.__stderr_brief = None
            self.__stderr += tuple(self.__poll_stream(src, log, verbose))

    @property
    def stdout_bin(self):  # type: () -> bytearray
        """Stdout in binary format.

        Sometimes logging is used to log binary objects too (example: Session),
        and for debug purposes we can use this as data source.
        :rtype: bytearray
        """
        with self.lock:
            return self._get_bytearray_from_array(self.stdout)

    @property
    def stderr_bin(self):  # type: () -> bytearray
        """Stderr in binary format.

        :rtype: bytearray
        """
        with self.lock:
            return self._get_bytearray_from_array(self.stderr)

    @property
    def stdout_str(self):  # type: () -> str
        """Stdout output as string.

        :rtype: str
        """
        with self.lock:
            if self.__stdout_str is None:
                self.__stdout_str = self._get_str_from_bin(self.stdout_bin)
            return self.__stdout_str

    @property
    def stderr_str(self):  # type: () -> str
        """Stderr output as string.

        :rtype: str
        """
        with self.lock:
            if self.__stderr_str is None:
                self.__stderr_str = self._get_str_from_bin(self.stderr_bin)
            return self.__stderr_str

    @property
    def stdout_brief(self):  # type: () -> str
        """Brief stdout output (mostly for exceptions).

        :rtype: str
        """
        with self.lock:
            if self.__stdout_brief is None:
                self.__stdout_brief = self._get_brief(self.stdout)
            return self.__stdout_brief

    @property
    def stderr_brief(self):  # type: () -> str
        """Brief stderr output (mostly for exceptions).

        :rtype: str
        """
        with self.lock:
            if self.__stderr_brief is None:
                self.__stderr_brief = self._get_brief(self.stderr)
            return self.__stderr_brief

    @property
    def exit_code(self):  # type: () -> typing.Union[int, proc_enums.ExitCodes]
        """Return(exit) code of command.

        :rtype: typing.Union[int, proc_enums.ExitCodes]
        """
        return self.__exit_code

    @exit_code.setter
    def exit_code(self, new_val):  # type: (_type_exit_codes) -> None
        """Return(exit) code of command.

        :type new_val: int
        If valid exit code is set - object became read-only.
        """
        if self.timestamp:
            raise RuntimeError('Exit code is already received.')
        if not isinstance(new_val, six.integer_types):
            raise TypeError('Exit code is strictly int')
        with self.lock:
            self.__exit_code = proc_enums.exit_code_to_enum(new_val)
            if self.__exit_code != proc_enums.ExitCodes.EX_INVALID:
                self.__timestamp = datetime.datetime.utcnow()

    def __deserialize(self, fmt):  # type: (str) -> typing.Any
        """Deserialize stdout as data format.

        :type fmt: str
        :rtype: object
        :raises: DevopsError
        """
        try:
            if fmt == 'json':
                return json.loads(self.stdout_str, encoding='utf-8')
            elif fmt == 'yaml':
                return yaml.safe_load(self.stdout_str)
        except Exception:
            tmpl = (
                " stdout is not valid {fmt}:\n"
                '{{stdout!r}}\n'.format(
                    fmt=fmt))
            logger.exception(self.cmd + tmpl.format(stdout=self.stdout_str))
            raise exceptions.ExecWrapperError(
                self.cmd + tmpl.format(stdout=self.stdout_brief)
            )
        msg = '{fmt} deserialize target is not implemented'.format(fmt=fmt)
        logger.error(msg)
        raise NotImplementedError(msg)

    @property
    def stdout_json(self):  # type: () -> typing.Any
        """JSON from stdout.

        :rtype: object
        """
        with self.lock:
            return self.__deserialize(fmt='json')

    @property
    def stdout_yaml(self):  # type: () -> typing.Any
        """YAML from stdout.

        :rtype: Union(list, dict, None)
        """
        with self.lock:
            return self.__deserialize(fmt='yaml')

    def __dir__(self):
        """Override dir for IDE and as source for getitem checks."""
        return [
            'cmd', 'stdout', 'stderr', 'exit_code',
            'stdout_bin', 'stderr_bin',
            'stdout_str', 'stderr_str', 'stdout_brief', 'stderr_brief',
            'stdout_json', 'stdout_yaml',
            'lock'
        ]

    def __getitem__(self, item):
        """Dict like get data."""
        if item in dir(self):
            return getattr(self, item)
        raise IndexError(
            '"{item}" not found in {dir}'.format(
                item=item, dir=dir(self)
            )
        )

    def __repr__(self):
        """Representation for debugging."""
        return (
            '{cls}(cmd={cmd!r}, stdout={stdout}, stderr={stderr}, '
            'exit_code={exit_code!s})'.format(
                cls=self.__class__.__name__,
                cmd=self.cmd,
                stdout=self.stdout,
                stderr=self.stderr,
                exit_code=self.exit_code
            ))

    def __str__(self):
        """Representation for logging."""
        return (
            "{cls}(\n\tcmd={cmd!r},"
            "\n\t stdout=\n'{stdout_brief}',"
            "\n\tstderr=\n'{stderr_brief}', "
            '\n\texit_code={exit_code!s}\n)'.format(
                cls=self.__class__.__name__,
                cmd=self.cmd,
                stdout_brief=self.stdout_brief,
                stderr_brief=self.stderr_brief,
                exit_code=self.exit_code
            )
        )

    def __eq__(self, other):
        """Comparsion."""
        return all(
            (
                getattr(self, val) == getattr(other, val)
                for val in ['cmd', 'stdout', 'stderr', 'exit_code']
            )
        )

    def __ne__(self, other):
        """Comparsion."""
        return not self.__eq__(other)

    def __hash__(self):
        """Hash for usage as dict key and in sets."""
        return hash(
            (
                self.__class__, self.cmd, self.stdout, self.stderr,
                self.exit_code
            ))
