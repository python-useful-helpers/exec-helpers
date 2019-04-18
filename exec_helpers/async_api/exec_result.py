#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.
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

"""Async execution result.

.. versionadded:: 3.0.0
"""

__all__ = ("ExecResult",)

# Standard Library
import logging
import typing

# Exec-Helpers Implementation
from exec_helpers import exec_result


class ExecResult(exec_result.ExecResult):
    """Execution result."""

    __slots__ = ()

    @staticmethod
    async def _poll_stream(  # type: ignore
        src: typing.AsyncIterable[bytes], log: typing.Optional[logging.Logger] = None, verbose: bool = False
    ) -> typing.List[bytes]:
        """Stream poll helper.

        :param src: source to read from
        :param log: logger instance, if line per line logging expected
        :param verbose: use INFO level for logging
        :returns: read result as list of bytes strings
        """
        dst: typing.List[bytes] = []
        try:
            async for line in src:
                dst.append(line)
                if log:
                    log.log(
                        level=logging.INFO if verbose else logging.DEBUG,
                        msg=line.decode("utf-8", errors="backslashreplace").rstrip(),
                    )
        except IOError:
            pass
        return dst

    async def read_stdout(  # type: ignore
        self,
        src: typing.Optional[typing.AsyncIterable[bytes]] = None,
        log: typing.Optional[logging.Logger] = None,
        verbose: bool = False,
    ) -> None:
        """Read asyncio stdout transport to stdout.

        :param src: source
        :type src: typing.Optional[typing.AsyncIterable]
        :param log: logger
        :type log: typing.Optional[logging.Logger]
        :param verbose: use log.info instead of log.debug
        :type verbose: bool
        :raises RuntimeError: Exit code is already received

        .. versionadded:: 3.0.0
        """
        if not src:
            return
        if self.timestamp:
            raise RuntimeError("Final exit code received.")

        with self.stdout_lock:
            self._stdout_str = self._stdout_brief = None
            self._stdout += tuple(await self._poll_stream(src, log, verbose))

    async def read_stderr(  # type: ignore
        self,
        src: typing.Optional[typing.AsyncIterable[bytes]] = None,
        log: typing.Optional[logging.Logger] = None,
        verbose: bool = False,
    ) -> None:
        """Read asyncio stderr transport to stdout.

        :param src: source
        :type src: typing.Optional[typing.AsyncIterable]
        :param log: logger
        :type log: typing.Optional[logging.Logger]
        :param verbose: use log.info instead of log.debug
        :type verbose: bool
        :raises RuntimeError: Exit code is already received

        .. versionadded:: 3.0.0
        """
        if not src:
            return
        if self.timestamp:
            raise RuntimeError("Final exit code received.")

        with self.stderr_lock:
            self._stderr_str = self._stderr_brief = None
            self._stderr += tuple(await self._poll_stream(src, log, verbose))
