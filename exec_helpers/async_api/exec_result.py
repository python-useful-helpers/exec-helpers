#    Copyright 2018 - 2023 Aleksei Stepanov aka penguinolog.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Async execution result.

.. versionadded:: 3.0.0
"""

from __future__ import annotations

import contextlib
import logging
import typing

if typing.TYPE_CHECKING:
    from collections.abc import AsyncIterable

from exec_helpers import exec_result  # pylint: disable=wrong-import-position

__all__ = ("ExecResult",)


class ExecResult(exec_result.ExecResult):
    """Execution result."""

    __slots__ = ()

    @staticmethod
    async def _poll_stream(  # type: ignore[override]  # pylint: disable=invalid-overridden-method
        src: AsyncIterable[bytes],
        log: logging.Logger | None = None,
        verbose: bool = False,
    ) -> list[bytes]:
        """Stream poll helper.

        :param src: Source to read from.
        :param log: Logger instance, if line per-line logging is expected.
        :param verbose: Use INFO level for logging.
        :return: Read result as a list of byte strings.
        """
        dst: list[bytes] = []
        with contextlib.suppress(IOError):
            async for line in src:
                dst.append(line)
                if log:
                    log.log(
                        level=logging.INFO if verbose else logging.DEBUG,
                        msg=line.decode("utf-8", errors="backslashreplace").rstrip(),
                    )
        return dst

    async def read_stdout(  # type: ignore[override]  # pylint: disable=invalid-overridden-method
        self,
        src: AsyncIterable[bytes] | None = None,
        log: logging.Logger | None = None,
        verbose: bool = False,
    ) -> None:
        """Read asyncio stdout transport to stdout.

        :param src: Source.
        :type src: AsyncIterable[bytes] | None
        :param log: Logger.
        :type log: logging.Logger | None
        :param verbose: Use log.info instead of log.debug.
        :type verbose: bool
        :raises RuntimeError: Exit code is already received.

        .. versionadded:: 3.0.0
        """
        if not src:
            return
        if self.timestamp:
            raise RuntimeError("Final exit code received.")

        with self.stdout_lock:
            self._stdout_str = self._stdout_brief = None
            self._stdout += tuple(await self._poll_stream(src, log, verbose))

    async def read_stderr(  # type: ignore[override]  # pylint: disable=invalid-overridden-method
        self,
        src: AsyncIterable[bytes] | None = None,
        log: logging.Logger | None = None,
        verbose: bool = False,
    ) -> None:
        """Read asyncio stderr transport to stdout.

        :param src: Source.
        :type src: AsyncIterable[bytes] | None
        :param log: Logger.
        :type log: logging.Logger | None
        :param verbose: Use log.info instead of log.debug.
        :type verbose: bool
        :raises RuntimeError: Exit code is already received.

        .. versionadded:: 3.0.0
        """
        if not src:
            return
        if self.timestamp:
            raise RuntimeError("Final exit code received.")

        with self.stderr_lock:
            self._stderr_str = self._stderr_brief = None
            self._stderr += tuple(await self._poll_stream(src, log, verbose))
