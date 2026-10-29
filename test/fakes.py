#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.
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

"""Fake process and channel objects shared by the tests of the command execution."""

from __future__ import annotations

import asyncio
import typing
from unittest import mock

host = "127.0.0.1"
host2 = "127.0.0.2"
port = 22
PROCESS_PID = 4242


class FakeFileStream:
    """Process stream, sync and async: yields the bytes lines and raises the exceptions found in the source."""

    def __init__(self, *lines: bytes | BaseException) -> None:
        self.__src = list(lines)
        self.closed = False

    def __iter__(self) -> typing.Iterator[bytes]:
        """Iterate over the source until it is exhausted."""
        while self.__src:
            item = self.__src.pop(0)
            if isinstance(item, BaseException):
                raise item
            yield item

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        """Iterate over the source the same way for the async reader."""
        for item in self:
            await asyncio.sleep(0)  # reading a pipe suspends the reader
            yield item

    def fileno(self) -> int:
        return id(self)

    def close(self) -> None:
        """Mark the stream as closed."""
        self.closed = True

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def fake_channel(
    *,
    stdout: tuple[bytes, ...] | None = (),
    stderr: tuple[bytes, ...] | None = (),
    exit_code: int = 0,
) -> mock.MagicMock:
    """Create the finished channel: `None` instead of a stream means that the stream is not read."""
    chan = mock.MagicMock(closed=False, exit_status=exit_code)
    chan.__enter__.return_value = chan
    chan.recv_exit_status.return_value = exit_code
    chan.status_event.is_set.return_value = True
    chan.status_event.wait.return_value = True
    stdin_file = mock.MagicMock(channel=chan)
    stdin_file.__enter__.return_value = stdin_file
    chan.stdin_file = stdin_file

    def makefile(flags: str) -> mock.MagicMock | FakeFileStream:
        if flags == "wb":
            return stdin_file
        if flags == "rb":
            return FakeFileStream(*(stdout or ()))
        raise ValueError(f"Unexpected flags: {flags!r}")

    chan.makefile.side_effect = makefile
    chan.makefile_stderr.side_effect = lambda _flags: FakeFileStream(*(stderr or ()))
    return chan
