#    Copyright 2019 - 2020 Alexey Stepanov aka penguinolog.
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

"""Shared pytest logic."""

from __future__ import annotations

import asyncio
import typing
from unittest import mock

import pytest

import exec_helpers
from fakes import PROCESS_PID
from fakes import FakeFileStream
from fakes import host
from fakes import port


@pytest.fixture(autouse=True)
def no_real_local_host_keys(mocker):
    """Do not allow real host SSH server keys usage."""
    mocker.patch("exec_helpers._ssh_helpers.local_host_keys", return_value=())


@pytest.fixture
def no_real_ssh_config(mocker):
    """Do not allow real host ssh config usage."""
    conf_sys: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_SYSTEM", autospec=True)
    conf_user: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_USER", autospec=True)
    conf_sys.exists.return_value = False
    conf_user.exists.return_value = False


@pytest.fixture
def paramiko_ssh_client(mocker, no_real_ssh_config) -> mock.MagicMock:
    """Minimal paramiko.SSHClient mock."""
    mocker.patch("time.sleep")
    return mocker.patch("paramiko.SSHClient", autospec=True)


@pytest.fixture
def ssh_auth_logger(mocker) -> mock.MagicMock:
    """Minimal exec_helpers.ssh_auth.logger mock."""
    return mocker.patch("exec_helpers.ssh_auth.LOGGER")


@pytest.fixture
def subprocess_logger(mocker) -> mock.MagicMock:
    """Minimal exec_helpers.subprocess.Subprocess.logger mock."""
    return mocker.patch("exec_helpers.subprocess.Subprocess.logger", autospec=True)


@pytest.fixture
def get_logger(mocker) -> mock.MagicMock:
    """Minimal logging.getLogger mock."""
    return mocker.patch("logging.getLogger")


@pytest.fixture
def no_real_process_control(mocker) -> None:
    """Do not allow a mocked pid to reach a real process or a real signal."""
    mocker.patch("psutil.Process")
    mocker.patch("psutil.wait_procs", return_value=([], []))
    mocker.patch("os.kill")
    mocker.patch("os.killpg")
    mocker.patch("signal.pthread_kill")


@pytest.fixture
def fake_popen(mocker, no_real_process_control) -> typing.Callable[..., mock.MagicMock]:
    """Patch `subprocess.Popen` and return the factory of the process it creates."""

    def create(
        *,
        stdout: tuple[bytes | BaseException, ...] | None = (),
        stderr: tuple[bytes | BaseException, ...] | None = None,
        wait: typing.Sequence[int | BaseException] = (0,),
        poll: typing.Sequence[int | None] = (0,),
        stdin_write: BaseException | None = None,
        stdin_close: BaseException | None = None,
    ) -> mock.MagicMock:
        """Create the process: `None` instead of a stream means that the pipe is not opened.

        `stdin_write` and `stdin_close` are the exceptions the stdin pipe raises, if any.
        """
        proc = mocker.MagicMock(pid=PROCESS_PID, returncode=0)
        proc.__enter__.return_value = proc
        proc.stdout = None if stdout is None else FakeFileStream(*stdout)
        proc.stderr = None if stderr is None else FakeFileStream(*stderr)
        proc.wait.side_effect = wait
        proc.poll.side_effect = poll
        proc.stdin.write.side_effect = stdin_write
        proc.stdin.close.side_effect = stdin_close
        mocker.patch("subprocess.Popen", return_value=proc)
        return proc

    return create


@pytest.fixture
def fake_async_popen(mocker, no_real_process_control) -> typing.Callable[..., mock.MagicMock]:
    """Patch the asyncio process creation and return the factory of the process it creates.

    The arguments are the ones of `fake_popen`, except `poll`. `stdin` is a pipe with `write`, `drain` and `close`.
    """

    def create(
        *,
        stdout: tuple[bytes | BaseException, ...] | None = (),
        stderr: tuple[bytes | BaseException, ...] | None = None,
        wait: typing.Sequence[int | BaseException] = (0,),
        stdin_write: BaseException | None = None,
        stdin_close: BaseException | None = None,
    ) -> mock.MagicMock:
        """Create the process: `None` instead of a stream means that the pipe is not opened."""
        proc = mocker.MagicMock(pid=PROCESS_PID, returncode=0)
        proc.stdout = None if stdout is None else FakeFileStream(*stdout)
        proc.stderr = None if stderr is None else FakeFileStream(*stderr)
        proc.stdin.drain = mocker.AsyncMock()
        proc.stdin.write.side_effect = stdin_write
        proc.stdin.close.side_effect = stdin_close
        results = list(wait)

        async def process_wait() -> int:
            """Let the readers of the streams run first, as a process that runs for a while does."""
            await asyncio.sleep(0)
            result = results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        proc.wait = mocker.AsyncMock(side_effect=process_wait)
        mocker.patch("asyncio.create_subprocess_shell", return_value=proc)
        return proc

    return create


@pytest.fixture
def make_ssh(paramiko_ssh_client, ssh_auth_logger, get_logger):
    """Create the client whose channel is the mock created by `fake_channel`."""

    def create(channel: mock.MagicMock, *, hostname: str = host) -> exec_helpers.SSHClient:
        transport = mock.Mock(open_session=mock.Mock(return_value=channel))
        paramiko_ssh_client.return_value = mock.Mock(get_transport=mock.Mock(return_value=transport))
        return exec_helpers.SSHClient(
            host=hostname,
            port=port,
            auth=exec_helpers.SSHAuth(username="user", password="pass"),
        )

    return create
