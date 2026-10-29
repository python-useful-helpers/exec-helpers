#    Copyright 2018 - 2026 Alexey Stepanov aka penguinolog.
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


"""Execution without a shell."""

from __future__ import annotations

import shlex

import pytest

import exec_helpers
from exec_helpers import async_api

ARGS = ["echo", "a b; c", "$HOME"]
COMMAND = shlex.join(ARGS)


@pytest.fixture
def async_spawn(mocker):
    """Mock process creation of asyncio: shell and exec variants, the same finished process."""
    create_shell = mocker.patch("asyncio.create_subprocess_shell")
    create_exec = mocker.patch("asyncio.create_subprocess_exec")
    process = mocker.MagicMock(returncode=0, stdin=None, wait=mocker.AsyncMock())
    create_shell.return_value = create_exec.return_value = process
    mocker.patch("exec_helpers._subprocess_helpers.kill_proc_tree")
    return create_shell, create_exec


def test_shell_default(mocker):
    """The shell is used by default and the command is passed as is."""
    popen = mocker.patch("subprocess.Popen", autospec=True)

    with exec_helpers.Subprocess().open_execute_context("echo a | cat"):
        pass

    assert popen.call_args.kwargs["shell"] is True
    assert popen.call_args.kwargs["args"] == "echo a | cat\n"


def test_shell_disabled(mocker):
    """The command is split to the arguments and executed directly."""
    popen = mocker.patch("subprocess.Popen", autospec=True)

    with exec_helpers.Subprocess(shell=False).open_execute_context(COMMAND):
        pass

    assert popen.call_args.kwargs["shell"] is False
    assert popen.call_args.kwargs["args"] == ARGS


def test_shell_disabled_chroot(mocker):
    """Chroot is applied to the arguments, without a shell inside."""
    popen = mocker.patch("subprocess.Popen", autospec=True)

    with exec_helpers.Subprocess(shell=False).open_execute_context(COMMAND, chroot_path="/mnt/target dir"):
        pass

    assert popen.call_args.kwargs["args"] == ["chroot", "/mnt/target dir", *ARGS]


def test_shell_disabled_string_rejected():
    """A string command is not accepted without a shell: its shell syntax would silently change the meaning."""
    with pytest.raises(TypeError, match="list of arguments"):
        exec_helpers.Subprocess(shell=False).execute("echo a | cat")


def test_shell_disabled_empty_command():
    """A command without a program is rejected with a clear error."""
    with pytest.raises(ValueError, match="at least the program"):
        exec_helpers.Subprocess(shell=False).execute([])


@pytest.mark.asyncio
async def test_async_shell_default(async_spawn):
    """The shell is used by default."""
    create_shell, create_exec = async_spawn

    async with async_api.Subprocess().open_execute_context("echo a | cat"):
        pass

    assert create_shell.call_args.args == ("echo a | cat\n",)
    create_exec.assert_not_called()


@pytest.mark.asyncio
async def test_async_shell_disabled(async_spawn):
    """The command is split to the arguments and executed directly."""
    create_shell, create_exec = async_spawn

    async with async_api.Subprocess(shell=False).open_execute_context(COMMAND, chroot_path="/mnt"):
        pass

    assert create_exec.call_args.args == ("chroot", "/mnt", *ARGS)
    create_shell.assert_not_called()


@pytest.mark.asyncio
async def test_async_shell_disabled_string_rejected():
    """A string command is not accepted without a shell."""
    with pytest.raises(TypeError, match="list of arguments"):
        await async_api.Subprocess(shell=False).execute("echo a | cat")


@pytest.mark.asyncio
async def test_async_shell_disabled_empty_command():
    """A command without a program is rejected with a clear error."""
    with pytest.raises(ValueError, match="at least the program"):
        await async_api.Subprocess(shell=False).execute([])
