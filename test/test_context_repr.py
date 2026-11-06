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

"""Debug strings of execute contexts do not expose secrets."""

from __future__ import annotations

import typing

import pytest

import exec_helpers
from exec_helpers import async_api
from fakes import fake_channel

SECRET = "s3cr3t-value"
PASSWORD_MASK = r"--password (\S+)"

MASK_ARGNAMES = ("instance_mask", "call_mask", "command")
MASK_CASES = (
    pytest.param(PASSWORD_MASK, None, f"tool --password {SECRET}", id="instance"),
    pytest.param(None, PASSWORD_MASK, f"tool --password {SECRET}", id="call"),
    pytest.param(
        PASSWORD_MASK,
        r"--token (\S+)",
        f"tool --password {SECRET} --token {SECRET}",
        id="both",
    ),
)


def check_masked(text: str) -> None:
    assert SECRET not in text
    assert "<*masked*>" in text
    assert f"stdin=<{len(SECRET)} bytes>" in text


@pytest.mark.parametrize(MASK_ARGNAMES, MASK_CASES)
def test_subprocess_context_repr(instance_mask, call_mask, command):
    """Subprocess context hides the command mask, STDIN data and environment values."""
    ctx = exec_helpers.Subprocess(log_mask_re=instance_mask).open_execute_context(
        command,
        stdin=SECRET,
        env={"TOKEN": SECRET},
        log_mask_re=call_mask,
    )
    text = repr(ctx)
    check_masked(text)
    assert "env=<names: ['TOKEN']>" in text


@pytest.mark.parametrize(MASK_ARGNAMES, MASK_CASES)
def test_async_subprocess_context_repr(instance_mask, call_mask, command):
    """Async subprocess context hides the command mask, STDIN data and environment values."""
    ctx = async_api.Subprocess(log_mask_re=instance_mask).open_execute_context(
        command,
        stdin=SECRET,
        env={"TOKEN": SECRET},
        log_mask_re=call_mask,
    )
    text = repr(ctx)
    check_masked(text)
    assert "env=<names: ['TOKEN']>" in text


@pytest.mark.parametrize(MASK_ARGNAMES, MASK_CASES)
def test_ssh_context_repr(
    paramiko_ssh_client,
    ssh_auth_logger,
    instance_mask,
    call_mask,
    command,
):
    """SSH context hides the command mask and STDIN data."""
    ssh = exec_helpers.SSHClient(
        host="192.0.2.1",
        auth=exec_helpers.SSHAuth(password="pass"),
    )
    ssh.log_mask_re = instance_mask
    ctx = ssh.open_execute_context(command, stdin=SECRET, log_mask_re=call_mask)
    check_masked(repr(ctx))


@pytest.mark.parametrize(MASK_ARGNAMES, MASK_CASES)
def test_execute_context_repr(
    mocker,
    fake_popen,
    subprocess_logger,
    instance_mask,
    call_mask,
    command,
):
    """The mask passed to execute reaches the debug string of the context."""
    fake_popen()
    spy = mocker.spy(exec_helpers.Subprocess, "open_execute_context")

    exec_helpers.Subprocess(log_mask_re=instance_mask).execute(
        command,
        stdin=SECRET,
        log_mask_re=call_mask,
    )

    check_masked(repr(spy.spy_return))


@pytest.mark.asyncio
@pytest.mark.parametrize(MASK_ARGNAMES, MASK_CASES)
async def test_async_execute_context_repr(
    mocker,
    fake_async_popen,
    instance_mask,
    call_mask,
    command,
):
    """The mask passed to the async execute reaches the debug string of the context."""
    fake_async_popen()
    spy = mocker.spy(async_api.Subprocess, "open_execute_context")

    await async_api.Subprocess(log_mask_re=instance_mask).execute(
        command,
        stdin=SECRET,
        log_mask_re=call_mask,
    )

    check_masked(repr(spy.spy_return))


@pytest.mark.parametrize(MASK_ARGNAMES, MASK_CASES)
def test_execute_together_context_repr(
    mocker,
    make_ssh,
    instance_mask,
    call_mask,
    command,
):
    """The mask passed to execute_together reaches the debug string of the context."""
    ssh = make_ssh(fake_channel())
    ssh.log_mask_re = instance_mask
    spy = mocker.spy(exec_helpers.SSHClient, "open_execute_context")

    exec_helpers.SSHClient.execute_together(
        remotes=[ssh],
        command=command,
        stdin=SECRET,
        log_mask_re=call_mask,
    )

    check_masked(repr(spy.spy_return))


def test_context_repr_no_stdin():
    """Absent STDIN and environment are shown as None."""
    text = repr(exec_helpers.Subprocess().open_execute_context("true"))
    assert "stdin=None" in text
    assert "env=None" in text


def test_context_repr_mixed_env_keys():
    """Names of an environment with mixed key types are listed without an error."""
    env: dict[typing.Any, str] = {b"A": SECRET, "B": SECRET}
    ctx = exec_helpers.Subprocess().open_execute_context("true", env=env)
    text = repr(ctx)
    assert SECRET not in text
    assert "env=<names: ['B', b'A']>" in text
