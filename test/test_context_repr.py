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

import exec_helpers
from exec_helpers import async_api

SECRET = "s3cr3t-value"


def check_masked(text: str) -> None:
    assert SECRET not in text
    assert "<*masked*>" in text
    assert f"stdin=<{len(SECRET)} bytes>" in text


def test_subprocess_context_repr():
    """Subprocess context hides the command mask, STDIN data and environment values."""
    ctx = exec_helpers.Subprocess(log_mask_re=r"--password (\S+)").open_execute_context(
        f"tool --password {SECRET}",
        stdin=SECRET,
        env={"TOKEN": SECRET},
    )
    text = repr(ctx)
    check_masked(text)
    assert "env=<names: ['TOKEN']>" in text


def test_async_subprocess_context_repr():
    """Async subprocess context hides the command mask, STDIN data and environment values."""
    ctx = async_api.Subprocess(log_mask_re=r"--password (\S+)").open_execute_context(
        f"tool --password {SECRET}",
        stdin=SECRET,
        env={"TOKEN": SECRET},
    )
    text = repr(ctx)
    check_masked(text)
    assert "env=<names: ['TOKEN']>" in text


def test_ssh_context_repr(paramiko_ssh_client, ssh_auth_logger):
    """SSH context hides the command mask and STDIN data."""
    ssh = exec_helpers.SSHClient(
        host="192.0.2.1",
        auth=exec_helpers.SSHAuth(password="pass"),
    )
    ssh.log_mask_re = r"--password (\S+)"
    ctx = ssh.open_execute_context(f"tool --password {SECRET}", stdin=SECRET)
    check_masked(repr(ctx))


def test_context_repr_no_stdin():
    """Absent STDIN and environment are shown as None."""
    text = repr(exec_helpers.Subprocess().open_execute_context("true"))
    assert "stdin=None" in text
    assert "env=None" in text


def test_context_repr_mixed_env_keys():
    """Names of an environment with mixed key types are listed without an error."""
    ctx = exec_helpers.Subprocess().open_execute_context("true", env={b"A": SECRET, "B": SECRET})
    text = repr(ctx)
    assert SECRET not in text
    assert "env=<names: ['B', b'A']>" in text
