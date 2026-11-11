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

"""MaskedArg: the process gets the secret, the logs, the result and the exceptions do not."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import shlex
import subprocess
import typing

import pytest

import exec_helpers
from exec_helpers import MaskedArg
from exec_helpers import _helpers
from exec_helpers import async_api
from fakes import fake_channel

if typing.TYPE_CHECKING:
    from unittest import mock

# Each of these leaks the tail of the secret with a naive `--pass=(\S+)` rule on the joined command.
SECRETS = (
    pytest.param("plain", id="plain"),
    pytest.param("two secret words", id="spaces"),
    pytest.param('it\'s "quoted"', id="quotes"),
    pytest.param("line1\nline2", id="newline"),
    pytest.param("$(rm -rf /) `x` ;|&", id="shell_syntax"),
)
MASK = "<*masked*>"
# The log form is a valid shell command too: `<*masked*>` makes shlex quote the argument.
MASKED_CMD = shlex.join(["tool", f"--pass={MASK}"])


def patched(target: typing.Any) -> mock.MagicMock:
    """Get the mock that a fixture put in place of `target`, typed as such."""
    return typing.cast("mock.MagicMock", target)


def leaked(secret: str, text: str) -> list[str]:
    """Parts of the secret (words and lines included) present in the text."""
    parts = {secret, *secret.split(), *secret.splitlines()}
    return [part for part in parts if len(part) > 2 and part in text]


def test_constructors() -> None:
    assert MaskedArg.secret("s3cr3t") == MaskedArg("s3cr3t", MASK)
    assert MaskedArg.option("pass", "s3cr3t") == MaskedArg("--pass=s3cr3t", f"--pass={MASK}")
    assert MaskedArg.option("db-pass", "s3cr3t") == MaskedArg("--db-pass=s3cr3t", f"--db-pass={MASK}")
    assert MaskedArg.option("p", "s3cr3t") == MaskedArg("-ps3cr3t", f"-p{MASK}")
    assert MaskedArg.key_value("if", "s3cr3t") == MaskedArg("if=s3cr3t", f"if={MASK}")
    assert MaskedArg.key_value("-Dtoken", "s3cr3t") == MaskedArg("-Dtoken=s3cr3t", f"-Dtoken={MASK}")
    assert MaskedArg.key_value("VAR", "s3cr3t", sep=":") == MaskedArg("VAR:s3cr3t", f"VAR:{MASK}")
    assert MaskedArg.regex("user:s3cr3t@host", r":(\w+)@") == MaskedArg("user:s3cr3t@host", f"user:{MASK}@host")


def test_key_value_empty_key() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        MaskedArg.key_value("", "s3cr3t")


@pytest.mark.parametrize("name", ["", "-p", "--pass", "pass=", "two words", "_x"])
def test_option_bad_name(name: str) -> None:
    with pytest.raises(ValueError, match="without leading dashes"):
        MaskedArg.option(name, "s3cr3t")


def test_immutable_and_repr_hides_secret() -> None:
    arg = MaskedArg.option("pass", "s3cr3t")
    assert "s3cr3t" not in repr(arg)
    assert "s3cr3t" not in str(arg)
    assert "s3cr3t" not in f"{[arg]}"
    with pytest.raises(dataclasses.FrozenInstanceError):
        arg.arg = "other"  # type: ignore[misc]


@pytest.mark.parametrize("secret", SECRETS)
def test_join(secret: str) -> None:
    """The process gets the exact argument, the log keeps the arguments around it and hides only the secret."""
    command = ("tool", MaskedArg.option("pass", secret), "--next", "arg")

    assert shlex.split(_helpers.cmd_to_string(command)) == ["tool", f"--pass={secret}", "--next", "arg"]
    for_log = _helpers.cmd_to_log_string(command)
    assert shlex.split(for_log) == ["tool", f"--pass={MASK}", "--next", "arg"]
    assert not leaked(secret, for_log)


def test_join_string_command_unchanged() -> None:
    assert _helpers.cmd_to_string("a b") == _helpers.cmd_to_log_string("a b") == "a b"


@pytest.mark.parametrize("secret", SECRETS)
def test_subprocess(fake_popen, caplog, secret: str) -> None:
    popen = fake_popen()
    caplog.set_level(logging.DEBUG)

    result = exec_helpers.Subprocess().execute(["tool", MaskedArg.option("pass", secret), "--next"], verbose=True)

    assert shlex.split(patched(subprocess.Popen).call_args.kwargs["args"])[1] == f"--pass={secret}"
    assert result.cmd == shlex.join(["tool", f"--pass={MASK}", "--next"])
    assert not leaked(secret, caplog.text)
    assert "--next" in caplog.text
    popen.wait.assert_called()


def test_subprocess_without_shell(fake_popen, caplog) -> None:
    fake_popen()
    caplog.set_level(logging.DEBUG)

    result = exec_helpers.Subprocess(shell=False).execute(["tool", MaskedArg.secret("two words")])

    assert patched(subprocess.Popen).call_args.kwargs["args"] == ["tool", "two words"]
    assert result.cmd == f"tool '{MASK}'"
    assert not leaked("two words", caplog.text)


def test_generator_command(fake_popen) -> None:
    """The command is consumed once, though it is joined for the process and for the log."""
    fake_popen()

    result = exec_helpers.Subprocess().execute(arg for arg in ("tool", MaskedArg.secret("s3cr3t")))

    assert patched(subprocess.Popen).call_args.kwargs["args"] == "tool s3cr3t\n"
    assert result.cmd == f"tool '{MASK}'"


def test_log_mask_re_still_applies(fake_popen) -> None:
    fake_popen()

    result = exec_helpers.Subprocess(log_mask_re=r"--user=(\S+)").execute(
        ["tool", "--user=bob", MaskedArg.option("pass", "s3cr3t")],
        log_mask_re=r"--host=(\S+)",
    )

    # `log_mask_re` runs on the joined log form: its mask is not quoted, the MaskedArg one is.
    assert result.cmd == f"tool --user={MASK} '--pass={MASK}'"


def test_check_call_error(fake_popen) -> None:
    fake_popen(wait=(1,))

    with pytest.raises(exec_helpers.CalledProcessError) as exc_info:
        exec_helpers.Subprocess().check_call(["tool", MaskedArg.option("pass", "two secret words")])

    assert "secret" not in str(exc_info.value)
    assert exc_info.value.cmd == MASKED_CMD


@pytest.mark.parametrize("chroot_path", [None, "/chroot"])
def test_context_repr(chroot_path) -> None:
    """The context repr hides the argument after chroot quoted the command again."""
    runner = exec_helpers.Subprocess()
    cmd = ["tool", MaskedArg.option("pass", "it's two words")]
    ctx = runner.open_execute_context(
        _helpers.cmd_to_string(cmd),
        command_for_log=_helpers.cmd_to_log_string(cmd),
        chroot_path=chroot_path,
    )

    text = repr(ctx)
    assert "two words" not in text
    assert MASK in text
    assert "two words" in ctx.command


@pytest.mark.asyncio
async def test_async_subprocess(fake_async_popen, caplog) -> None:
    fake_async_popen()
    caplog.set_level(logging.DEBUG)

    result = await async_api.Subprocess().execute(["tool", MaskedArg.option("pass", "two secret words")])

    created = patched(asyncio.create_subprocess_shell).call_args.args[0]
    assert "two secret words" in created
    assert result.cmd == MASKED_CMD
    assert "secret" not in caplog.text


@pytest.mark.parametrize("chroot_path", [None, "/chroot"])
def test_ssh_context_repr_sudo(make_ssh, chroot_path) -> None:
    """The context repr hides the argument after sudo and chroot quoted the command again."""
    ssh = make_ssh(fake_channel())
    ssh.sudo_mode = True
    cmd = ["tool", MaskedArg.option("pass", "it's two words")]
    ctx = ssh.open_execute_context(
        _helpers.cmd_to_string(cmd),
        command_for_log=_helpers.cmd_to_log_string(cmd),
        chroot_path=chroot_path,
    )

    assert "sudo" in ctx.command
    assert "two words" in ctx.command
    assert "two words" not in repr(ctx)
    assert MASK in repr(ctx)


def test_ssh(mocker, make_ssh) -> None:
    chan = fake_channel(exit_code=1)
    ssh = make_ssh(chan)
    spy = mocker.spy(exec_helpers.SSHClient, "open_execute_context")

    with pytest.raises(exec_helpers.CalledProcessError) as exc_info:
        ssh.check_call(["tool", MaskedArg.option("pass", "two secret words")], chroot_path="/chroot")

    assert "two secret words" in chan.exec_command.call_args.args[0]
    assert exc_info.value.result.cmd == MASKED_CMD
    assert "secret" not in str(exc_info.value)
    assert "secret" not in repr(spy.spy_return)
    assert MASK in repr(spy.spy_return)
    assert "secret" not in str(ssh.logger.mock_calls)


def test_execute_together(make_ssh) -> None:
    remotes = [make_ssh(fake_channel(exit_code=ec), hostname=name) for name, ec in (("h1", 0), ("h2", 1))]

    with pytest.raises(exec_helpers.ParallelCallProcessError) as exc_info:
        exec_helpers.SSHClient.execute_together(
            remotes=remotes,
            command=["tool", MaskedArg.option("pass", "two secret words")],
        )

    exc = exc_info.value
    assert exc.cmd == MASKED_CMD
    assert all(res.cmd == MASKED_CMD for res in exc.results.values())
    assert "secret" not in str(exc)
    for remote in remotes:
        sent = remote._ssh_transport.open_session.return_value.exec_command.call_args.args[0]
        assert "two secret words" in sent
