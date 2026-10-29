#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.

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

# pylint: disable=no-self-use

from __future__ import annotations

import pathlib
import stat
import unittest
from unittest import mock

import paramiko
import pytest

import exec_helpers

host = "127.0.0.1"
port = 22
username = "user"
password = "pass"


@mock.patch("logging.getLogger", autospec=True)
@mock.patch("paramiko.WarningPolicy", autospec=True, return_value="WarningPolicy")
@mock.patch("paramiko.SSHClient", autospec=True)
class TestSftp(unittest.TestCase):
    @staticmethod
    def prepare_sftp_file_tests(client):
        ssh_ = mock.Mock()
        client.return_value = ssh_
        sftp = mock.Mock()
        open_sftp = mock.Mock(parent=ssh_.get_transport(), return_value=sftp)
        ssh_.get_transport().attach_mock(open_sftp, "open_sftp_client")

        with (
            mock.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_SYSTEM", autospec=True) as conf_sys,
            mock.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_USER", autospec=True) as conf_user,
        ):
            conf_sys.exists.return_value = False
            conf_user.exists.return_value = False

            # noinspection PyTypeChecker
            ssh = exec_helpers.SSHClient(
                host=host,
                port=port,
                auth=exec_helpers.SSHAuth(username=username, password=password),
            )
            return ssh, sftp

    def test_exists(self, client, *args):
        ssh, sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        sftp.attach_mock(lstat, "lstat")
        dst = "/etc"

        # noinspection PyTypeChecker
        result = ssh.exists(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.side_effect = IOError

        # noinspection PyTypeChecker
        result = ssh.exists(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    def test_stat(self, client, *args):
        ssh, sftp = self.prepare_sftp_file_tests(client)
        stat = mock.Mock()
        sftp.attach_mock(stat, "stat")
        stat.return_value = paramiko.sftp_attr.SFTPAttributes()
        stat.return_value.st_size = 0
        stat.return_value.st_uid = 0
        stat.return_value.st_gid = 0
        dst = "/etc/passwd"

        # noinspection PyTypeChecker
        result = ssh.stat(dst)
        self.assertEqual(result.st_size, 0)
        self.assertEqual(result.st_uid, 0)
        self.assertEqual(result.st_gid, 0)

    def test_isfile(self, client, *args):
        class Attrs:
            def __init__(self, mode):
                self.st_mode = mode

        ssh, sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        sftp.attach_mock(lstat, "lstat")
        lstat.return_value = Attrs(stat.S_IFREG)
        dst = "/etc/passwd"

        # noinspection PyTypeChecker
        result = ssh.isfile(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.return_value = Attrs(stat.S_IFDIR)

        # noinspection PyTypeChecker
        result = ssh.isfile(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

        lstat.reset_mock()
        lstat.side_effect = IOError

        # noinspection PyTypeChecker
        result = ssh.isfile(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    def test_isdir(self, client, *args):
        class Attrs:
            def __init__(self, mode):
                self.st_mode = mode

        ssh, sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        sftp.attach_mock(lstat, "lstat")
        lstat.return_value = Attrs(stat.S_IFDIR)
        dst = "/etc/passwd"

        # noinspection PyTypeChecker
        result = ssh.isdir(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.return_value = Attrs(stat.S_IFREG)

        # noinspection PyTypeChecker
        result = ssh.isdir(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

        lstat.reset_mock()
        lstat.side_effect = IOError
        # noinspection PyTypeChecker
        result = ssh.isdir(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    def test_islink(self, client, *args):
        class Attrs:
            def __init__(self, mode):
                self.st_mode = mode

        ssh, sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        sftp.attach_mock(lstat, "lstat")
        lstat.return_value = Attrs(stat.S_IFLNK)
        dst = "/etc/passwd"

        # noinspection PyTypeChecker
        result = ssh.islink(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.return_value = Attrs(stat.S_IFREG)

        # noinspection PyTypeChecker
        result = ssh.islink(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

        lstat.reset_mock()
        lstat.side_effect = IOError
        # noinspection PyTypeChecker
        result = ssh.islink(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    def test_open(self, client, *args):
        ssh, sftp = self.prepare_sftp_file_tests(client)
        fopen = mock.Mock(return_value=True)
        sftp.attach_mock(fopen, "open")

        dst = "/etc/passwd"
        mode = "r"
        # noinspection PyTypeChecker
        result = ssh.open(dst)
        fopen.assert_called_once_with(dst, mode)
        self.assertTrue(result)


@pytest.fixture
def sftp_client(paramiko_ssh_client, ssh_auth_logger, get_logger) -> tuple[exec_helpers.SSHClient, mock.Mock]:
    """Create the client and the SFTP session mock it opens."""
    sftp = mock.Mock()
    transport = mock.Mock(open_sftp_client=mock.Mock(return_value=sftp))
    paramiko_ssh_client.return_value = mock.Mock(get_transport=mock.Mock(return_value=transport))
    ssh = exec_helpers.SSHClient(
        host=host,
        port=port,
        auth=exec_helpers.SSHAuth(username=username, password=password),
    )
    return ssh, sftp


def test_mkdir(mocker, sftp_client) -> None:
    """The directory is created by a command with the escaped path, only when it is missing."""
    ssh, _ = sftp_client
    exists = mocker.patch.object(exec_helpers.SSHClient, "exists", side_effect=[False, True])
    execute = mocker.patch.object(exec_helpers.SSHClient, "execute")

    ssh.mkdir("~/tst dir")
    exists.assert_called_once_with("~/tst dir")
    execute.assert_called_once_with("mkdir -p ~/tst\\ dir\n")

    exists.reset_mock()
    execute.reset_mock()
    ssh.mkdir("~/tst dir")
    exists.assert_called_once_with("~/tst dir")
    execute.assert_not_called()


def test_rm_rf(mocker, sftp_client) -> None:
    """The path is removed by a command with the escaped path."""
    ssh, _ = sftp_client
    execute = mocker.patch.object(exec_helpers.SSHClient, "execute")

    ssh.rm_rf("~/tst dir")
    execute.assert_called_once_with("rm -rf ~/tst\\ dir")


@pytest.mark.parametrize(
    ("remote_isdir", "expected_target"),
    [
        pytest.param(False, "/etc/environment", id="to_file"),
        pytest.param(True, "/etc/environment/environment", id="into_dir"),
    ],
)
def test_upload_file(mocker, tmp_path, sftp_client, remote_isdir, expected_target) -> None:
    """A file is put to the target, or into it when the target is a directory."""
    ssh, sftp = sftp_client
    source = tmp_path / "environment"
    source.write_text("A=1\n")
    isdir = mocker.patch.object(exec_helpers.SSHClient, "isdir", return_value=remote_isdir)

    ssh.upload(source=source, target="/etc/environment")
    isdir.assert_called_once_with("/etc/environment")
    sftp.put.assert_called_once_with(source.resolve().as_posix(), expected_target, confirm=True)


def test_upload_dir(mocker, tmp_path, sftp_client) -> None:
    """A directory is copied recursively: subdirectories are created and existing remote files are replaced."""
    ssh, sftp = sftp_client
    source = tmp_path / "bash"
    (source / "completions").mkdir(parents=True)
    (source / "bashrc").write_text("")
    (source / "completions" / "git").write_text("")
    mocker.patch.object(exec_helpers.SSHClient, "isdir", return_value=True)
    mkdir = mocker.patch.object(exec_helpers.SSHClient, "mkdir")
    remote_files = {"/etc/bash/bashrc"}
    mocker.patch.object(exec_helpers.SSHClient, "exists", side_effect=remote_files.__contains__)

    ssh.upload(source=source, target="/etc")
    mkdir.assert_any_call("/etc/bash/completions")
    sftp.unlink.assert_called_once_with("/etc/bash/bashrc")
    sftp.put.assert_has_calls(
        [
            mock.call((source / "bashrc").resolve().as_posix(), "/etc/bash/bashrc", confirm=True),
            mock.call((source / "completions" / "git").resolve().as_posix(), "/etc/bash/completions/git", confirm=True),
        ],
        any_order=True,
    )
    assert sftp.put.call_count == 2


@pytest.mark.parametrize(
    ("remote_isdir", "remote_exists", "downloaded"),
    [
        pytest.param(False, True, True, id="file"),
        pytest.param(False, False, False, id="missing"),
        pytest.param(True, True, False, id="directory"),
    ],
)
def test_download(mocker, tmp_path, sftp_client, remote_isdir, remote_exists, downloaded) -> None:
    """A remote file is got into a local directory; a missing path or a directory is not downloaded."""
    ssh, sftp = sftp_client
    mocker.patch.object(exec_helpers.SSHClient, "isdir", return_value=remote_isdir)
    mocker.patch.object(exec_helpers.SSHClient, "exists", return_value=remote_exists)
    target = tmp_path.resolve() / "environment"
    sftp.get.side_effect = lambda _remote, local: pathlib.Path(local).write_text("A=1\n")

    assert ssh.download(destination="/etc/environment", target=tmp_path) is downloaded
    if downloaded:
        sftp.get.assert_called_once_with("/etc/environment", target.as_posix())
    else:
        sftp.get.assert_not_called()
