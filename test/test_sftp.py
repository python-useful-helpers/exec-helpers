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

import os
import posixpath
import stat
import unittest
from unittest import mock

import paramiko

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
        open_sftp = mock.Mock(parent=ssh_, return_value=sftp)
        ssh_.attach_mock(open_sftp, "open_sftp")

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

    @unittest.skip("Need to port to pytest: too huge chain of mocks and setup")
    @mock.patch("exec_helpers.ssh.SSHClient.exists")
    @mock.patch("exec_helpers.ssh.SSHClient.execute")
    def test_mkdir(self, execute, exists, *args):
        exists.side_effect = [False, True]

        dst = "~/tst dir"
        escaped_dst = r"~/tst\ dir"

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(username=username, password=password),
        )

        # Path not exists
        # noinspection PyTypeChecker
        ssh.mkdir(dst)
        exists.assert_called_once_with(dst)
        execute.assert_called_once_with(f"mkdir -p {escaped_dst}\n")

        # Path exists
        exists.reset_mock()
        execute.reset_mock()

        # noinspection PyTypeChecker
        ssh.mkdir(dst)
        exists.assert_called_once_with(dst)
        execute.assert_not_called()

    @unittest.skip("Need to port to pytest: too huge chain of mocks and setup")
    @mock.patch("exec_helpers.ssh.SSHClient.execute")
    def test_rm_rf(self, execute, *args):
        dst = "~/tst"

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(username=username, password=password),
        )

        # Path not exists
        # noinspection PyTypeChecker
        ssh.rm_rf(dst)
        execute.assert_called_once_with(f"rm -rf {dst}")

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

    @unittest.skip("Need to port to pytest: too huge chain of mocks and setup")
    @mock.patch("exec_helpers.ssh.SSHClient.exists")
    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("exec_helpers.ssh.SSHClient.isdir")
    @mock.patch("os.path.isdir", autospec=True)
    def test_download(
        self,
        isdir,
        remote_isdir,
        exists,
        remote_exists,
        client,
        policy,
        _logger,
    ):
        ssh, sftp = self.prepare_sftp_file_tests(client)
        isdir.return_value = True
        exists.side_effect = [True, False, False]
        remote_isdir.side_effect = [False, False, True]
        remote_exists.side_effect = [True, False, False]

        dst = "/etc/environment"
        target = "/tmp/environment"
        # noinspection PyTypeChecker
        result = ssh.download(destination=dst, target=target)
        self.assertTrue(result)
        isdir.assert_called_once_with(target)
        exists.assert_called_once_with(posixpath.join(target, os.path.basename(dst)))
        remote_isdir.assert_called_once_with(dst)
        remote_exists.assert_called_once_with(dst)
        sftp.assert_has_calls(
            mock.call.get(
                dst,
                posixpath.join(target, os.path.basename(dst)),
            )
        )

        # Negative scenarios
        # noinspection PyTypeChecker
        result = ssh.download(destination=dst, target=target)
        self.assertFalse(result)

        # noinspection PyTypeChecker
        ssh.download(destination=dst, target=target)

    @unittest.skip("Need to port to pytest: too huge chain of mocks and setup")
    @mock.patch("exec_helpers.ssh.SSHClient.isdir")
    @mock.patch("os.path.isdir", autospec=True)
    def test_upload_file(self, isdir, remote_isdir, client, *args):
        ssh, sftp = self.prepare_sftp_file_tests(client)
        isdir.return_value = False
        remote_isdir.return_value = False
        target = "/etc/environment"
        source = "/tmp/environment"

        # noinspection PyTypeChecker
        ssh.upload(source=source, target=target)
        isdir.assert_called_once_with(source)
        remote_isdir.assert_called_once_with(target)
        sftp.assert_has_calls((mock.call.put(source, target),))

    @unittest.skip("Need to port to pytest: too huge chain of mocks and setup")
    @mock.patch("exec_helpers.ssh.SSHClient.exists")
    @mock.patch("exec_helpers.ssh.SSHClient.mkdir")
    @mock.patch("os.walk")
    @mock.patch("exec_helpers.ssh.SSHClient.isdir")
    @mock.patch("os.path.isdir", autospec=True)
    def test_upload_dir(self, isdir, remote_isdir, walk, mkdir, exists, client, *args):
        ssh, sftp = self.prepare_sftp_file_tests(client)
        isdir.return_value = True
        remote_isdir.return_value = True
        exists.return_value = True
        target = "/etc"
        source = "/tmp/bash"
        filename = "bashrc"
        walk.return_value = ((source, "", [filename]),)
        expected_path = posixpath.join(target, os.path.basename(source))
        expected_file = posixpath.join(expected_path, filename)

        # noinspection PyTypeChecker
        ssh.upload(source=source, target=target)
        isdir.assert_called_once_with(source)
        remote_isdir.assert_called_once_with(target)
        mkdir.assert_called_once_with(expected_path)
        exists.assert_called_once_with(expected_file)
        sftp.assert_has_calls(
            (
                mock.call.unlink(expected_file),
                mock.call.put(
                    os.path.normpath(os.path.join(source, filename)),
                    expected_file,
                ),
            )
        )
