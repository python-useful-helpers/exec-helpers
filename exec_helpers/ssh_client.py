#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.

#    Copyright 2013 - 2016 Mirantis, Inc.
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

"""SSH client helper based on Paramiko. Extended API helpers."""

__all__ = ("SSHClient",)

# Standard Library
import os
import posixpath

# Local Implementation
from ._ssh_client_base import SSHClientBase


class SSHClient(SSHClientBase):
    """SSH Client helper."""

    __slots__ = ()

    @staticmethod
    def _path_esc(path: str) -> str:
        """Escape space character in the path.

        :param path: path to be escaped
        :type path: str
        :returns: path with escaped spaces
        :rtype: str
        """
        return path.replace(" ", r"\ ")

    def mkdir(self, path: str) -> None:
        """Run 'mkdir -p path' on remote.

        :param path: path to create
        :type path: str
        """
        if self.exists(path):
            return
        # noinspection PyTypeChecker
        self.execute("mkdir -p {}\n".format(self._path_esc(path)))

    def rm_rf(self, path: str) -> None:
        """Run 'rm -rf path' on remote.

        :param path: path to remove
        :type path: str
        """
        # noinspection PyTypeChecker
        self.execute("rm -rf {}".format(self._path_esc(path)))

    def upload(self, source: str, target: str) -> None:
        """Upload file(s) from source to target using SFTP session.

        :param source: local path
        :type source: str
        :param target: remote path
        :type target: str
        """
        self.logger.debug("Copying '{source}' -> '{target}'".format(source=source, target=target))

        if self.isdir(target):
            target = posixpath.join(target, os.path.basename(source))

        source = os.path.expanduser(source)
        if not os.path.isdir(source):
            self._sftp.put(source, target)
            return

        for rootdir, _, files in os.walk(source):
            targetdir = os.path.normpath(os.path.join(target, os.path.relpath(rootdir, source))).replace("\\", "/")

            self.mkdir(targetdir)

            for entry in files:
                local_path = os.path.normpath(os.path.join(rootdir, entry))
                remote_path = posixpath.join(targetdir, entry)
                if self.exists(remote_path):
                    self._sftp.unlink(remote_path)
                self._sftp.put(local_path, remote_path)

    def download(self, destination: str, target: str) -> bool:
        """Download file(s) to target from destination.

        :param destination: remote path
        :type destination: str
        :param target: local path
        :type target: str
        :return: downloaded file present on local filesystem
        :rtype: bool
        """
        self.logger.debug(
            "Copying '{destination}' -> '{target}' from remote to local host".format(
                destination=destination, target=target
            )
        )

        if os.path.isdir(target):
            target = posixpath.join(target, os.path.basename(destination))

        if not self.isdir(destination):
            if self.exists(destination):
                self._sftp.get(destination, target)
            else:
                self.logger.debug(
                    "Can't download {destination} because it doesn't exist".format(destination=destination)
                )
        else:
            self.logger.debug("Can't download {destination} because it is a directory".format(destination=destination))
        return os.path.exists(target)
