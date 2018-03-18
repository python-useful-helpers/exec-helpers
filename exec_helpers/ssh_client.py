#    Copyright 2018 Alexey Stepanov aka penguinolog.

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

from __future__ import absolute_import
from __future__ import unicode_literals

import os
import posixpath

import logging

from ._ssh_client_base import SSHAuth, SSHClientBase

__all__ = ('SSHAuth', 'SSHClient')

logger = logging.getLogger(__name__)
logging.getLogger('paramiko').setLevel(logging.WARNING)


class SSHClient(SSHClientBase):
    """SSH Client helper."""

    __slots__ = ()

    @staticmethod
    def _path_esc(path):  # type: (str) -> str
        """Escape space character in the path."""
        return path.replace(' ', '\ ')

    def mkdir(self, path):  # type: (str) -> None
        """run 'mkdir -p path' on remote.

        :type path: str
        """
        if self.exists(path):
            return
        logger.debug("Creating directory: {}".format(self._path_esc(path)))
        # noinspection PyTypeChecker
        self.execute("mkdir -p {}\n".format(self._path_esc(path)))

    def rm_rf(self, path):  # type: (str) -> None
        """run 'rm -rf path' on remote.

        :type path: str
        """
        logger.debug("rm -rf {}".format(self._path_esc(path)))
        # noinspection PyTypeChecker
        self.execute("rm -rf {}".format(self._path_esc(path)))

    def upload(self, source, target):
        """Upload file(s) from source to target using SFTP session.

        :type source: str
        :type target: str
        """
        logger.debug("Copying '%s' -> '%s'", source, target)

        if self.isdir(target):
            target = posixpath.join(target, os.path.basename(source))

        source = os.path.expanduser(source)
        if not os.path.isdir(source):
            self._sftp.put(source, target)
            return

        for rootdir, _, files in os.walk(source):
            targetdir = os.path.normpath(
                os.path.join(
                    target,
                    os.path.relpath(rootdir, source))).replace("\\", "/")

            self.mkdir(targetdir)

            for entry in files:
                local_path = os.path.normpath(os.path.join(rootdir, entry))
                remote_path = posixpath.join(targetdir, entry)
                if self.exists(remote_path):
                    self._sftp.unlink(remote_path)
                self._sftp.put(local_path, remote_path)

    def download(self, destination, target):
        """Download file(s) to target from destination.

        :type destination: str
        :type target: str
        :rtype: bool
        """
        logger.debug(
            "Copying '%s' -> '%s' from remote to local host",
            destination, target
        )

        if os.path.isdir(target):
            target = posixpath.join(target, os.path.basename(destination))

        if not self.isdir(destination):
            if self.exists(destination):
                self._sftp.get(destination, target)
            else:
                logger.debug(
                    "Can't download %s because it doesn't exist", destination
                )
        else:
            logger.debug(
                "Can't download %s because it is a directory", destination
            )
        return os.path.exists(target)
