#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.

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
import pathlib
import posixpath
import typing  # pylint: disable=unused-import

# Local Implementation
from . import _ssh_base


class SSHClient(_ssh_base.SSHClientBase):
    """SSH Client helper."""

    __slots__ = ()

    def __enter__(self) -> "SSHClient":  # pylint: disable=useless-super-delegation
        """Get context manager.

        :return: SSHClient instance with entered context
        :rtype: SSHClient
        """
        return super().__enter__()

    @staticmethod
    def _path_esc(path: str) -> str:
        """Escape space character in the path.

        :param path: path to be escaped
        :type path: str
        :return: path with escaped spaces
        :rtype: str
        """
        return path.replace(" ", r"\ ")

    @_ssh_base.normalize_path
    def mkdir(self, path: str) -> None:
        """Run 'mkdir -p path' on remote.

        :param path: path to create
        :type path: str
        """
        if self.exists(path):
            return
        # noinspection PyTypeChecker
        self.execute(f"mkdir -p {self._path_esc(path)}\n")

    @_ssh_base.normalize_path
    def rm_rf(self, path: str) -> None:
        """Run 'rm -rf path' on remote.

        :param path: path to remove
        :type path: str
        """
        # noinspection PyTypeChecker
        self.execute(f"rm -rf {self._path_esc(path)}")

    def upload(
        self, source: "typing.Union[str, pathlib.PurePath]", target: "typing.Union[str, pathlib.PurePath]"
    ) -> None:
        """Upload file(s) from source to target using SFTP session.

        :param source: local path
        :type source: typing.Union[str, pathlib.PurePath]
        :param target: remote path
        :type target: typing.Union[str, pathlib.PurePath]
        """
        self.logger.debug(f"Copying '{source}' -> '{target}'")

        if self.isdir(target):
            target = posixpath.join(target, os.path.basename(source))

        tgt = pathlib.PurePath(target)  # Remote -> No FS access, system agnostic
        src = pathlib.Path(source).expanduser().resolve()
        if not src.is_dir():
            self._sftp.put(src.as_posix(), target)
            return

        for pth in src.glob("**/*"):
            relative = pth.relative_to(src).as_posix()
            destination: str = os.path.normpath(tgt.joinpath(relative).as_posix()).replace("\\", "/")
            if pth.is_dir():
                self.mkdir(destination)
                continue

            if self.exists(destination):
                self._sftp.unlink(destination)
            self._sftp.put(pth.as_posix(), destination)

    def download(
        self, destination: "typing.Union[str, pathlib.PurePath]", target: "typing.Union[str, pathlib.PurePath]"
    ) -> bool:
        """Download file(s) to target from destination.

        :param destination: remote path
        :type destination: typing.Union[str, pathlib.PurePath]
        :param target: local path
        :type target: typing.Union[str, pathlib.PurePath]
        :return: downloaded file present on local filesystem
        :rtype: bool
        """
        self.logger.debug(f"Copying '{destination}' -> '{target}' from remote to local host")

        tgt = pathlib.Path(target).expanduser().resolve()
        dst = pathlib.PurePath(destination).as_posix()
        if tgt.is_dir():
            tgt = tgt.joinpath(os.path.basename(dst))

        if not self.isdir(destination):
            if self.exists(destination):
                self._sftp.get(dst, tgt.as_posix())
            else:
                self.logger.debug(f"Can't download {destination} because it does not exist")
        else:
            self.logger.debug(f"Can't download {destination} because it is a directory")
        return tgt.exists()
