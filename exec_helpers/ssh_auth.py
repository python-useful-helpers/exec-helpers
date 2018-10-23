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

"""SSH client credentials class."""

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import copy
import logging
import typing  # noqa  # pylint: disable=unused-import

import paramiko  # type: ignore

__all__ = ("SSHAuth",)

logger = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("iso8601").setLevel(logging.WARNING)


class SSHAuth(object):
    """SSH Authorization object."""

    __slots__ = ("__username", "__password", "__key", "__keys", "__key_filename", "__passphrase")

    def __init__(
        self,
        username=None,  # type: typing.Optional[str]
        password=None,  # type: typing.Optional[str]
        key=None,  # type: typing.Optional[paramiko.RSAKey]
        keys=None,  # type: typing.Optional[typing.Iterable[paramiko.RSAKey]]
        key_filename=None,  # type: typing.Union[typing.List[str], str, None]
        passphrase=None,  # type: typing.Optional[str]
    ):  # type: (...) -> None
        """SSH credentials object.

        Used to authorize SSHClient.
        Single SSHAuth object is associated with single host:port.
        Password and key is private, other data is read-only.

        :param username: remote username.
        :type username: typing.Optional[str]
        :param password: remote password
        :type password: typing.Optional[str]
        :param key: Main connection key
        :type key: typing.Optional[paramiko.RSAKey]
        :param keys: Alternate connection keys
        :type keys: typing.Optional[typing.Iterable[paramiko.RSAKey]]]
        :param key_filename: filename(s) for additional key files
        :type key_filename: typing.Union[typing.List[str], str, None]
        :param passphrase: passphrase for keys. Need, if differs from password
        :type passphrase: typing.Optional[str]

        .. versionchanged:: 1.0.0
            added: key_filename, passphrase arguments
        """
        self.__username = username
        self.__password = password
        self.__key = key
        self.__keys = [None]
        if key is not None:
            # noinspection PyTypeChecker
            self.__keys.append(key)
        if keys is not None:
            for k in keys:
                if k not in self.__keys:
                    self.__keys.append(k)
        self.__key_filename = key_filename
        self.__passphrase = passphrase

    @property
    def username(self):  # type: () -> typing.Optional[str]
        """Username for auth.

        :rtype: str
        """
        return self.__username

    @staticmethod
    def __get_public_key(key):  # type: (typing.Union[paramiko.RSAKey, None]) -> typing.Optional[str]
        """Internal method for get public key from private.

        :type key: paramiko.RSAKey
        """
        if key is None:
            return None
        return "{0} {1}".format(key.get_name(), key.get_base64())

    @property
    def public_key(self):  # type: () -> typing.Optional[str]
        """Public key for stored private key if presents else None.

        :rtype: str
        """
        return self.__get_public_key(self.__key)

    @property
    def key_filename(self):  # type: () -> typing.Union[typing.List[str], str, None]
        """Key filename(s).

        .. versionadded:: 1.0.0
        """
        return copy.deepcopy(self.__key_filename)

    def enter_password(self, tgt):  # type: (typing.IO) -> None
        """Enter password to STDIN.

        Note: required for 'sudo' call

        :param tgt: Target
        :type tgt: file
        """
        # noinspection PyTypeChecker
        tgt.write("{}\n".format(self.__password))

    def connect(
        self,
        client,  # type: typing.Union[paramiko.SSHClient, paramiko.Transport]
        hostname=None,  # type: typing.Optional[str]
        port=22,  # type: int
        log=True,  # type: bool
    ):  # type: (...) -> None
        """Connect SSH client object using credentials.

        :param client: SSH Client (low level)
        :type client: typing.Union[paramiko.SSHClient, paramiko.Transport]
        :param hostname: remote hostname
        :type hostname: str
        :param port: remote ssh port
        :type port: int
        :param log: Log on generic connection failure
        :type log: bool
        :raises PasswordRequiredException: No password has been set, but required.
        :raises AuthenticationException: Authentication failed.
        """
        kwargs = {"username": self.username, "password": self.__password}  # type: typing.Dict[str, typing.Any]
        if hostname is not None:
            kwargs["hostname"] = hostname
            kwargs["port"] = port

        if isinstance(client, paramiko.client.SSHClient):  # pragma: no cover
            # paramiko.transport.Transport still do not allow passphrase and key filename

            if self.key_filename is not None:
                kwargs["key_filename"] = self.key_filename
            if self.__passphrase is not None:
                kwargs["passphrase"] = self.__passphrase

        keys = [self.__key]
        keys.extend([k for k in self.__keys if k != self.__key])

        for key in keys:
            kwargs["pkey"] = key
            try:
                client.connect(**kwargs)
                if self.__key != key:
                    self.__key = key
                    logger.debug("Main key has been updated, public key is: \n{}".format(self.public_key))
                return
            except paramiko.PasswordRequiredException:
                if self.__password is None:
                    logger.exception("No password has been set!")
                    raise
                else:
                    logger.critical("Unexpected PasswordRequiredException, when password is set!")
                    raise
            except (paramiko.AuthenticationException, paramiko.BadHostKeyException):
                continue
        msg = "Connection using stored authentication info failed!"
        if log:
            logger.exception(msg)
        raise paramiko.AuthenticationException(msg)

    def __hash__(self):  # type: () -> int
        """Hash for usage as dict keys and comparison."""
        return hash(
            (
                self.__class__,
                self.username,
                self.__password,
                tuple(self.__keys),
                (tuple(self.key_filename) if isinstance(self.key_filename, list) else self.key_filename),
                self.__passphrase,
            )
        )

    def __eq__(self, other):  # type: (typing.Any) -> bool
        """Comparison helper."""
        return hash(self) == hash(other)

    def __ne__(self, other):  # type: (typing.Any) -> bool
        """Comparison helper."""
        return not self.__eq__(other)

    def __deepcopy__(self, memo):  # type: (typing.Any) -> SSHAuth
        """Helper for copy.deepcopy."""
        return self.__class__(
            username=self.username, password=self.__password, key=self.__key, keys=copy.deepcopy(self.__keys)
        )

    def __copy__(self):  # type: () -> SSHAuth
        """Copy self."""
        return self.__class__(username=self.username, password=self.__password, key=self.__key, keys=self.__keys)

    def __repr__(self):  # type: (...) -> str
        """Representation for debug purposes."""
        _key = None if self.__key is None else "<private for pub: {}>".format(self.public_key)
        _keys = []  # type: typing.List[typing.Union[str, None]]
        for k in self.__keys:
            if k == self.__key:
                continue
            # noinspection PyTypeChecker
            _keys.append("<private for pub: {}>".format(self.__get_public_key(key=k)) if k is not None else None)

        return (
            "{cls}("
            "username={self.username!r}, "
            "password=<*masked*>, "
            "key={key}, "
            "keys={keys}, "
            "key_filename={self.key_filename!r}, "
            "passphrase=<*masked*>,"
            ")".format(cls=self.__class__.__name__, self=self, key=_key, keys=_keys)
        )

    def __str__(self):  # type: (...) -> str
        """Representation for debug purposes."""
        return "{cls} for {self.username}".format(cls=self.__class__.__name__, self=self)
