#    Copyright 2018 - 2023 Aleksei Stepanov aka penguinolog.

#    Copyright 2013 - 2016 Mirantis, Inc.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""SSH client credentials class."""

from __future__ import annotations

import copy
import logging
import typing

import paramiko

if typing.TYPE_CHECKING:
    import socket
    from collections.abc import Collection
    from collections.abc import Iterable
    from collections.abc import Sequence

__all__ = ("SSHAuth",)

LOGGER = logging.getLogger(__name__)


class SSHAuth:
    """SSH Authorization object."""

    __slots__ = ("__key_filename", "__key_index", "__keys", "__passphrase", "__password", "__username")

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        key: paramiko.PKey | None = None,
        keys: Sequence[paramiko.PKey | None] | None = None,
        key_filename: Iterable[str] | str | None = None,
        passphrase: str | None = None,
    ) -> None:
        """SSH credentials object.

        Used to authorize SSHClient.
        Single SSHAuth object is associated with single host:port.
        Password and key is private, other data is read-only.

        :param username: Remote username.
        :type username: str | None
        :param password: Remote password.
        :type password: str | None
        :param key: Main connection key.
        :type key: paramiko.PKey | None
        :param keys: Alternate connection keys.
        :type keys: Sequence[paramiko.PKey | None] | None
        :param key_filename: Filename(s) for additional key files.
        :type key_filename: Iterable[str] | str | None
        :param passphrase: Passphrase for keys. Need, if differs from password.
        :type passphrase: str | None

        .. versionchanged:: 1.0.0
            added: key_filename, passphrase arguments
        """
        self.__username: str | None = username
        self.__password: str | None = password

        self.__keys: list[None | paramiko.PKey] = []

        if key is not None:
            # noinspection PyTypeChecker
            self.__keys.append(key)

        if keys is not None:
            for k in keys:
                if k is None:
                    continue
                if k not in self.__keys:
                    if key is not None:
                        if k != key:
                            self.__keys.append(k)
                    else:
                        self.__keys.append(k)

        self.__keys.append(None)

        self.__key_index: int = 0

        if key_filename is None:
            self.__key_filename: Collection[str] = ()
        elif isinstance(key_filename, str):
            self.__key_filename = (key_filename,)
        else:
            self.__key_filename = tuple(key_filename)
        self.__passphrase: str | None = passphrase

    @property
    def username(self) -> str | None:
        """Username for auth.

        :return: Auth username.
        :rtype: str
        """
        return self.__username

    @staticmethod
    def __get_public_key(key: paramiko.PKey | None) -> str | None:
        """Internal method for get public key from private.

        :param key: SSH private key.
        :type key: paramiko.PKey
        :return: Public key text if applicable.
        :rtype: str | None
        """
        if key is None:
            return None
        return f"{key.get_name()} {key.get_base64()}"

    @property
    def public_key(self) -> str | None:
        """Public key for the stored private key if presents else None.

        :return: Public key for the current private key.
        :rtype: str
        """
        return self.__get_public_key(self.__keys[self.__key_index])

    @property
    def key_filename(self) -> Collection[str]:
        """Key filename(s).

        :return: Copy of used key filename (original should not be changed via mutability).
        .. versionadded:: 1.0.0
        .. versionchanged:: 7.0.5 changed type relying on paramiko sources
        """
        return self.__key_filename

    def enter_password(self, tgt: typing.BinaryIO) -> None:
        """Enter password to STDIN.

        Note: required for 'sudo' call

        :param tgt: Target.
        :type tgt: typing.BinaryIO
        """
        # noinspection PyTypeChecker
        tgt.write(f"{self.__password if self.__password is not None else ''}\n".encode())

    def connect(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        port: int = 22,
        log: bool = True,
        *,
        sock: paramiko.ProxyCommand | paramiko.Channel | socket.socket | None = None,
        allow_ssh_agent: bool = True,
    ) -> None:
        """Connect the SSH client object using credentials.

        :param client: SSH Client (low level).
        :type client: paramiko.SSHClient
        :param hostname: Remote hostname.
        :type hostname: str
        :param port: Remote ssh port.
        :type port: int
        :param log: Log on generic connection failure.
        :type log: bool
        :param sock: Socket for connection. Useful for ssh proxies support.
        :type sock: paramiko.ProxyCommand | paramiko.Channel | socket.socket | None
        :param allow_ssh_agent: Use SSH Agent if available.
        :type allow_ssh_agent: bool
        :raises PasswordRequiredException: No password has been set, but required.
        :raises AuthenticationException: Authentication failed.
        """
        kwargs: dict[str, typing.Any] = {}

        if self.__passphrase is not None:
            kwargs["passphrase"] = self.__passphrase
        if sock is not None:
            kwargs["sock"] = sock

        for index, key in sorted(enumerate(self.__keys), key=lambda i_k: i_k[0] != self.__key_index):
            kwargs["pkey"] = key
            try:
                # noinspection PyTypeChecker
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=self.username,
                    password=self.__password,
                    key_filename=self.__key_filename,  # type: ignore[arg-type]  # types verified by not signature
                    allow_agent=allow_ssh_agent,
                    **kwargs,
                )
                if index != self.__key_index:
                    self.__key_index = index
                    LOGGER.debug(f"Main key has been updated, public key is: \n{self.public_key}")
            except paramiko.PasswordRequiredException:
                if self.__password is None:
                    LOGGER.exception("No password has been set!")
                    raise
                LOGGER.critical("Unexpected PasswordRequiredException, when password is set!")
                raise
            except (paramiko.AuthenticationException, paramiko.BadHostKeyException):
                continue
            else:
                return
        msg: str = "Connection using stored authentication info failed!"
        if log:
            LOGGER.exception(msg)
        raise paramiko.AuthenticationException(msg)

    def __hash__(self) -> int:
        """Hash for usage as dict keys and comparison.

        :return: Hash value.
        :rtype: int
        """
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

    def __eq__(self, other: object) -> bool:
        """Comparison helper.

        :param other: Another SSHAuth instance.
        :type other: typing.Any
        :return: Current object equals other.
        :rtype: bool
        """
        return hash(self) == hash(other)

    def __ne__(self, other: object) -> bool:
        """Comparison helper.

        :param other: Another SSHAuth instance.
        :type other: typing.Any
        :return: Current object doesn't equal other.
        :rtype: bool
        """
        return not self.__eq__(other)

    def __deepcopy__(self, memo: typing.Any) -> SSHAuth:
        """Helper for copy.deepcopy.

        :param memo: copy.deepcopy() memodict.
        :type memo: typing.Any
        :return: Re-constructed copy of the current class.
        :rtype: SSHAuth
        """
        # noinspection PyTypeChecker
        return self.__class__(
            username=self.username,
            password=self.__password,
            key=self.__keys[self.__key_index],
            keys=copy.deepcopy(self.__keys),
            key_filename=copy.deepcopy(self.key_filename),
            passphrase=self.__passphrase,
        )

    def __copy__(self) -> SSHAuth:
        """Copy self.

        :return: Re-constructed copy of the current class.
        :rtype: SSHAuth
        """
        # noinspection PyTypeChecker
        return self.__class__(
            username=self.username,
            password=self.__password,
            key=self.__keys[self.__key_index],
            keys=self.__keys,
            key_filename=self.key_filename,
            passphrase=self.__passphrase,
        )

    def __repr__(self) -> str:
        """Representation for debug purposes.

        :return: Partial instance fields in human-friendly format.
        :rtype: str
        """
        if self.__keys[self.__key_index] is None:
            _key: str | None = None
        else:
            _key = f"<private for pub: {self.public_key}>"
        _keys: list[str | None] = []
        for idx, k in enumerate(self.__keys):
            if idx == self.__key_index:
                continue
            # noinspection PyTypeChecker
            _keys.append(f"<private for pub: {self.__get_public_key(key=k)}>" if k is not None else None)

        return (
            f"{self.__class__.__name__}("
            f"username={self.username!r}, "
            f"password=<*masked*>, "
            f"key={_key}, "
            f"keys={_keys}, "
            f"key_filename={self.key_filename!r}, "
            f"passphrase=<*masked*>,"
            f")"
        )

    def __str__(self) -> str:
        """Representation for debug purposes.

        :return: Username related to class instance.
        :rtype: str
        """
        return f"{self.__class__.__name__} for {self.username}"


class SSHAuthMapping(typing.Dict[str, SSHAuth]):
    """Specific dictionary for ssh hostname - auth mapping.

    Keys are always string and saved/collected lowercase.
    """

    __slots__ = ()

    def __init__(
        self,
        auth_dict: dict[str, SSHAuth] | SSHAuthMapping | None = None,
        **auth_mapping: SSHAuth,
    ) -> None:
        """Specific dictionary for ssh hostname - auth mapping.

        :param auth_dict: Original hostname - source ssh auth mapping (dictionary of SSHAuthMapping).
        :type auth_dict: dict[str, SSHAuth] | SSHAuthMapping | None
        :param auth_mapping: SSHAuth setting via **kwargs.
        :type auth_mapping: SSHAuth
        :raises TypeError: Incorrect type of auth dict or auth object.
        """
        super().__init__()
        if auth_dict is not None:
            if isinstance(auth_dict, (dict, SSHAuthMapping)):
                for hostname in auth_dict:
                    self[hostname] = auth_dict[hostname]
            else:  # pragma: no cover
                raise TypeError(f"Incorrect type of auth dict! (got: {auth_dict!r})")

        for hostname, auth in auth_mapping.items():
            if isinstance(auth, SSHAuth):
                self[hostname] = auth
            else:  # pragma: no cover
                raise TypeError(f"Auth object have incorrect type: (got {auth!r})")

    def __setitem__(self, hostname: str, auth: SSHAuth) -> None:
        """Dict-like access.

        :param hostname: Key - hostname.
        :type hostname: str
        :param auth: value - SSHAuth object.
        :type auth: SSHAuth
        :raises TypeError: Key is not string or value is not SSHAuth.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        if not isinstance(auth, SSHAuth):  # pragma: no cover
            raise TypeError(f"Value {auth!r} is not SSHAuth object!")
        super().__setitem__(hostname.lower(), auth)

    def __getitem__(self, hostname: str) -> SSHAuth:
        """Dict-like access.

        :param hostname: Key - hostname.
        :type hostname: str
        :return: Associated SSHAuth object.
        :rtype: SSHAuth
        :raises TypeError: Key is not a string.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        return super().__getitem__(hostname.lower())

    @typing.overload
    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: SSHAuth,
    ) -> SSHAuth:
        """Try to guess hostname with credentials."""

    @typing.overload
    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: None = None,
    ) -> SSHAuth | None:
        """Try to guess hostname with credentials."""

    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: SSHAuth | None = None,
    ) -> SSHAuth | None:
        """Try to guess hostname with credentials.

        :param hostname: Expected target hostname.
        :type hostname: str
        :param host_names: Alternate host names.
        :type host_names: str
        :param default: Credentials if hostname not found.
        :type default: SSHAuth | None
        :return: Guessed credentials.
        :rtype: SSHAuth | None
        :raises TypeError: Default SSH Auth object is not SSHAuth.

        Method used in cases when 1 host shares two or more names in config.
        """
        if default is not None and not isinstance(default, SSHAuth):  # pragma: no cover
            raise TypeError(f"Default SSH Auth object is not SSHAuth!. (got {default!r})")
        if hostname in self:
            return self[hostname]
        for host in host_names:
            if host in self:
                return self[host]
        return default

    def __delitem__(self, hostname: str) -> None:
        """Dict-like access.

        :param hostname: Key - hostname.
        :type hostname: str
        :raises TypeError: Key is not a string.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        super().__delitem__(hostname.lower())
