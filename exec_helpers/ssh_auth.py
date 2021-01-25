#    Copyright 2018 - 2021 Alexey Stepanov aka penguinolog.

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

from __future__ import annotations

# Standard Library
import copy
import logging
import typing

# External Dependencies
import paramiko

if typing.TYPE_CHECKING:
    # Standard Library
    import socket

__all__ = ("SSHAuth",)

LOGGER = logging.getLogger(__name__)


class SSHAuth:
    """SSH Authorization object."""

    __slots__ = ("__username", "__password", "__key_index", "__keys", "__key_filename", "__passphrase")

    def __init__(
        self,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        key: typing.Optional[paramiko.PKey] = None,
        keys: typing.Optional[typing.Sequence[typing.Union[paramiko.PKey, None]]] = None,
        key_filename: typing.Union[typing.Iterable[str], str, None] = None,
        passphrase: typing.Optional[str] = None,
    ) -> None:
        """SSH credentials object.

        Used to authorize SSHClient.
        Single SSHAuth object is associated with single host:port.
        Password and key is private, other data is read-only.

        :param username: remote username.
        :type username: typing.Optional[str]
        :param password: remote password
        :type password: typing.Optional[str]
        :param key: Main connection key
        :type key: typing.Optional[paramiko.PKey]
        :param keys: Alternate connection keys
        :type keys: typing.Optional[typing.Sequence[typing.Union[paramiko.PKey, None]]]
        :param key_filename: filename(s) for additional key files
        :type key_filename: typing.Union[typing.Iterable[str], str, None]
        :param passphrase: passphrase for keys. Need, if differs from password
        :type passphrase: typing.Optional[str]

        .. versionchanged:: 1.0.0
            added: key_filename, passphrase arguments
        """
        self.__username: typing.Optional[str] = username
        self.__password: typing.Optional[str] = password

        self.__keys: typing.List[typing.Union[None, paramiko.PKey]] = []

        if key is not None:
            # noinspection PyTypeChecker
            self.__keys.append(key)

        if keys is not None:
            for k in keys:
                if k not in self.__keys and k != key:
                    self.__keys.append(k)

        self.__keys.append(None)

        self.__key_index: int = 0

        if key_filename is None:
            self.__key_filename: typing.Collection[str] = ()
        elif isinstance(key_filename, str):
            self.__key_filename = (key_filename,)
        else:
            self.__key_filename = tuple(key_filename)
        self.__passphrase: typing.Optional[str] = passphrase

    @property
    def username(self) -> typing.Optional[str]:
        """Username for auth.

        :return: auth username
        :rtype: str
        """
        return self.__username

    @staticmethod
    def __get_public_key(key: typing.Union[paramiko.PKey, None]) -> typing.Optional[str]:
        """Internal method for get public key from private.

        :param key: SSH private key
        :type key: paramiko.PKey
        :return: public key text if applicable
        :rtype: typing.Optional[str]
        """
        if key is None:
            return None
        return f"{key.get_name()} {key.get_base64()}"

    @property
    def public_key(self) -> typing.Optional[str]:
        """Public key for stored private key if presents else None.

        :return: public key for current private key
        :rtype: str
        """
        return self.__get_public_key(self.__keys[self.__key_index])

    @property
    def key_filename(self) -> typing.Collection[str]:
        """Key filename(s).

        :return: copy of used key filename (original should not be changed via mutability).
        .. versionadded:: 1.0.0
        .. versionchanged:: 7.0.5 changed type relying on paramiko sources
        """
        return self.__key_filename

    def enter_password(self, tgt: typing.BinaryIO) -> None:
        """Enter password to STDIN.

        Note: required for 'sudo' call

        :param tgt: Target
        :type tgt: typing.BinaryIO
        """
        # noinspection PyTypeChecker
        tgt.write(f"{self.__password if self.__password is not None else ''}\n".encode("utf-8"))

    def connect(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        port: int = 22,
        log: bool = True,
        *,
        sock: typing.Optional[typing.Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]] = None,
    ) -> None:
        """Connect SSH client object using credentials.

        :param client: SSH Client (low level)
        :type client: paramiko.SSHClient
        :param hostname: remote hostname
        :type hostname: str
        :param port: remote ssh port
        :type port: int
        :param log: Log on generic connection failure
        :type log: bool
        :param sock: socket for connection. Useful for ssh proxies support
        :type sock: typing.Optional[typing.Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]]
        :raises PasswordRequiredException: No password has been set, but required.
        :raises AuthenticationException: Authentication failed.
        """
        kwargs: typing.Dict[str, typing.Any] = {}

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
                    key_filename=self.__key_filename,  # type: ignore  # types verified by code (not signature)
                    **kwargs,
                )
                if index != self.__key_index:
                    self.__key_index = index
                    LOGGER.debug(f"Main key has been updated, public key is: \n{self.public_key}")
                return
            except paramiko.PasswordRequiredException:
                if self.__password is None:
                    LOGGER.exception("No password has been set!")
                    raise
                LOGGER.critical("Unexpected PasswordRequiredException, when password is set!")
                raise
            except (paramiko.AuthenticationException, paramiko.BadHostKeyException):
                continue
        msg: str = "Connection using stored authentication info failed!"
        if log:
            LOGGER.exception(msg)
        raise paramiko.AuthenticationException(msg)

    def __hash__(self) -> int:
        """Hash for usage as dict keys and comparison.

        :return: hash value
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

    def __eq__(self, other: typing.Any) -> bool:
        """Comparison helper.

        :param other: other SSHAuth instance
        :type other: typing.Any
        :return: current object equals other
        :rtype: bool
        """
        return hash(self) == hash(other)

    def __ne__(self, other: typing.Any) -> bool:
        """Comparison helper.

        :param other: other SSHAuth instance
        :type other: typing.Any
        :return: current object not equals other
        :rtype: bool
        """
        return not self.__eq__(other)

    def __deepcopy__(self, memo: typing.Any) -> SSHAuth:
        """Helper for copy.deepcopy.

        :param memo: copy.deepcopy() memodict
        :type memo: typing.Any
        :return: re-constructed copy of current class
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

        :return: re-constructed copy of current class
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

        :return: partial instance fields in human-friendly format
        :rtype: str
        """
        if self.__keys[self.__key_index] is None:
            _key: typing.Optional[str] = None
        else:
            _key = f"<private for pub: {self.public_key}>"
        _keys: typing.List[typing.Union[str, None]] = []
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

        :return: user name related to class instance
        :rtype: str
        """
        return f"{self.__class__.__name__} for {self.username}"


class SSHAuthMapping(typing.Dict[str, SSHAuth]):
    """Specific dictionary for  ssh hostname - auth mapping.

    keys are always string and saved/collected lowercase.
    """

    __slots__ = ()

    def __init__(
        self,
        auth_dict: typing.Optional[typing.Union[typing.Dict[str, SSHAuth], SSHAuthMapping]] = None,
        **auth_mapping: SSHAuth,
    ) -> None:
        """Specific dictionary for  ssh hostname - auth mapping.

        :param auth_dict: original hostname - source ssh auth mapping (dictionary of SSHAuthMapping)
        :type auth_dict: typing.Optional[typing.Union[typing.Dict[str, SSHAuth], SSHAuthMapping]]
        :param auth_mapping: SSHAuth setting via **kwargs
        :type auth_mapping: SSHAuth
        :raises TypeError: Incorrect type of auth dict or auth object
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

        :param hostname: key - hostname
        :type hostname: str
        :param auth: value - SSHAuth object
        :type auth: SSHAuth
        :raises TypeError: key is not string or value is not SSHAuth.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        if not isinstance(auth, SSHAuth):  # pragma: no cover
            raise TypeError(f"Value {auth!r} is not SSHAuth object!")
        super().__setitem__(hostname.lower(), auth)  # pylint: disable=no-member

    def __getitem__(self, hostname: str) -> SSHAuth:
        """Dict-like access.

        :param hostname: key - hostname
        :type hostname: str
        :return: associated SSHAuth object
        :rtype: SSHAuth
        :raises TypeError: key is not string.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        return super().__getitem__(hostname.lower())  # pylint: disable=no-member

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
    ) -> typing.Optional[SSHAuth]:
        """Try to guess hostname with credentials."""

    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: typing.Optional[SSHAuth] = None,
    ) -> typing.Optional[SSHAuth]:
        """Try to guess hostname with credentials.

        :param hostname: expected target hostname
        :type hostname: str
        :param host_names: alternate host names
        :type host_names: str
        :param default: credentials if hostname not found
        :type default: typing.Optional[SSHAuth]
        :return: guessed credentials
        :rtype: typing.Optional[SSHAuth]
        :raises TypeError: Default SSH Auth object is not SSHAuth

        Method used in cases, when 1 host share 2 or more names in config.
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

        :param hostname: key - hostname
        :type hostname: str
        :raises TypeError: key is not string.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        super().__delitem__(hostname.lower())  # pylint: disable=no-member
