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

"""SSH client credentials class."""

__all__ = ("SSHAuth",)

# Standard Library
import copy
import logging
import socket
import typing

# External Dependencies
import paramiko  # type: ignore

LOGGER = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


cdef class SSHAuth:
    """SSH Authorization object."""

    cdef:
        readonly object username
        readonly object key_filename
        object password
        object key
        list keys
        object passphrase

    def __init__(
        self,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        key: typing.Optional[paramiko.RSAKey] = None,
        keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = None,
        key_filename: typing.Union[typing.List[str], str, None] = None,
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
        self.username = username  # type: typing.Optional[str]
        self.password = password  # type: typing.Optional[str]
        self.key = key  # type: typing.Optional[paramiko.RSAKey]
        self.keys = [None]  # type: typing.List[typing.Union[None, paramiko.RSAKey]]
        if key is not None:
            # noinspection PyTypeChecker
            self.keys.append(key)
        if keys is not None:
            for k in keys:
                if k not in self.keys:
                    self.keys.append(k)
        if key_filename is None or isinstance(key_filename, list):
            self.key_filename = key_filename  # type: typing.Optional[typing.List[str]]
        else:
            self.__key_filename = [key_filename]
        self.passphrase = passphrase  # type: typing.Optional[str]

    @staticmethod
    def __get_public_key(key: typing.Union[paramiko.RSAKey, None]) -> typing.Optional[str]:
        """Internal method for get public key from private.

        :param key: SSH private key
        :type key: paramiko.RSAKey
        :returns: public key text if applicable
        :rtype: typing.Optional[str]
        """
        if key is None:
            return None
        return f"{key.get_name()} {key.get_base64()}"

    @property
    def public_key(self) -> typing.Optional[str]:
        """Public key for stored private key if presents else None.

        :returns: public key for current private key
        :rtype: str
        """
        return self.__get_public_key(self.key)

    def enter_password(self, tgt: typing.BinaryIO) -> None:
        """Enter password to STDIN.

        Note: required for 'sudo' call

        :param tgt: Target
        :type tgt: typing.BinaryIO
        """
        # noinspection PyTypeChecker
        tgt.write(f"{self.password if self.password is not None else ''}\n".encode("utf-8"))

    def connect(
        self,
        client: typing.Union[paramiko.SSHClient, paramiko.Transport],
        hostname: typing.Optional[str] = None,
        unsigned int port = 22,
        bint log = True,
        *,
        sock: typing.Optional[typing.Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]] = None,
    ) -> None:
        """Connect SSH client object using credentials.

        :param client: SSH Client (low level)
        :type client: typing.Union[paramiko.SSHClient, paramiko.Transport]
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
        kwargs = {"username": self.username, "password": self.password}  # type: typing.Dict[str, typing.Any]
        if hostname is not None:
            kwargs["hostname"] = hostname
            kwargs["port"] = port

        if self.key_filename is not None:
            kwargs["key_filename"] = self.key_filename
        if self.passphrase is not None:
            kwargs["passphrase"] = self.passphrase
        if sock is not None:
            kwargs["sock"] = sock

        keys = [self.key]  # type: typing.List[typing.Union[None, paramiko.RSAKey]]
        keys.extend([k for k in self.keys if k != self.key])

        for key in keys:
            kwargs["pkey"] = key
            try:
                client.connect(**kwargs)
                if self.key != key:
                    self.key = key
                    LOGGER.debug(f"Main key has been updated, public key is: \n{self.public_key}")
                return
            except paramiko.PasswordRequiredException:
                if self.password is None:
                    LOGGER.exception("No password has been set!")
                    raise
                LOGGER.critical("Unexpected PasswordRequiredException, when password is set!")
                raise
            except (paramiko.AuthenticationException, paramiko.BadHostKeyException):
                continue
        msg = "Connection using stored authentication info failed!"
        if log:
            LOGGER.exception(msg)
        raise paramiko.AuthenticationException(msg)

    def __hash__(self) -> int:
        """Hash for usage as dict keys and comparison."""
        return hash(
            (
                self.__class__,
                self.username,
                self.password,
                tuple(self.keys),
                (tuple(self.key_filename) if isinstance(self.key_filename, list) else self.key_filename),
                self.passphrase,
            )
        )

    def __eq__(self, other: typing.Any) -> bool:
        """Comparison helper.

        :param other: other SSHAuth instance
        :returns: current object equals other
        """
        return hash(self) == hash(other)

    def __ne__(self, other: typing.Any) -> bool:
        """Comparison helper.

        :param other: other SSHAuth instance
        :returns: current object not equals other
        """
        return not self.__eq__(other)

    def __deepcopy__(self, memo: typing.Any) -> "SSHAuth":
        """Helper for copy.deepcopy.

        :param memo: copy.deeepcopy() memodict
        :returns: re-constructed copy of current class
        """
        return self.__class__(
            username=self.username, password=self.password, key=self.key, keys=copy.deepcopy(self.keys)
        )

    def __copy__(self) -> "SSHAuth":
        """Copy self."""
        return self.__class__(username=self.username, password=self.password, key=self.key, keys=self.keys)

    def __repr__(self) -> str:
        """Representation for debug purposes."""
        _key = None if self.key is None else f"<private for pub: {self.public_key}>"  # type: typing.Optional[str]
        cdef list _keys = []  # type: typing.List[typing.Union[str, None]]
        for k in self.keys:
            if k == self.key:
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
        """Representation for debug purposes."""
        return f"{self.__class__.__name__} for {self.username}"


cdef class SSHAuthMapping(dict):
    """Specific dict-like ssh hostname - auth mapping."""

    def __init__(
        self,
        auth_dict: typing.Optional[typing.Union[typing.Dict[str, SSHAuth], "SSHAuthMapping"]] = None,
        **auth_mapping: SSHAuth,
    ) -> None:
        """Specific dict-like ssh hostname - auth mapping.

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
            else:
                raise TypeError(f"Incorrect type of auth dict! (got: {auth_dict!r})")

        for hostname, auth in auth_mapping.items():
            if isinstance(auth, SSHAuth):
                self[hostname] = auth
            else:
                raise TypeError(f"Auth object have incorrect type: (got {auth!r})")

    def __setitem__(self, str hostname, SSHAuth auth) -> None:
        """Dict-like access.

        :param hostname: key - hostname
        :type hostname: str
        :param auth: value - SSHAuth object
        :type auth: SSHAuth
        :raises TypeError: key is not string or value is not SSHAuth.
        """
        super().__setitem__(hostname.lower(), auth)

    def __getitem__(self, str hostname) -> SSHAuth:
        """Dict-like access.

        :param hostname: key - hostname
        :type hostname: str
        :returns: associated SSHAuth object
        :rtype: SSHAuth
        :raises TypeError: key is not string.
        """
        return super().__getitem__(hostname.lower())

    def get_with_alt_hostname(
        self, str hostname, *host_names: str, default: typing.Optional[SSHAuth] = None
    ) -> typing.Optional[SSHAuth]:
        """Try to guess hostname with credentials.

        :param hostname: expected target hostname
        :type hostname: str
        :param host_names: alternate host names
        :type host_names: str
        :param default: credentials if hostname not found
        :type default: typing.Optional[SSHAuth]
        :returns: guessed credentials
        :rtype: typing.Optional[SSHAuth]
        :raises TypeError: Default SSH Auth object is not SSHAuth
        """
        if default is not None and not isinstance(default, SSHAuth):
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
        if not isinstance(hostname, str):
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        super().__delitem__(hostname.lower())
