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

# Standard Library
import copy
import logging
import typing
import warnings

# External Dependencies
import paramiko

if typing.TYPE_CHECKING:
    # Standard Library
    import pathlib
    import socket
    from collections.abc import Collection
    from collections.abc import Iterable
    from collections.abc import Sequence

__all__ = ("SSHAuth", "AuthStrategy")

LOGGER = logging.getLogger(__name__)


def _try_to_get_pkey(path: str | pathlib.Path, passphrases: Collection[str | None]) -> paramiko.PKey:
    for idx, passwd in enumerate(passphrases):
        try:
            return paramiko.PKey.from_path(path, passwd)  # type: ignore[no-any-return,attr-defined]
        except paramiko.PasswordRequiredException:  # noqa: PERF203
            if idx + 1 < len(passphrases):
                continue
            raise
    raise RuntimeError("No key created and all exception silenced.")


class AuthStrategy(paramiko.AuthStrategy):  # type: ignore[name-defined,misc]  # stubs is outdated
    """Paramiko authorisation strategy with static credentials."""

    __slots__ = ("__sources", "__password")

    def __init__(
        self,
        ssh_config: paramiko.SSHConfig | None = None,
        *,
        username: str = "",
        password: str | None = None,
        keys: Sequence[paramiko.PKey | None] = (),
        key_filename: Iterable[str] | str | None = None,
        passphrase: str | None = None,
        sources: Iterable[paramiko.AuthSource] = (),  # type: ignore[name-defined]
    ):
        """SSH AuthStrategy for paramiko.

        :param ssh_config: ssh config object (source for data). Required only by base class.
        :type ssh_config: paramiko.SSHConfig | None
        :param username: auth username. Used for paramiko.Password auth.
        :type username: str
        :param password: auth password. Used for paramiko.Password auth generation.
        :type password: str | None
        :param keys: ssh keys. Used for paramiko.InMemoryPrivateKey generation.
        :type keys: Sequence[paramiko.PKey | None]
        :param key_filename: key filename(s) for paramiko.OnDiskPrivateKey generation
        :type key_filename: Iterable[str] | str | None
        :param passphrase: passphrase for on-disk private keys decoding. Parameter `password` will be used as fallback
        :type passphrase: str | None
        :param sources: ready to use AuthSource objects
        :type sources: Iterable[paramiko.AuthSource]
        """
        super().__init__(ssh_config if ssh_config is not None else paramiko.SSHConfig())
        self.__password = f"{password if password is not None else ''}\n".encode()

        sources_prep: list[paramiko.AuthSource] = []  # type: ignore[name-defined]

        sources_prep.extend(sources)

        if password:
            sources_prep.append(
                paramiko.Password(  # type: ignore[attr-defined]
                    username,
                    password_getter=lambda: password,
                )
            )

        sources_prep.extend(
            paramiko.InMemoryPrivateKey(  # type: ignore[attr-defined]
                username,
                pkey,
            )
            for pkey in keys
            if pkey is not None
        )

        if key_filename:
            if isinstance(key_filename, str):
                sources_prep.append(
                    paramiko.OnDiskPrivateKey(  # type: ignore[attr-defined]
                        username,
                        source="python-config",
                        path=key_filename,
                        pkey=_try_to_get_pkey(key_filename, passphrases={passphrase, password, None}),
                    )
                )
            else:
                sources_prep.extend(
                    paramiko.OnDiskPrivateKey(  # type: ignore[attr-defined]
                        username,
                        source="python-config",
                        path=pth,
                        pkey=_try_to_get_pkey(pth, passphrases={passphrase, password, None}),
                    )
                    for pth in key_filename
                )

        self.__sources = tuple(sources_prep)

    @property
    def username(self) -> str:
        """Username for auth.

        .. note:: first available in auth sources username will be used
        """
        return next((auth.username for auth in self.__sources if auth.username), "")

    def enter_password(self, tgt: typing.BinaryIO) -> None:
        """Enter password to STDIN.

        .. note:: required for 'sudo' call
        .. warning:: only password provided explicit in constructor will be used.

        :param tgt: Target
        :type tgt: typing.BinaryIO
        """
        # noinspection PyTypeChecker
        tgt.write(self.__password)

    def get_sources(self) -> Collection[paramiko.AuthSource]:  # type: ignore[name-defined]
        """Auth sources getter.

        .. note:: We can not use `Iterator` since we are support re-connect
        """
        return self.__sources

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"for username={self.username!r} "
            f"and sources {[src.__class__.__name__ for src in self.__sources]}>"
        )


class SSHAuth:
    """SSH Authorization object."""

    __slots__ = ("__username", "__password", "__keys", "__key_filename", "__passphrase")

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

        :param username: remote username.
        :type username: str | None
        :param password: remote password
        :type password: str | None
        :param key: Main connection key
        :type key: paramiko.PKey | None
        :param keys: Alternate connection keys
        :type keys: Sequence[paramiko.PKey | None] | None
        :param key_filename: filename(s) for additional key files
        :type key_filename: Iterable[str] | str | None
        :param passphrase: passphrase for keys. Need, if differs from password
        :type passphrase: str | None

        .. versionchanged:: 1.0.0 added: key_filename, passphrase arguments
        .. deprecated:: 8.0.0
           not used internally

        """
        warnings.warn(
            "SSHAuth is deprecated. Please use `AuthStrategy` instead for authentication purposes.",
            DeprecationWarning,
            stacklevel=2,
        )
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

        :return: auth username
        :rtype: str
        """
        return self.__username

    @property
    def auth_strategy(self) -> AuthStrategy:
        """Auth strategy for real usage."""
        return AuthStrategy(
            ssh_config=paramiko.SSHConfig(),
            username=self.__username if self.__username is not None else "",
            password=self.__password,
            keys=self.__keys,
            key_filename=self.__key_filename,
            passphrase=self.__passphrase,
        )

    @staticmethod
    def __get_public_key(key: paramiko.PKey | None) -> str | None:
        """Internal method for get public key from private.

        :param key: SSH private key
        :type key: paramiko.PKey
        :return: public key text if applicable
        :rtype: str | None
        """
        if key is None:
            return None
        return f"{key.get_name()} {key.get_base64()}"

    @property
    def key_filename(self) -> Collection[str]:
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
        tgt.write(f"{self.__password if self.__password is not None else ''}\n".encode())

    def connect(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        port: int = 22,
        log: bool = True,
        *,
        sock: paramiko.ProxyCommand | paramiko.Channel | socket.socket | None = None,
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
        :type sock: paramiko.ProxyCommand | paramiko.Channel | socket.socket | None
        :raises PasswordRequiredException: No password has been set, but required.
        :raises AuthenticationException: Authentication failed.

        .. deprecated:: 8.0.0
        """
        try:
            # noinspection PyTypeChecker
            client.connect(
                hostname=hostname,
                port=port,
                sock=sock,  # type: ignore[arg-type]  # outdated stubs
                auth_strategy=self.auth_strategy,
            )
        except paramiko.BadHostKeyException as exc:
            LOGGER.exception(f"Connection impossible: {exc}")  # noqa: TRY401
            raise
        except paramiko.PasswordRequiredException:
            if self.__password is None:
                LOGGER.exception("No password has been set!")
                raise
            LOGGER.critical("Unexpected PasswordRequiredException, when password is set!")
            raise

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

    def __eq__(self, other: object) -> bool:
        """Comparison helper.

        :param other: other SSHAuth instance
        :type other: typing.Any
        :return: current object equals other
        :rtype: bool
        """
        return hash(self) == hash(other)

    def __ne__(self, other: object) -> bool:
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
            keys=self.__keys,
            key_filename=self.key_filename,
            passphrase=self.__passphrase,
        )

    def __repr__(self) -> str:
        """Representation for debug purposes.

        :return: partial instance fields in human-friendly format
        :rtype: str
        """
        _keys: list[str | None] = [
            f"<private for pub: {self.__get_public_key(key=k)}>" if k is not None else None
            for idx, k in enumerate(self.__keys)
        ]

        return (
            f"{self.__class__.__name__}("
            f"username={self.username!r}, "
            f"password=<*masked*>, "
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


class SSHAuthStrategyMapping(typing.Dict[str, AuthStrategy]):
    """Specific dictionary for ssh hostname - auth_strategy mapping.

    keys are always string and saved/collected lowercase.
    """

    __slots__ = ()

    def __init__(
        self,
        auth_dict: dict[str, AuthStrategy] | SSHAuthStrategyMapping | None = None,
        **auth_mapping: AuthStrategy,
    ) -> None:
        """Specific dictionary for ssh hostname - auth_strategy mapping.

        :param auth_dict: original hostname - source ssh auth_strategy mapping (dictionary of SSHAuthStrategyMapping)
        :type auth_dict: dict[str, paramiko.AuthStrategy] | SSHAuthStrategyMapping | None
        :param auth_mapping: AuthStrategy setting via **kwargs
        :type auth_mapping: paramiko.AuthStrategy
        :raises TypeError: Incorrect type of auth_strategy dict or auth_strategy object
        """
        super().__init__()
        if auth_dict is not None:
            if isinstance(auth_dict, (dict, SSHAuthStrategyMapping)):
                for hostname in auth_dict:
                    self[hostname] = auth_dict[hostname]
            else:  # pragma: no cover
                raise TypeError(f"Incorrect type of auth_strategy dict! (got: {auth_dict!r})")

        for hostname, auth in auth_mapping.items():
            if isinstance(auth, AuthStrategy):
                self[hostname] = auth
            else:  # pragma: no cover
                raise TypeError(f"Auth object have incorrect type: (got {auth!r})")

    def __setitem__(self, hostname: str, auth_strategy: AuthStrategy) -> None:
        """Dict-like access.

        :param hostname: key - hostname
        :type hostname: str
        :param auth_strategy: value - AuthStrategy object
        :type auth_strategy: AuthStrategy
        :raises TypeError: key is not string or value is not SSHAuth.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        if not isinstance(auth_strategy, AuthStrategy):  # pragma: no cover
            raise TypeError(f"Value {auth_strategy!r} is not AuthStrategy object!")
        super().__setitem__(hostname.lower(), auth_strategy)

    def __getitem__(self, hostname: str) -> AuthStrategy:
        """Dict-like access.

        :param hostname: key - hostname
        :type hostname: str
        :return: associated SSHAuth object
        :rtype: AuthStrategy
        :raises TypeError: key is not string.
        """
        if not isinstance(hostname, str):  # pragma: no cover
            raise TypeError(f"Hostname should be string only! Got: {hostname!r}")
        return super().__getitem__(hostname.lower())

    @typing.overload
    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: AuthStrategy,
    ) -> AuthStrategy:
        """Try to guess hostname with credentials."""

    @typing.overload
    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: None = None,
    ) -> AuthStrategy | None:
        """Try to guess hostname with credentials."""

    def get_with_alt_hostname(
        self,
        hostname: str,
        *host_names: str,
        default: AuthStrategy | None = None,
    ) -> AuthStrategy | None:
        """Try to guess hostname with credentials.

        :param hostname: expected target hostname
        :type hostname: str
        :param host_names: alternate host names
        :type host_names: str
        :param default: credentials if hostname not found
        :type default: AuthStrategy | None
        :return: guessed credentials
        :rtype: AuthStrategy | None
        :raises TypeError: Default AuthStrategy object is not AuthStrategy

        Method used in cases, when 1 host share 2 or more names in config.
        """
        if default is not None and not isinstance(default, AuthStrategy):  # pragma: no cover
            raise TypeError(f"Default AuthStrategy object is not paramiko.AuthStrategy!. (got {default!r})")
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
        super().__delitem__(hostname.lower())


class SSHAuthMapping(typing.Dict[str, SSHAuth]):
    """Specific dictionary for ssh hostname - auth_strategy mapping.

    keys are always string and saved/collected lowercase.
    """

    __slots__ = ()

    def __init__(
        self,
        auth_dict: dict[str, SSHAuth] | SSHAuthMapping | None = None,
        **auth_mapping: SSHAuth,
    ) -> None:
        """Specific dictionary for ssh hostname - auth_strategy mapping.

        :param auth_dict: original hostname - source ssh auth_strategy mapping (dictionary of SSHAuthMapping)
        :type auth_dict: dict[str, SSHAuth] | SSHAuthMapping | None
        :param auth_mapping: SSHAuth setting via **kwargs
        :type auth_mapping: SSHAuth
        :raises TypeError: Incorrect type of auth_strategy dict or auth_strategy object

        .. deprecated:: 8.0.0
           not used internally
        """
        super().__init__()
        if auth_dict is not None:
            if isinstance(auth_dict, (dict, SSHAuthMapping)):
                for hostname in auth_dict:
                    self[hostname] = auth_dict[hostname]
            else:  # pragma: no cover
                raise TypeError(f"Incorrect type of auth_strategy dict! (got: {auth_dict!r})")

        for hostname, auth in auth_mapping.items():
            if isinstance(auth, SSHAuth):
                self[hostname] = auth
            else:  # pragma: no cover
                raise TypeError(f"Auth object have incorrect type: (got {auth!r})")

    def get_auth_strategy_mapping(self) -> SSHAuthStrategyMapping:
        """Get SSHAuthStrategyMapping."""
        return SSHAuthStrategyMapping({hostname: auth.auth_strategy for hostname, auth in self.items()})

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
        super().__setitem__(hostname.lower(), auth)

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

        :param hostname: expected target hostname
        :type hostname: str
        :param host_names: alternate host names
        :type host_names: str
        :param default: credentials if hostname not found
        :type default: SSHAuth | None
        :return: guessed credentials
        :rtype: SSHAuth | None
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
        super().__delitem__(hostname.lower())
