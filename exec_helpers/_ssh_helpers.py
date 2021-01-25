"""SSH client shared helpers."""

from __future__ import annotations

# Standard Library
import functools
import pathlib
import typing

# External Dependencies
import paramiko

if typing.TYPE_CHECKING:
    # External Dependencies
    # noinspection PyPackageRequirements
    import logwrap

SSHConfigDictLikeT = typing.Dict[str, typing.Union[str, int, bool, typing.Collection[str]]]
SSHConfigsDictT = typing.Dict[str, SSHConfigDictLikeT]


# Parse default SSHConfig if available
SSH_CONFIG_FILE_SYSTEM = pathlib.Path("/etc/ssh/ssh_config")
SSH_CONFIG_FILE_USER = pathlib.Path("~/.ssh/config").expanduser()


@functools.lru_cache(maxsize=128, typed=True)
def _parse_ssh_config_file(file_path: pathlib.Path) -> typing.Optional[paramiko.SSHConfig]:
    """Parse ssh config file.

    :param file_path: file path for parsing
    :type file_path: pathlib.Path
    :return: SSH config if file found and parsed else None
    :rtype: typing.Optional[paramiko.SSHConfig]
    """
    if not file_path.exists():
        return None
    # noinspection PyBroadException
    try:
        config = paramiko.SSHConfig()
        with file_path.open() as f_obj:
            config.parse(f_obj)
        return config
    except Exception:
        return None


class SSHConfig:
    """Parsed SSH Config for creation connection."""

    __slots__ = (
        "__hostname",
        "__user",
        "__port",
        "__identityfile",
        "__proxycommand",
        "__proxyjump",
        "__controlpath",
        "__controlmaster",
    )

    def __init__(
        self,
        hostname: str,
        port: typing.Optional[typing.Union[str, int]] = None,
        user: typing.Optional[str] = None,
        identityfile: typing.Optional[typing.Collection[str]] = None,
        proxycommand: typing.Optional[str] = None,
        proxyjump: typing.Optional[str] = None,
        *,
        controlpath: typing.Optional[str] = None,
        controlmaster: typing.Optional[typing.Union[str, bool]] = None,
    ):
        """SSH Config for creation connection.

        :param hostname: hostname, which config relates
        :type hostname: str
        :param port: remote port
        :type port: typing.Optional[typing.Union[str, int]]
        :param user: remote user
        :type user: typing.Optional[str]
        :param identityfile: connection ssh keys file names
        :type identityfile: typing.Optional[typing.Collection[str]]
        :param proxycommand: proxy command for ssh connection
        :type proxycommand: typing.Optional[str]
        :type proxyjump: typing.Optional[str]
        :param proxyjump: proxy host name
        :param controlpath: shared socket file path for re-using connection by multiple instances
        :type controlpath: typing.Optional[str]
        :param controlmaster: re-use connection
        :type controlmaster: typing.Optional[typing.Union[str, bool]]
        :raises ValueError: Invalid argument provided.

        .. versionadded:: 6.0.0
        """
        self.__hostname: str = hostname
        self.__port: typing.Optional[int] = self._parse_optional_int(port)
        if isinstance(self.__port, int) and not 0 < self.__port < 65535:
            raise ValueError(f"port {self.__port} if not in range [1, 65535], which is incorrect.")

        self.__user: typing.Optional[str] = user
        self.__identityfile: typing.Optional[typing.Collection[str]] = identityfile

        if proxycommand and proxyjump:
            raise ValueError(
                f"ProxyCommand ({proxycommand}) and ProxyJump ({proxyjump}) is mixed for single connection!"
            )

        self.__proxycommand: typing.Optional[str] = proxycommand
        self.__proxyjump: typing.Optional[str] = proxyjump
        self.__controlpath: typing.Optional[str] = controlpath
        self.__controlmaster: typing.Optional[bool] = self._parse_optional_bool(controlmaster)

    def __hash__(self) -> int:  # pragma: no cover
        """Hash for caching possibility.

        :return: hash for instance
        :rtype: int
        """
        return hash(
            (
                self.__class__,
                self.__hostname,
                self.__port,
                self.__user,
                self.__identityfile if self.__identityfile is None else tuple(self.__identityfile),
                self.__proxycommand,
                self.__proxyjump,
                self.__controlpath,
                self.__controlmaster,
            )
        )

    def __repr__(self) -> str:
        """Debug support.

        :return: string representation allowing to re-construct object
        :rtype: str
        """
        return (
            f"{self.__class__.__name__}("
            f"hostname={self.hostname!r}, "
            f"port={self.port!r}, "
            f"user={self.user!r}, "
            f"identityfile={self.identityfile!r}, "
            f"proxycommand={self.proxycommand!r}, "
            f"proxyjump={self.proxyjump!r}, "
            f"controlpath={self.controlpath!r}, "
            f"controlmaster={self.controlmaster!r}, "
            f")"
        )

    def __pretty_repr__(
        self,
        log_wrap: logwrap.PrettyRepr,
        indent: int = 0,
        no_indent_start: bool = False,
    ) -> str:
        """Make human readable representation of object.

        :param log_wrap: logwrap instance
        :type log_wrap: logwrap.PrettyRepr
        :param indent: start indentation
        :type indent: int
        :param no_indent_start: do not indent open bracket and simple parameters
        :type no_indent_start: bool
        :return: formatted string
        :rtype: str
        """
        next_indent = log_wrap.next_indent(indent)
        msg = (
            f"{'':<{0 if no_indent_start else indent}}{self.__class__.__name__}(\n"
            f"{'':<{next_indent}}hostname={self.hostname!r},\n"
            f"{'':<{next_indent}}port={self.port!r},\n"
            f"{'':<{next_indent}}user={self.user!r},\n"
            f"{'':<{next_indent}}identityfile={self.identityfile!r},\n"
            f"{'':<{next_indent}}proxycommand={self.proxycommand!r},\n"
            f"{'':<{next_indent}}proxyjump={self.proxyjump!r},\n"
            f"{'':<{next_indent}}controlpath={self.controlpath!r},\n"
            f"{'':<{next_indent}}controlmaster={self.controlmaster!r},\n"
            f"{'':<{0 if no_indent_start else indent}})"
        )
        return msg

    @staticmethod
    def _parse_optional_int(value: typing.Optional[typing.Union[str, int]]) -> typing.Optional[int]:
        """Parse optional integer field in source data.

        :param value: value to process
        :type value: typing.Optional[typing.Union[str, int]]
        :return: integer value if applicable
        :rtype: typing.Optional[int]
        """
        if value is None or isinstance(value, int):
            return value
        return int(value)

    @staticmethod
    def _parse_optional_bool(value: typing.Optional[typing.Union[str, bool]]) -> typing.Optional[bool]:
        """Parse optional bool field in source data.

        :param value: value to process
        :type value: typing.Optional[typing.Union[str, bool]]
        :return: boolean value if applicable
        :rtype: typing.Optional[bool]
        """
        if value is None or isinstance(value, bool):
            return value
        return value.lower() == "yes"

    @classmethod
    def from_ssh_config(
        cls,
        ssh_config: typing.Union[paramiko.config.SSHConfigDict, SSHConfigDictLikeT],
    ) -> SSHConfig:
        """Construct config from Paramiko parsed file.

        :param ssh_config: paramiko parsed ssh config or it reconstruction as a dict
        :type ssh_config: typing.Union[
            paramiko.config.SSHConfigDict, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]
        ]
        :return: SSHConfig with supported values from config
        :rtype: SSHConfig
        """
        return cls(
            hostname=ssh_config["hostname"],  # type: ignore
            port=ssh_config.get("port", None),  # type: ignore
            user=ssh_config.get("user", None),  # type: ignore
            identityfile=ssh_config.get("identityfile", None),  # type: ignore
            proxycommand=ssh_config.get("proxycommand", None),  # type: ignore
            proxyjump=ssh_config.get("proxyjump", None),  # type: ignore
            controlpath=ssh_config.get("controlpath", None),  # type: ignore
            controlmaster=ssh_config.get("controlmaster", None),  # type: ignore
        )

    @property
    def as_dict(self) -> SSHConfigDictLikeT:
        """Dictionary for rebuilding config.

        :return: config as dictionary with only not None values
        :rtype: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]
        """
        result: SSHConfigDictLikeT = {"hostname": self.hostname}
        if self.port is not None:
            result["port"] = self.port
        if self.user is not None:
            result["user"] = self.user
        if self.identityfile is not None:
            result["identityfile"] = self.identityfile
        if self.proxycommand is not None:
            result["proxycommand"] = self.proxycommand
        if self.proxyjump is not None:
            result["proxyjump"] = self.proxyjump
        if self.controlpath is not None:
            result["controlpath"] = self.controlpath
        if self.controlmaster is not None:
            result["controlmaster"] = self.controlmaster
        return result

    def overridden_by(self, ssh_config: SSHConfig) -> SSHConfig:
        """Get copy with values overridden by another config.

        :param ssh_config: Other ssh config
        :type ssh_config: SSHConfig
        :return: Composite from 2 configs with priority of second one
        :rtype: SSHConfig
        """
        cls: typing.Type[SSHConfig] = self.__class__
        return cls(
            hostname=ssh_config.hostname,
            port=ssh_config.port if ssh_config.port is not None else self.port,
            user=ssh_config.user if ssh_config.user is not None else self.user,
            identityfile=ssh_config.identityfile if ssh_config.identityfile is not None else self.identityfile,
            proxycommand=ssh_config.proxycommand if ssh_config.proxycommand is not None else self.proxycommand,
            proxyjump=ssh_config.proxyjump if ssh_config.proxyjump is not None else self.proxyjump,
            controlpath=ssh_config.controlpath if ssh_config.controlpath is not None else self.controlpath,
            controlmaster=ssh_config.controlmaster if ssh_config.controlmaster is not None else self.controlmaster,
        )

    def __eq__(
        self,
        other: typing.Union["SSHConfig", SSHConfigDictLikeT, typing.Any],
    ) -> typing.Union[bool, type(NotImplemented)]:  # type: ignore
        """Equality check.

        :return: other equals self
        :rtype: bool
        """
        if isinstance(other, SSHConfig):
            return all(
                getattr(self, attr) == getattr(other, attr)
                for attr in (
                    "hostname",
                    "user",
                    "port",
                    "identityfile",
                    "proxycommand",
                    "proxyjump",
                    "controlpath",
                    "controlmaster",
                )
            )
        if isinstance(other, dict):
            return self == self.from_ssh_config(other)
        return NotImplemented

    @property
    def hostname(self) -> str:
        """Hostname which config relates.

        :return: remote hostname
        :rtype: str
        """
        return self.__hostname

    @property
    def port(self) -> typing.Optional[int]:
        """Remote port.

        :return: propagated remote port for connection
        :rtype: typing.Optional[int]
        """
        return self.__port

    @property
    def user(self) -> typing.Optional[str]:
        """Remote user.

        :return: propagated username for connection
        :rtype: typing.Optional[str]
        """
        return self.__user

    @property
    def identityfile(self) -> typing.Collection[str]:
        """Connection ssh keys file names.

        :return: list of ssh private keys names
        :rtype: typing.Collection[str]
        """
        if self.__identityfile is None:
            return ()
        if isinstance(self.__identityfile, str):
            return (self.__identityfile,)
        return tuple(self.__identityfile)

    @property
    def proxycommand(self) -> typing.Optional[str]:
        """Proxy command for ssh connection.

        :return: command to be executed for socket creation if applicable
        :rtype: typing.Optional[str]
        """
        return self.__proxycommand

    @property
    def proxyjump(self) -> typing.Optional[str]:
        """Proxy host name.

        :return: proxy hostname if applicable
        :rtype: typing.Optional[str]
        """
        return self.__proxyjump

    @property
    def controlpath(self) -> typing.Optional[str]:
        """Shared socket file path for re-using connection by multiple instances.

        :return: shared socket filesystem path
        :rtype: typing.Optional[str]
        """
        return self.__controlpath

    @property
    def controlmaster(self) -> typing.Optional[bool]:
        """Re-use connection.

        :return: connection should be re-used if possible
        :rtype: typing.Optional[bool]
        """
        return self.__controlmaster


class HostsSSHConfigs(typing.Dict[str, SSHConfig]):
    """Specific dictionary for managing SSHConfig records.

    Instead of creating new record by request just generate default value and return if not exists.
    """

    def __missing__(self, key: str) -> SSHConfig:
        """Missing key handling.

        :param key: nonexistent key
        :type key: str
        :return: generated ssh config for host
        :rtype: SSHConfig
        :raises KeyError: key is not string
        .. versionadded:: 6.0.0
        """
        if isinstance(key, str):
            return SSHConfig(key)
        raise KeyError(f"{key} is not available and not allowed.")  # pragma: no cover


def _parse_paramiko_ssh_config(conf: paramiko.SSHConfig, host: str) -> HostsSSHConfigs:
    """Parse Paramiko ssh config for specific host to dictionary.

    :param conf: Paramiko SSHConfig instance
    :type conf: paramiko.SSHConfig
    :param host: hostname to seek in config
    :type host: str
    :return: parsed dictionary with proxy jump path, if available
    :rtype: HostsSSHConfigs
    """
    # pylint: disable=no-member,unsubscriptable-object,unsupported-assignment-operation
    config = HostsSSHConfigs({host: SSHConfig.from_ssh_config(conf.lookup(host))})
    config.setdefault(config[host].hostname, config[host])

    # Expand proxy info
    proxy_jump: typing.Optional[str] = config[host].proxyjump
    while proxy_jump is not None:
        config[proxy_jump] = SSHConfig.from_ssh_config(conf.lookup(proxy_jump))
        proxy_jump = config[proxy_jump].proxyjump
    return config


def _parse_dict_ssh_config(conf: SSHConfigsDictT, host: str) -> HostsSSHConfigs:
    """Extract required data from pre-parsed ssh config for specific host to dictionary.

    :param conf: pre-parsed dictionary
    :type conf: typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]]
    :param host: hostname to seek in config
    :type host: str
    :return: parsed dictionary with proxy jump path, if available
    :rtype: HostsSSHConfigs
    """
    # pylint: disable=no-member,unsubscriptable-object,unsupported-assignment-operation
    config = HostsSSHConfigs({host: SSHConfig.from_ssh_config(conf.get(host, {"hostname": host}))})
    config.setdefault(config[host].hostname, config[host])

    # Expand proxy info
    proxy_jump: typing.Optional[str] = config[host].proxyjump
    while proxy_jump is not None:
        config[proxy_jump] = SSHConfig.from_ssh_config(conf.get(proxy_jump, {"hostname": proxy_jump}))
        proxy_jump = config[proxy_jump].proxyjump
    return config


def parse_ssh_config(
    ssh_config: typing.Union[str, paramiko.SSHConfig, SSHConfigsDictT, None],
    host: str,
) -> HostsSSHConfigs:
    """Parse ssh config to get real connection parameters.

    :param ssh_config: SSH configuration for connection. Maybe config path, parsed as dict and paramiko parsed.
    :type ssh_config:
        typing.Union[
            str,
            paramiko.SSHConfig,
            typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]],
            None
        ]
    :param host: remote hostname
    :type host: str
    :return: parsed ssh config if available
    :rtype: HostsSSHConfigs
    """
    if isinstance(ssh_config, paramiko.SSHConfig):
        return _parse_paramiko_ssh_config(ssh_config, host)

    if isinstance(ssh_config, dict):
        return _parse_dict_ssh_config(ssh_config, host)

    if isinstance(ssh_config, str):
        ssh_config_path = pathlib.Path(ssh_config).expanduser()
        if ssh_config_path.exists():
            real_config = paramiko.SSHConfig()
            with ssh_config_path.open() as f_config:
                real_config.parse(f_config)
            return _parse_paramiko_ssh_config(real_config, host)

    system_ssh_config: typing.Optional[paramiko.config.SSHConfig] = _parse_ssh_config_file(SSH_CONFIG_FILE_SYSTEM)
    user_ssh_config: typing.Optional[paramiko.config.SSHConfig] = _parse_ssh_config_file(SSH_CONFIG_FILE_USER)

    if system_ssh_config is not None:
        config = _parse_paramiko_ssh_config(system_ssh_config, host)
    else:
        config = HostsSSHConfigs({host: SSHConfig(host)})

    if user_ssh_config is not None:
        # pylint: disable=no-member,unsubscriptable-object,unsupported-assignment-operation
        user_config = _parse_paramiko_ssh_config(user_ssh_config, host)
        for hostname, cfg in user_config.items():
            config[hostname] = config[hostname].overridden_by(cfg)

    return config
