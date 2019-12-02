"""SSH client shared helpers."""

# Standard Library
import functools
import pathlib
import typing

# External Dependencies
import paramiko  # type: ignore

if typing.TYPE_CHECKING:
    # noinspection PyPackageRequirements
    import logwrap


# Parse default SSHConfig if available
SSH_CONFIG_FILE_SYSTEM = pathlib.Path("/etc/ssh/ssh_config")
SSH_CONFIG_FILE_USER = pathlib.Path("~/.ssh/config").expanduser()


@functools.lru_cache(maxsize=128, typed=True)
def _parse_ssh_config_file(file_path: pathlib.Path) -> typing.Optional[paramiko.SSHConfig]:
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


cdef class SSHConfig:
    """Parsed SSH Config for creation connection."""

    cdef:
        readonly str hostname
        readonly user
        readonly port
        _identityfile
        readonly proxycommand
        readonly proxyjump
        readonly controlpath
        readonly controlmaster

    def __init__(
        self,
        str hostname: str,
        port: typing.Optional[typing.Union[str, int]] = None,
        user: typing.Optional[str] = None,
        identityfile: typing.Optional[typing.List[str]] = None,
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
        :type identityfile: typing.Optional[typing.List[str]]
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
        self.hostname = hostname  # type: str
        self.port = self._parse_optional_int(port)  # type: typing.Optional[int]
        if isinstance(self.port, int) and not 0 < self.port < 65535:
            raise ValueError(f"port {self.port} if not in range [1, 65535], which is incorrect.")

        self.user = user  # type: typing.Optional[str]
        self._identityfile = identityfile  # type: typing.Optional[typing.List[str]]

        if proxycommand and proxyjump:
            raise ValueError(
                f"ProxyCommand ({proxycommand}) and ProxyJump ({proxyjump}) is mixed for single connection!"
            )

        self.proxycommand = proxycommand  # type: typing.Optional[str]
        self.proxyjump = proxyjump  # type: typing.Optional[str]
        self.controlpath = controlpath  # type: typing.Optional[str]
        self.controlmaster = self._parse_optional_bool(controlmaster)  # type: typing.Optional[bool]

    def __hash__(self) -> int:  # pragma: no cover
        """Hash for caching possibility."""
        return hash(
            (
                self.__class__,
                self.hostname,
                self.port,
                self.user,
                self._identityfile if self._identityfile is None else tuple(self._identityfile),
                self.proxycommand,
                self.proxyjump,
                self.controlpath,
                self.controlmaster,
            )
        )

    def __repr__(self) -> str:
        """Debug support."""
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

    cpdef str __pretty_repr__(self, log_wrap: "logwrap.PrettyRepr", indent: int = 0, no_indent_start: bool = False):
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
        cdef unsigned long next_indent = log_wrap.next_indent(indent)
        return (
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

    @staticmethod
    def _parse_optional_int(value: typing.Optional[typing.Union[str, int]]) -> typing.Optional[int]:
        if value is None or isinstance(value, int):
            return value
        return int(value)

    @staticmethod
    def _parse_optional_bool(value: typing.Optional[typing.Union[str, bool]]) -> typing.Optional[bool]:
        if value is None or isinstance(value, bool):
            return value
        return value.lower() == "yes"

    @classmethod
    def from_ssh_config(
        cls,
        ssh_config: typing.Union[
            paramiko.config.SSHConfigDict, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]
        ],
    ) -> "SSHConfig":
        """Construct config from Paramiko parsed file.

        :param ssh_config: paramiko parsed ssh config or it reconstruction as a dict,
        :return: SSHConfig with supported values from config
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
    def as_dict(self) -> typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]:
        """Dictionary for rebuilding config.

        :return: config as dictionary with only not None values
        :rtype: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]
        """
        result = {"hostname": self.hostname}  # type: typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]
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

    cpdef SSHConfig overridden_by(self, SSHConfig ssh_config: "SSHConfig"):
        """Get copy with values overridden by another config.

        :param ssh_config: Other ssh config
        :type ssh_config: SSHConfig
        :return: Composite from 2 configs with priority of second one
        :rtype: SSHConfig
        """
        cls = self.__class__  # type: typing.Type["SSHConfig"]
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
        other: typing.Union[
            "SSHConfig", typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]], typing.Any
        ],
    ) -> typing.Union[bool, type(NotImplemented)]:  # type: ignore
        """Equality check."""
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
            return self.as_dict == other
        return NotImplemented

    @property
    def identityfile(self) -> typing.Optional[typing.List[str]]:
        """Connection ssh keys file names."""
        if self._identityfile is None:
            return None
        return self._identityfile.copy()


class HostsSSHConfigs(dict):
    """Specific dictionary for managing SSHConfig records.

    Instead of creating new record by request just generate default value and return if not exists.
    """

    def __missing__(self, str key: str) -> SSHConfig:
        """Missing key handling.

        :param key: nonexistent key
        :type key: str
        :return: generated ssh config for host
        :rtype: SSHConfig
        :raises KeyError: key is not string
        .. versionadded:: 6.0.0
        """
        return SSHConfig(key)


def  _parse_paramiko_ssh_config(conf: paramiko.SSHConfig, str host: str) -> HostsSSHConfigs:
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
    proxy_jump = config[host].proxyjump  # type: typing.Optional[str]
    while proxy_jump is not None:
        config[proxy_jump] = SSHConfig.from_ssh_config(conf.lookup(proxy_jump))
        proxy_jump = config[proxy_jump].proxyjump
    return config


def _parse_dict_ssh_config(
    conf: typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]], str host: str
) -> HostsSSHConfigs:
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
    proxy_jump = config[host].proxyjump  # type: typing.Optional[str]
    while proxy_jump is not None:
        config[proxy_jump] = SSHConfig.from_ssh_config(conf.get(proxy_jump, {"hostname": proxy_jump}))
        proxy_jump = config[proxy_jump].proxyjump
    return config


def parse_ssh_config(
    ssh_config: typing.Union[
        str,
        paramiko.SSHConfig,
        typing.Dict[str, typing.Dict[str, typing.Union[str, int, bool, typing.List[str]]]],
        None,
    ],
    str host: str,
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

    system_ssh_config = _parse_ssh_config_file(SSH_CONFIG_FILE_SYSTEM)  # type: typing.Optional[paramiko.config.SSHConfig]
    user_ssh_config = _parse_ssh_config_file(SSH_CONFIG_FILE_USER)  # type: typing.Optional[paramiko.config.SSHConfig]

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
