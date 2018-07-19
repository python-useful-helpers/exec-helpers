import collections
import typing

import paramiko  # type: ignore

from exec_helpers import exec_result, ssh_auth, api

CPYTHON: bool = ...


class _MemorizedSSH(type):
    @classmethod
    def __prepare__(
        mcs: typing.Type[_MemorizedSSH],
        name: str,
        bases: typing.Iterable[typing.Type],
        **kwargs: typing.Dict
    ) -> collections.OrderedDict: ...

    def __call__(  # type: ignore
        cls: _MemorizedSSH,
        host: str,
        port: int = ...,
        username: typing.Optional[str] = ...,
        password: typing.Optional[str] = ...,
        private_keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = ...,
        auth: typing.Optional[ssh_auth.SSHAuth] = ...,
        verbose: bool = ...,
    ) -> SSHClientBase: ...

    @classmethod
    def clear_cache(mcs: typing.Type[_MemorizedSSH]) -> None: ...

    @classmethod
    def close_connections(mcs: typing.Type[_MemorizedSSH]) -> None: ...


class SSHClientBase(api.ExecHelper, metaclass=_MemorizedSSH):
    def __hash__(self) -> int: ...

    def __init__(
        self,
        host: str,
        port: int = ...,
        username: typing.Optional[str] = ...,
        password: typing.Optional[str] = ...,
        private_keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = ...,
        auth: typing.Optional[ssh_auth.SSHAuth] = ...,
        verbose: bool = ...,
    ) -> None: ...

    @property
    def auth(self) -> ssh_auth.SSHAuth: ...

    @property
    def hostname(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def is_alive(self) -> bool: ...

    def __repr__(self) -> str: ...

    def __str__(self) -> str: ...

    @property
    def _ssh(self) -> paramiko.SSHClient: ...

    @property
    def _sftp(self) -> paramiko.sftp_client.SFTPClient: ...

    @classmethod
    def close(cls: typing.Union[SSHClientBase, typing.Type[SSHClientBase]]) -> None: ...

    @classmethod
    def _clear_cache(cls) -> None: ...

    def __del__(self) -> None: ...

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None: ...

    @property
    def sudo_mode(self) -> bool: ...

    @sudo_mode.setter
    def sudo_mode(self, mode: bool) -> None: ...

    @property
    def keepalive_mode(self) -> bool: ...

    @keepalive_mode.setter
    def keepalive_mode(self, mode: bool) -> None: ...

    def reconnect(self) -> None: ...

    def sudo(self, enforce: typing.Optional[bool] = ...) -> typing.ContextManager: ...

    def keepalive(self, enforce: bool = ...) -> typing.ContextManager: ...

    def execute_async(
        self,
        command: str,
        stdin: typing.Union[typing.AnyStr, bytearray, None] = ...,
        open_stdout: bool = ...,
        open_stderr: bool = ...,
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> typing.Tuple[
        paramiko.Channel,
        paramiko.ChannelFile,
        typing.Optional[paramiko.ChannelFile],
        typing.Optional[paramiko.ChannelFile],
    ]: ...

    def _exec_command(
        self,
        command: str,
        interface: paramiko.channel.Channel,
        stdout: paramiko.channel.ChannelFile,
        stderr: paramiko.channel.ChannelFile,
        timeout: typing.Union[int, None],
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> exec_result.ExecResult: ...

    def execute_through_host(
        self,
        hostname: str,
        command: str,
        auth: typing.Optional[ssh_auth.SSHAuth] = ...,
        target_port: int = ...,
        verbose: bool = ...,
        timeout: typing.Union[int, None] = ...,
        get_pty: bool = ...,
        **kwargs: typing.Dict
    ) -> exec_result.ExecResult: ...

    @classmethod
    def execute_together(
        cls,
        remotes: typing.Iterable[SSHClientBase],
        command: str,
        timeout: typing.Union[int, None] = ...,
        expected: typing.Optional[typing.Iterable[int]] = ...,
        raise_on_err: bool = ...,
        **kwargs: typing.Dict
    ) -> typing.Dict[typing.Tuple[str, int], exec_result.ExecResult]: ...

    def open(self, path: str, mode: str = ...) -> paramiko.SFTPFile: ...

    def exists(self, path: str) -> bool: ...

    def stat(self, path: str) -> paramiko.sftp_attr.SFTPAttributes: ...

    def utime(self, path: str, times: typing.Optional[typing.Tuple[int, int]] = ...) -> None: ...

    def isfile(self, path: str) -> bool: ...

    def isdir(self, path: str) -> bool: ...
