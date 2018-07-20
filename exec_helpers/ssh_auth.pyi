import io
import paramiko  # type: ignore
import typing

class SSHAuth:
    def __init__(
        self,
        username: typing.Optional[str] = ...,
        password: typing.Optional[str] = ...,
        key: typing.Optional[paramiko.RSAKey] = ...,
        keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = ...,
        key_filename: typing.Union[typing.List[str], str, None] = ...,
        passphrase: typing.Optional[str] = ...,
    ) -> None: ...

    @property
    def username(self) -> typing.Optional[str]: ...

    @property
    def public_key(self) -> typing.Optional[str]: ...

    @property
    def key_filename(self) -> typing.Union[typing.List[str], str, None]: ...

    def enter_password(self, tgt: io.StringIO) -> None: ...

    def connect(
        self,
        client: typing.Union[paramiko.SSHClient, paramiko.Transport],
        hostname: typing.Optional[str] = ...,
        port: int = ...,
        log: bool = ...,
    ) -> None: ...

    def __eq__(self, other: typing.Any) -> bool: ...

    def __ne__(self, other: typing.Any) -> bool: ...

    def __deepcopy__(self, memo: typing.Any) -> SSHAuth: ...

    def __copy__(self) -> SSHAuth: ...

    def __repr__(self) -> str: ...

    def __str__(self) -> str: ...
