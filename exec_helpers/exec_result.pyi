import datetime
import logging
import threading
import typing
from exec_helpers import proc_enums

class ExecResult:
    def __init__(
        self,
        cmd: str,
        stdin: typing.Union[typing.AnyStr, bytearray, None] = ...,
        stdout: typing.Optional[typing.Iterable[bytes]] = ...,
        stderr: typing.Optional[typing.Iterable[bytes]] = ...,
        exit_code: typing.Union[int, proc_enums.ExitCodes] = ...,
    ) -> None: ...

    @property
    def lock(self) -> threading.RLock: ...

    @property
    def timestamp(self) -> typing.Optional[datetime.datetime]: ...

    @staticmethod
    def _get_bytearray_from_array(src: typing.Iterable[bytes]) -> bytearray: ...

    @staticmethod
    def _get_str_from_bin(src: bytearray) -> typing.Text: ...

    @classmethod
    def _get_brief(cls, data: typing.Tuple[bytes]) -> typing.Text: ...

    @property
    def cmd(self) -> str: ...

    @property
    def stdin(self) -> typing.Optional[typing.Text]: ...

    @property
    def stdout(self) -> typing.Tuple[bytes]: ...

    @property
    def stderr(self) -> typing.Tuple[bytes]: ...

    def read_stdout(
        self,
        src: typing.Optional[typing.Iterable] = ...,
        log: typing.Optional[logging.Logger] = ...,
        verbose: bool = ...,
    ) -> None: ...

    def read_stderr(
        self,
        src: typing.Optional[typing.Iterable] = ...,
        log: typing.Optional[logging.Logger] = ...,
        verbose: bool = ...,
    ) -> None: ...

    @property
    def stdout_bin(self) -> bytearray: ...

    @property
    def stderr_bin(self) -> bytearray: ...

    @property
    def stdout_str(self) -> typing.Text: ...

    @property
    def stderr_str(self) -> typing.Text: ...

    @property
    def stdout_brief(self) -> typing.Text: ...

    @property
    def stderr_brief(self) -> typing.Text: ...

    @property
    def exit_code(self) -> typing.Union[int, proc_enums.ExitCodes]: ...

    @exit_code.setter
    def exit_code(self, new_val: typing.Union[int, proc_enums.ExitCodes]) -> None: ...

    @property
    def stdout_json(self) -> typing.Any: ...

    @property
    def stdout_yaml(self) -> typing.Any: ...

    def __getitem__(self, item: str) -> typing.Any: ...

    def __repr__(self) -> str: ...

    def __str__(self) -> str: ...

    def __eq__(self, other: typing.Any) -> bool: ...

    def __ne__(self, other: typing.Any) -> bool: ...
