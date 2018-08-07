import collections
import logging
import subprocess
import threading
import typing

from exec_helpers import exec_result, api

logger: logging.Logger
devnull: typing.IO

_win: bool
_posix: bool

class SingletonMeta(type):
    _instances: typing.Dict[typing.Type, typing.Any] = ...
    _lock: threading.RLock = ...

    def __call__(cls: SingletonMeta, *args: typing.Tuple, **kwargs: typing.Dict) -> typing.Any: ...

    @classmethod
    def __prepare__(
        mcs: typing.Type[SingletonMeta],
        name: str,
        bases: typing.Iterable[typing.Type],
        **kwargs: typing.Dict
    ) -> collections.OrderedDict: ...


def set_nonblocking_pipe(pipe: typing.Any) -> None: ...

def set_blocking_pipe(pipe: typing.Any) -> None: ...


class Subprocess(api.ExecHelper, metaclass=SingletonMeta):
    def __init__(self, log_mask_re: typing.Optional[str] = ...) -> None: ...

    def _exec_command(
        self,
        command: str,
        interface: subprocess.Popen,
        stdout: typing.Optional[typing.IO],
        stderr: typing.Optional[typing.IO],
        timeout: typing.Union[int, None],
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> exec_result.ExecResult: ...

    @typing.overload  # type: ignore
    def execute_async(
        self,
        command: str,
        stdin: typing.Union[typing.AnyStr, bytearray] = ...,
        open_stdout: bool = ...,
        open_stderr: bool = ...,
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> typing.Tuple[subprocess.Popen, None, None, None]: ...

    @typing.overload
    def execute_async(
        self,
        command: str,
        stdin: None = ...,
        open_stdout: bool = ...,
        open_stderr: bool = ...,
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> typing.Tuple[subprocess.Popen, None, typing.IO, typing.IO]: ...
