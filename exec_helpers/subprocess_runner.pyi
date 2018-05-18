import collections
import logging
import subprocess
import threading
import typing

from exec_helpers import exec_result, _api

logger: logging.Logger
devnull: typing.IO

_win: bool
_posix: bool

class SingletonMeta(type):
    _instances: typing.Dict[typing.Type, typing.Any] = ...
    _lock: threading.RLock = ...

    def __call__(cls, *args, **kwargs): ...

    @classmethod
    def __prepare__(mcs, name: str, bases: typing.Iterable[typing.Type], **kwargs) -> collections.OrderedDict: ...


def set_nonblocking_pipe(pipe: typing.Any) -> None: ...


class Subprocess(_api.ExecHelper, metaclass=SingletonMeta):
    def __init__(
        self,
        log_mask_re: typing.Optional[str]=...
    ) -> None: ...

    def _exec_command(
        self,
        command: str,
        interface: subprocess.Popen,
        stdout: typing.Optional[typing.IO],
        stderr: typing.Optional[typing.IO],
        timeout: typing.Union[int, None],
        verbose: bool=...,
        log_mask_re: typing.Optional[str]=...,
        **kwargs
    ) -> exec_result.ExecResult: ...

    def execute_async(
        self,
        command: str,
        stdin: typing.Union[typing.AnyStr, bytearray, None]=...,
        open_stdout: bool=...,
        open_stderr: bool=...,
        verbose: bool=...,
        log_mask_re: typing.Optional[str]=...,
        **kwargs
    ) -> typing.Tuple[subprocess.Popen, None, typing.Optional[typing.IO], typing.Optional[typing.IO]]: ...
