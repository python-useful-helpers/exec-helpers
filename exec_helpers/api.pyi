import logging
import threading
import typing

from exec_helpers import exec_result, proc_enums

class ExecHelper:
    log_mask_re: typing.Optional[str] = ...

    def __init__(self, logger: logging.Logger, log_mask_re: typing.Optional[str] = ...) -> None: ...

    @property
    def logger(self) -> logging.Logger: ...

    @property
    def lock(self) -> threading.RLock: ...

    def __enter__(self) -> ExecHelper: ...

    def __exit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any) -> None: ...

    def _mask_command(self, cmd: str, log_mask_re: typing.Optional[str] = ...) -> str: ...

    def execute_async(
        self,
        command: str,
        stdin: typing.Union[typing.AnyStr, bytearray, None] = ...,
        open_stdout: bool = ...,
        open_stderr: bool = ...,
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> typing.Tuple[typing.Any, typing.Any, typing.Any, typing.Any]: ...

    def _exec_command(
        self,
        command: str,
        interface: typing.Any,
        stdout: typing.Any,
        stderr: typing.Any,
        timeout: typing.Union[int, None],
        verbose: bool = ...,
        log_mask_re: typing.Optional[str] = ...,
        **kwargs: typing.Dict
    ) -> exec_result.ExecResult: ...

    def execute(
        self,
        command: str,
        verbose: bool = ...,
        timeout: typing.Union[int, None] = ...,
        **kwargs: typing.Type
    ) -> exec_result.ExecResult: ...

    def check_call(
        self,
        command: str,
        verbose: bool = ...,
        timeout: typing.Union[int, None] = ...,
        error_info: typing.Optional[str] = ...,
        expected: typing.Optional[typing.Iterable[typing.Union[int, proc_enums.ExitCodes]]] = ...,
        raise_on_err: bool = ...,
        **kwargs: typing.Type
    ) -> exec_result.ExecResult: ...

    def check_stderr(
        self,
        command: str,
        verbose: bool = ...,
        timeout: typing.Union[int, None] = ...,
        error_info: typing.Optional[str] = ...,
        raise_on_err: bool = ...,
        **kwargs: typing.Dict
    ) -> exec_result.ExecResult: ...
