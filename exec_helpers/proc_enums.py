#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.

#    Copyright 2016 Mirantis, Inc.
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

"""Process enumerators.

Linux signals, Linux & bash return codes.
"""

__all__ = ("SigNum", "ExitCodes", "exit_code_to_enum", "exit_codes_to_enums", "EXPECTED", "INVALID")

# Standard Library
import enum
import sys
import typing


@enum.unique
class SigNum(enum.IntEnum):
    """Signal enumerators."""

    SIGHUP = 1  # Hangup (POSIX).
    SIGINT = 2  # Interrupt (ANSI).
    SIGQUIT = 3  # Quit (POSIX).
    SIGILL = 4  # Illegal instruction (ANSI).
    SIGTRAP = 5  # Trace trap (POSIX).
    SIGABRT = 6  # Abort (ANSI).
    SIGBUS = 7  # BUS error (4.2 BSD).
    SIGFPE = 8  # Floating-point exception (ANSI).
    SIGKILL = 9  # Kill, unblockable (POSIX).
    SIGUSR1 = 10  # User-defined signal 1 (POSIX).
    SIGSEGV = 11  # Segmentation violation (ANSI).
    SIGUSR2 = 12  # User-defined signal 2 (POSIX).
    SIGPIPE = 13  # Broken pipe (POSIX).
    SIGALRM = 14  # Alarm clock (POSIX).
    SIGTERM = 15  # Termination (ANSI).
    SIGSTKFLT = 16  # Stack fault.
    SIGCHLD = 17  # Child status has changed (POSIX).
    SIGCONT = 18  # Continue (POSIX).
    SIGSTOP = 19  # Stop, unblockable (POSIX).
    SIGTSTP = 20  # Keyboard stop (POSIX).
    SIGTTIN = 21  # Background read from tty (POSIX).
    SIGTTOU = 22  # Background write to tty (POSIX).
    SIGURG = 23  # Urgent condition on socket (4.2 BSD).
    SIGXCPU = 24  # CPU limit exceeded (4.2 BSD).
    SIGXFSZ = 25  # File size limit exceeded (4.2 BSD).
    SIGVTALRM = 26  # Virtual alarm clock (4.2 BSD).
    SIGPROF = 27  # Profiling alarm clock (4.2 BSD).
    SIGWINCH = 28  # Window size change (4.3 BSD, Sun).
    SIGPOLL = 29  # Pollable event occurred (System V)
    SIGPWR = 30  # Power failure restart (System V).
    SIGSYS = 31  # Bad system call.

    def __str__(self) -> str:
        """Representation for logs."""
        return "{self.name}<{self.value:d}(0x{self.value:02X})>".format(self=self)  # pragma: no cover


@enum.unique
class ExitCodes(int, enum.Enum):
    """Linux & bash exit codes."""

    EX_OK = 0  # successful termination

    EX_INVALID = 0xDEADBEEF  # uint32 debug value. Impossible for POSIX

    EX_ERROR = 1  # general failure
    EX_BUILTIN = 2  # Misuse of shell builtins (according to Bash)

    EX_USAGE = 64  # command line usage error
    EX_DATAERR = 65  # data format error
    EX_NOINPUT = 66  # cannot open input
    EX_NOUSER = 67  # addressee unknown
    EX_NOHOST = 68  # host name unknown
    EX_UNAVAILABLE = 69  # service unavailable
    EX_SOFTWARE = 70  # internal software error
    EX_OSERR = 71  # system error (e.g., can't fork)
    EX_OSFILE = 72  # critical OS file missing
    EX_CANTCREAT = 73  # can't create (user) output file
    EX_IOERR = 74  # input/output error
    EX_TEMPFAIL = 75  # temp failure; user is invited to retry
    EX_PROTOCOL = 76  # remote error in protocol
    EX_NOPERM = 77  # permission denied
    EX_CONFIG = 78  # configuration error

    EX_NOEXEC = 126  # If a command is found but is not executable
    EX_NOCMD = 127  # If a command is not found

    # Signal exits

    EX_SIGHUP = -SigNum.SIGHUP
    EX_SIGINT = -SigNum.SIGINT
    EX_SIGQUIT = -SigNum.SIGQUIT
    EX_SIGILL = -SigNum.SIGILL
    EX_SIGTRAP = -SigNum.SIGTRAP
    EX_SIGABRT = -SigNum.SIGABRT
    EX_SIGBUS = -SigNum.SIGBUS
    EX_SIGFPE = -SigNum.SIGFPE
    EX_SIGKILL = -SigNum.SIGKILL
    EX_SIGUSR1 = -SigNum.SIGUSR1
    EX_SIGSEGV = -SigNum.SIGSEGV
    EX_SIGUSR2 = -SigNum.SIGUSR2
    EX_SIGPIPE = -SigNum.SIGPIPE
    EX_SIGALRM = -SigNum.SIGALRM
    EX_SIGTERM = -SigNum.SIGTERM
    EX_SIGSTKFLT = -SigNum.SIGSTKFLT
    EX_SIGCHLD = -SigNum.SIGCHLD
    EX_SIGCONT = -SigNum.SIGCONT
    EX_SIGSTOP = -SigNum.SIGSTOP
    EX_SIGTSTP = -SigNum.SIGTSTP
    EX_SIGTTIN = -SigNum.SIGTTIN
    EX_SIGTTOU = -SigNum.SIGTTOU
    EX_SIGURG = -SigNum.SIGURG
    EX_SIGXCPU = -SigNum.SIGXCPU
    EX_SIGXFSZ = -SigNum.SIGXFSZ
    EX_SIGVTALRM = -SigNum.SIGVTALRM
    EX_SIGPROF = -SigNum.SIGPROF
    EX_SIGWINCH = -SigNum.SIGWINCH
    EX_SIGPOLL = -SigNum.SIGPOLL
    EX_SIGPWR = -SigNum.SIGPWR
    EX_SIGSYS = -SigNum.SIGSYS

    # Signal exits shell:
    SH_EX_SIGHUP = 128 + SigNum.SIGHUP
    SH_EX_SIGINT = 128 + SigNum.SIGINT
    SH_EX_SIGQUIT = 128 + SigNum.SIGQUIT
    SH_EX_SIGILL = 128 + SigNum.SIGILL
    SH_EX_SIGTRAP = 128 + SigNum.SIGTRAP
    SH_EX_SIGABRT = 128 + SigNum.SIGABRT
    SH_EX_SIGBUS = 128 + SigNum.SIGBUS
    SH_EX_SIGFPE = 128 + SigNum.SIGFPE
    SH_EX_SIGKILL = 128 + SigNum.SIGKILL
    SH_EX_SIGUSR1 = 128 + SigNum.SIGUSR1
    SH_EX_SIGSEGV = 128 + SigNum.SIGSEGV
    SH_EX_SIGUSR2 = 128 + SigNum.SIGUSR2
    SH_EX_SIGPIPE = 128 + SigNum.SIGPIPE
    SH_EX_SIGALRM = 128 + SigNum.SIGALRM
    SH_EX_SIGTERM = 128 + SigNum.SIGTERM
    SH_EX_SIGSTKFLT = 128 + SigNum.SIGSTKFLT
    SH_EX_SIGCHLD = 128 + SigNum.SIGCHLD
    SH_EX_SIGCONT = 128 + SigNum.SIGCONT
    SH_EX_SIGSTOP = 128 + SigNum.SIGSTOP
    SH_EX_SIGTSTP = 128 + SigNum.SIGTSTP
    SH_EX_SIGTTIN = 128 + SigNum.SIGTTIN
    SH_EX_SIGTTOU = 128 + SigNum.SIGTTOU
    SH_EX_SIGURG = 128 + SigNum.SIGURG
    SH_EX_SIGXCPU = 128 + SigNum.SIGXCPU
    SH_EX_SIGXFSZ = 128 + SigNum.SIGXFSZ
    SH_EX_SIGVTALRM = 128 + SigNum.SIGVTALRM
    SH_EX_SIGPROF = 128 + SigNum.SIGPROF
    SH_EX_SIGWINCH = 128 + SigNum.SIGWINCH
    SH_EX_SIGPOLL = 128 + SigNum.SIGPOLL
    SH_EX_SIGPWR = 128 + SigNum.SIGPWR
    SH_EX_SIGSYS = 128 + SigNum.SIGSYS

    def __str__(self) -> str:
        """Representation for logs."""
        return "{self.name}<{self.value:d}(0x{self.value:02X})>".format(self=self)


EXPECTED = 0 if "win32" == sys.platform else ExitCodes.EX_OK  # type: typing.Union[int, ExitCodes]
INVALID = 0xDEADBEEF if "win32" == sys.platform else ExitCodes.EX_INVALID  # type: typing.Union[int, ExitCodes]


def exit_code_to_enum(code: typing.Union[int, ExitCodes]) -> typing.Union[int, ExitCodes]:  # pragma: no cover
    """Convert exit code to enum if possible.

    :param code: code to convert from
    :returns: enum code if suitable else original code
    """
    if "win32" == sys.platform:
        return int(code)
    if isinstance(code, int) and code in ExitCodes.__members__.values():
        return ExitCodes(code)
    return code


def exit_codes_to_enums(
    codes: typing.Optional[typing.Iterable[typing.Union[int, ExitCodes]]] = None
) -> typing.Tuple[typing.Union[int, ExitCodes], ...]:
    """Convert integer exit codes to enums.

    :param codes: exit codes to process
    :returns: exit codes as enums if suitable
    """
    if codes is None:
        # noinspection PyRedundantParentheses
        return (EXPECTED,)
    return tuple(exit_code_to_enum(code) for code in codes)
