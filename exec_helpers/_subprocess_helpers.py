#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.
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

"""Python subprocess shared code."""

from __future__ import annotations

# Standard Library
import contextlib
import platform
import typing

# External Dependencies
import psutil  # type: ignore

__all__ = ("kill_proc_tree", "subprocess_kw")


# Adopt from:
# https://stackoverflow.com/questions/1230669/subprocess-deleting-child-processes-in-windows
def kill_proc_tree(pid: int, including_parent: bool = True) -> None:  # pragma: no cover
    """Kill process tree.

    :param pid: PID of parent process to kill
    :type pid: int
    :param including_parent: kill also parent process
    :type including_parent: bool
    """

    def safe_stop(proc: psutil.Process, kill: bool = False) -> None:
        """Do not crash on already stopped process.

        :param proc: target process
        :type proc: psutil.Process
        :param kill: use SIGKILL instead of SIGTERM
        :type kill: bool
        """
        with contextlib.suppress(psutil.NoSuchProcess):
            if kill:
                proc.kill()
            proc.terminate()

    parent = psutil.Process(pid)
    children: typing.List[psutil.Process] = parent.children(recursive=True)
    child: psutil.Process
    for child in children:
        safe_stop(child)  # SIGTERM to allow cleanup
    _, alive = psutil.wait_procs(children, timeout=1)
    for child in alive:
        safe_stop(child, kill=True)  # 2nd shot: SIGKILL
    if including_parent:
        safe_stop(parent)  # SIGTERM to allow cleanup
        _, alive = psutil.wait_procs((parent,), timeout=1)
        if alive:
            safe_stop(parent, kill=True)  # 2nd shot: SIGKILL
        parent.wait(5)


# Subprocess extra arguments.
# Flags from:
# https://stackoverflow.com/questions/13243807/popen-waiting-for-child-process-even-when-the-immediate-child-has-terminated
subprocess_kw: typing.Dict[str, typing.Any] = {}
if platform.system() == "Windows":
    subprocess_kw["creationflags"] = 0x00000200
else:  # pragma: no cover
    subprocess_kw["start_new_session"] = True
