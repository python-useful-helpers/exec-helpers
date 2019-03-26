#    Copyright 2018 - 2019 Alexey Stepanov aka penguinolog.
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

__all__ = ("kill_proc_tree", "SUBPROCESS_KW")

# Standard Library
import platform
# pylint: disable=unused-import
import typing  # noqa: F401

# External Dependencies
import psutil  # type: ignore

# pylint: enable=unused-import


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
        :param kill: use SIGKILL instead of SIGTERM
        """
        try:
            if kill:
                proc.kill()
            proc.terminate()
        except psutil.NoSuchProcess:
            pass

    parent = psutil.Process(pid)
    children = parent.children(recursive=True)  # type: typing.List[psutil.Process]
    for child in children:  # type: psutil.Process
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
SUBPROCESS_KW = {}  # type: typing.Dict[str, typing.Any]
if "Windows" == platform.system():  # pragma: no cover
    SUBPROCESS_KW["creationflags"] = 0x00000200
else:  # pragma: no cover
    SUBPROCESS_KW["start_new_session"] = True
