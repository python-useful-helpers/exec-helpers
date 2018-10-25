#    Copyright 2018 Alexey Stepanov aka penguinolog.
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

__all__ = ("kill_proc_tree", "subprocess_kw")

import platform

# pylint: disable=unused-import
import typing  # noqa: F401

# pylint: enable=unused-import

import psutil  # type: ignore


# Adopt from:
# https://stackoverflow.com/questions/1230669/subprocess-deleting-child-processes-in-windows
def kill_proc_tree(pid: int, including_parent: bool = True) -> None:  # pragma: no cover
    """Kill process tree.

    :param pid: PID of parent process to kill
    :type pid: int
    :param including_parent: kill also parent process
    :type including_parent: bool
    """
    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    for child in children:  # type: psutil.Process
        child.kill()
    _, alive = psutil.wait_procs(children, timeout=5)
    for proc in alive:  # type: psutil.Process
        proc.kill()  # 2nd shot
    if including_parent:
        parent.kill()
        parent.wait(5)


# Subprocess extra arguments.
# Flags from:
# https://stackoverflow.com/questions/13243807/popen-waiting-for-child-process-even-when-the-immediate-child-has-terminated
subprocess_kw = {}  # type: typing.Dict[str, typing.Any]
if "Windows" == platform.system():  # pragma: no cover
    subprocess_kw["creationflags"] = 0x00000200
else:  # pragma: no cover
    subprocess_kw["start_new_session"] = True
