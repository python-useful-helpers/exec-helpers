#    Copyright 2018 Alexey Stepanov aka penguinolog.

#    Copyright 2017 Mirantis, Inc.
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

"""Text templates for logging."""

from __future__ import absolute_import
from __future__ import unicode_literals

CMD_EXEC = "Executing command:\n{cmd!s}\n"
CMD_RESULT = "Command exit code '{code!s}':\n{cmd!s}\n"
CMD_UNEXPECTED_EXIT_CODE = (
    "{append}Command '{cmd!s}' returned exit code '{code!s}' "
    "while expected '{expected!s}'\n"
)
CMD_UNEXPECTED_STDERR = (
    "{append}Command '{cmd!s}' STDERR while not expected\n"
    "\texit code: '{code!s}'"
)
CMD_WAIT_ERROR = "Wait for '{cmd!s}' during {timeout!s}s: no return code!"
