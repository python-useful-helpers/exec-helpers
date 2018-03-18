exec-helpers
============

.. image:: https://travis-ci.org/penguinolog/exec-helpers.svg?branch=master
    :target: https://travis-ci.org/penguinolog/exec-helpers
.. image:: https://coveralls.io/repos/github/penguinolog/exec-helpers/badge.svg?branch=master
    :target: https://coveralls.io/github/penguinolog/exec-helpers?branch=master
.. image:: https://img.shields.io/pypi/v/exec-helpers.svg
    :target: https://pypi.python.org/pypi/exec-helpers
.. image:: https://img.shields.io/pypi/pyversions/exec-helpers.svg
    :target: https://pypi.python.org/pypi/exec-helpers
.. image:: https://img.shields.io/pypi/status/exec-helpers.svg
    :target: https://pypi.python.org/pypi/exec-helpers
.. image:: https://img.shields.io/github/license/penguinolog/exec-helpers.svg
    :target: https://raw.githubusercontent.com/penguinolog/exec-helpers/master/LICENSE

Execution helpers for simplified usage of subprocess and ssh.
Why another subprocess wrapper and why no clear `paramiko`?

Historically `paramiko` offers good ssh client, but with specific limitations:
you can call command with timeout, but without receiving return code,
or call command and wait for return code, but without timeout processing.

In the most cases, we are need just simple SSH client with comfortable API for calls, calls via SSH proxy and checking return code/stderr.
This library offers this functionality with connection memorizing, deadlock free polling and friendly result objects (with inline decoding of YAML, JSON, binary or just strings).
In addition this library offers the same API for subprocess calls, but with specific limitation: no parallel calls (for protection from race conditions).

Pros:

* STDOUT and STDERR polling during command execution - no deadlocks.
* The same API for subprocess and ssh.
* Connection memorize.
* Free software: Apache license
* Open Source: https://github.com/penguinolog/exec-helpers
* PyPI packaged: https://pypi.python.org/pypi/exec-helpers
* Self-documented code: docstrings with types in comments
* Tested: see bages on top
* Support multiple Python versions:

::

    Python 2.7
    Python 3.4
    Python 3.5
    Python 3.6

This package includes:

* `SSHClient` - historically the first one helper, which used for SSH connections and requires memorization
  due to impossibility of connection close prediction.
  Several API calls for sFTP also presents.

* `SSHAuth` - class for credentials storage. `SSHClient` does not store credentials as-is, but uses `SSHAuth` for it.
  Objects of this class can be copied between ssh connection objects, also it used for `execute_through_host`.

* `Subprocess` - `subprocess.Popen` wrapper with timeouts, polling and almost the same API, as `SSHClient`
  (except specific flags, like `cwd` for subprocess and `get_tty` for ssh).

* `ExecResult` - class for execution results storage.
  Contains exit code, stdout, stderr and getters for decoding as JSON, YAML, string, bytearray and brief strings (up to 7 lines).

* `ExitCodes` - enumerator for standard Linux exit codes. BASH return codes (broduced from signal codes) also available.


Testing
=======
The main test mechanism for the package `exec-helpers` is using `tox`.
Test environments available:

::

    pep8
    py27
    py34
    py35
    py36
    pylint
    pep257

CI systems
==========
For code checking several CI systems is used in parallel:

1. `Travis CI: <https://travis-ci.org/penguinolog/exec-helpers>`_ is used for checking: PEP8, pylint, bandit, installation possibility and unit tests. Also it's publishes coverage on coveralls.

2. `coveralls: <https://coveralls.io/github/penguinolog/exec-helpers>`_ is used for coverage display.
