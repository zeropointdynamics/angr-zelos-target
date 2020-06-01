![PyPI](https://img.shields.io/pypi/v/angr-zelos-target)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/angr-zelos-target)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>

# Zelos Concrete Execution Engine for angr
Provides support for using [*zelos*](https://github.com/zeropointdynamics/zelos) (a python-based binary instrumentation and emulation platform) as a concrete execution engine in `angr` via the `symbion` interface. Symbion provides an interface that enables `angr` to get and set program state from an external execution engine. Conversely, this enables `zelos` to take advantage of the symbolic execution capabilities of `angr`.

# Installation

You first need `angr` with `symbion`. Their documentation recommends installation in a separate virtual environment, as several python packages are customized, including `unicorn`. This is the boilerplate to setup angr in a new virtual environment. Refer to their documentation for more comprehensive instructions.

```bash
$ sudo apt-get install python3-dev libffi-dev build-essential cmake gdb-multiarch python3-venv
$ git clone https://github.com/angr/angr-targets.git

$ python3 -m venv ~/.venv/angr && source ~/.venv/angr/bin/activate
(angr) $ pip install wheel && pip install angr && pip install -e angr-targets
```

Once you have the `angr` environment setup, install the `angr-zelos-target` package within the environment to enable `zelos` as a concrete target:

```st
(angr) $ pip install angr-zelos-target
```

Install the [*zelos emulator*](https://github.com/zeropointdynamics/zelos) in a separate virtual environment, e.g.:

```st
(zelos) $ pip install zelos
```

# Basic Usage

Write your `angr` scripts as you usually would, but specify the `zelos` concrete target when creating the project:

```py
from angr_zelos_target import ZelosConcreteTarget

...

zelos_target = ZelosConcreteTarget()
project = angr.Project(
    filepath,
    concrete_target=zelos_target,
    use_sim_procedures=True,
)
```

Use the `angr.exploration_techniques.Symbion` exploration technique when you want to concretely execution in `zelos`.

Before running your `angr` script, start the `zelos` `zdbserver` on the target binary:

```bash
(zelos) $ python -m zelos.tools.zdbserver FILENAME
```

The `zdbserver` and `angr` scripts can run on the same system, but be sure to run them in separate python environments, as both packages use different versions of the `unicorn` CPU emulator.

# Symbion Tutorial: "Fusing Concrete and Symbolic Execution"

As an example, we have reimplemented the [*symbion tutorial*](http://angr.io/blog/angr_symbion/) using the `zelos` concrete engine. In that tutorial, the goal is to force execution of a binary down the path that prints "*Executing stage 2 fake malware V2*" instead of the default message:

```st
$ ./not_packed_elf64
[+] Parsing malware configuration
[+] Virtual environment detected!
```

The [*not_packed_elf64*](https://github.com/zeropointdynamics/angr-zelos-target/blob/master/src/angr_zelos_target/example/not_packed_elf64) binary is duplicated from the `angr-binaries` repository. The reimplemented tutorial [*example*](https://github.com/zeropointdynamics/angr-zelos-target/blob/master/src/angr_zelos_target/example/__main__.py) script will concretely execute up to the decision point, solve for a value that will ultimately drive excution to the desired path, write that value into zelos, then resume execution in zelos. The basic workflow is to start the binary via the `zelos.zdbserver`, then run the `angr` script that utilizes the `zdbserver`, for instance:

Terminal 1 (zelos):
```st
(zelos) $ python -m zelos.zdbserver not_packed_elf64
```

Terminal 2 (angr):
```st
(angr) $ python3 -m angr_zelos_target.example
```

Terminal 2 Output:
```st
[0] Created angr_zelos project for 'angr_zelos_target/example/not_packed_elf64'
[1] Got to decision point concretely.
[2] Symbolically finding second stage @ 0x400bb6
[3] Executing concretely until exit @ 0x65310d
[4] DONE.
```

Terminal 1 Output:
```st
[main] [SYSCALL] brk ( addr=0x0 ) -> 0x900000a4
[main] [SYSCALL] openat ( dirfd=0xffffff9c, pathname=0xb229170 ("not_packed_elf64"), flags=0x80000 ) -> 18
...
...
[main] [SYSCALL] brk ( addr=0x90022000 ) -> 0x90022000
Breakpoint "bp_400af3"
[StdOut]: 'bytearray(b'[+]Parsing malware configuration\n\n[+] Executing stage 2 fake malware V2\n\n')'
[main] [SYSCALL] write ( fd=0x1, buf=0x90000310 ("[+]Parsing malware configuration [+] Executing stage 2 fake malware V2"), count=0x3a ) -> 3a
[main] [SYSCALL] exit_group ( status=0x0 ) -> void
```

## License
[AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html)
