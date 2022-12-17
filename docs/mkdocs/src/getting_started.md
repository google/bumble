GETTING STARTED WITH BUMBLE
===========================

# Prerequisites

You need Python 3.8 or above. Python >= 3.9 is recommended, but 3.8 should be sufficient if
necessary (there may be some optional functionality that will not work on some platforms with
python 3.8).
Visit the [Python site](https://www.python.org/) for instructions on how to install Python
for your platform.
Throughout the documentation, when shell commands are shown, it is assumed that you can
invoke Python as
```
$ python
```
If invoking python is different on your platform (it may be `python3` for example, or just `py` or `py.exe`),
adjust accordingly.

You may be simply using Bumble as a module for your own application or as a dependency to your own
module, or you may be working on modifying or contributing to the Bumble module or example code
itself.

# Using Bumble As A Python Module

## Installing

You may choose to install the Bumble module from an online package repository, with a package
manager, or from source.

!!! tip "Python Virtual Environments"
    When you install Bumble, you have the option to install it as part of your default
    python environment, or in a virtual environment, such as a `venv`, `pyenv` or `conda` environment.
    See the [Python Environments page](development/python_environments.md) page for details.

### Install From Source

Install with `pip`. Run in a command shell in the directory where you downloaded the source
distribution
```
$ python -m pip install -e .
```

### Install from GitHub

You can install directly from GitHub without first downloading the repo.

Install the latest commit from the main branch with `pip`:
```
$ python -m pip install git+https://github.com/google/bumble.git
```

You can specify a specific tag.

Install tag `v0.0.1` with `pip`:
```
$ python -m pip install git+https://github.com/google/bumble.git@v0.0.1
```

You can also specify a specific commit.

Install commit `27c0551` with `pip`:
```
$ python -m pip install git+https://github.com/google/bumble.git@27c0551
```

# Working On The Bumble Code
When you work on the Bumble code itself, and run some of the tests or example apps, or import the
module in your own code, you typically either install the package from source in "development mode" as described above, or you may choose to skip the install phase.

If you plan on contributing to the project, please read the [contributing](development/contributing.md) section.

## Without Installing
If you prefer not to install the package (even in development mode), you can load the module directly from its location in the project.
A simple way to do that is to set your `PYTHONPATH` to
point to the root project directory, where the `bumble` subdirectory is located. You may set
`PYTHONPATH` globally, or locally with each command line execution (on Unix-like systems).

Example with a global `PYTHONPATH`, from a unix shell, when the working directory is the root
directory of the project.

```bash
$ export PYTHONPATH=.
$ python apps/console.py serial:/dev/tty.usbmodem0006839912171
```

or running an example, with the working directory set to the `examples` subdirectory
```bash
$ cd examples
$ export PYTHONPATH=..
$ python run_scanner.py usb:0
```

Or course, `export PYTHONPATH` only needs to be invoked once, not before each app/script execution.

Setting `PYTHONPATH` locally with each command would look something like:
```
$ PYTHONPATH=. python examples/run_advertiser.py examples/device1.json serial:/dev/tty.usbmodem0006839912171
```

# Where To Go Next
Once you've installed or downloaded Bumble, you can either start using some of the
[Bundled apps and tools](apps_and_tools/index.md), or look at the [examples](examples/index.md)
to get a feel for how to use the APIs, and start writing your own applications.

Depending on the use case you're interested in exploring, you may need to use a physical Bluetooth
controller, like a USB dongle or a board with a Bluetooth radio. Visit the [Hardware page](hardware/index.md)
for more information on using a physical radio, and/or the [Transports page](transports/index.md) for more
details on interfacing with either hardware modules or virtual controllers over various transports.
