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

# Working With Bumble As A Module

## Installing

You may choose to install the Bumble module from an online package repository, with a package
manager, or from source.

!!! tip "Python Virtual Environments"
    When you install Bumble, you have the option to install it as part of your default
    python environment, or in a virtual environment, such as a `venv`, `pyenv` or `conda` environment

### venv

`venv` is a standard module that is included with python.
Visit the [`venv` documentation](https://docs.python.org/3/library/venv.html) page for details.

### Pyenv

`pyenv` lets you easily switch between multiple versions of Python. It's simple, unobtrusive, and follows the UNIX tradition of single-purpose tools that do one thing well.  
Visit the [`pyenv` site](https://github.com/pyenv/pyenv) for instructions on how to install
and use `pyenv`

### Conda

Conda is a convenient package manager and virtual environment.
The file `environment.yml` is a Conda environment file that you can use to create
a new Conda environment. Once created, you can simply activate this environment when
working with Bumble.  
Visit the [Conda side](https://docs.conda.io/en/latest/) for instructions on how to install
and use Conda.
A few useful commands:  

#### Create a new `bumble` Conda environment
```
$ conda env create -f environment.yml
```
This will create a new environment, named `bumble`, which you can then activate with:
```
$ conda activate bumble
```

#### Update an existing `bumble` environment
```
$ conda env update -f environment.yml
```

### Install From Source

The instructions for working with virtual Python environments above also apply in this case.

Install with `pip`
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
