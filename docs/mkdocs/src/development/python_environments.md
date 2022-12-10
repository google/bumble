PYTHON ENVIRONMENTS
===================

When you don't want to install Bumble in your main/default python environment,
using a virtual environment, where the package and its dependencies can be
installed, isolated from the rest, may be useful.

There are many flavors of python environments and dependency managers.
This page describes a few of the most common ones.


## venv

`venv` is a standard module that is included with python.
Visit the [`venv` documentation](https://docs.python.org/3/library/venv.html) page for details.

## Pyenv

`pyenv` lets you easily switch between multiple versions of Python. It's simple, unobtrusive, and follows the UNIX tradition of single-purpose tools that do one thing well.
Visit the [`pyenv` site](https://github.com/pyenv/pyenv) for instructions on how to install
and use `pyenv`

## Conda

Conda is a convenient package manager and virtual environment.
The file `environment.yml` is a Conda environment file that you can use to create
a new Conda environment. Once created, you can simply activate this environment when
working with Bumble.
Visit the [Conda site](https://docs.conda.io/en/latest/) for instructions on how to install
and use Conda.
A few useful commands:

### Create a new `bumble` Conda environment
```
$ conda env create -f environment.yml
```
This will create a new environment, named `bumble`, which you can then activate with:
```
$ conda activate bumble
```

### Update an existing `bumble` environment
```
$ conda env update -f environment.yml
```
