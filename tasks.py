# Copyright 2021-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Invoke tasks
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import os

from invoke import task, call, Collection
from invoke.exceptions import Exit, UnexpectedExit


# -----------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))

ns = Collection()


# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
build_tasks = Collection()
ns.add_collection(build_tasks, name="build")


# -----------------------------------------------------------------------------
@task
def build(ctx, install=False):
    if install:
        ctx.run('python -m pip install .[build]')

    ctx.run("python -m build")


# -----------------------------------------------------------------------------
@task
def release_build(ctx):
    build(ctx, install=True)


# -----------------------------------------------------------------------------
@task
def mkdocs(ctx):
    ctx.run("mkdocs build -f docs/mkdocs/mkdocs.yml")


# -----------------------------------------------------------------------------
build_tasks.add_task(build, default=True)
build_tasks.add_task(release_build, name="release")
build_tasks.add_task(mkdocs, name="mkdocs")


# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------
test_tasks = Collection()
ns.add_collection(test_tasks, name="test")


# -----------------------------------------------------------------------------
@task(incrementable=["verbose"])
def test(ctx, match=None, junit=False, install=False, html=False, verbose=0):
    # Install the package before running the tests
    if install:
        ctx.run("python -m pip install .[test]")

    args = ""
    if junit:
        args += "--junit-xml test-results.xml"
    if match is not None:
        args += f" -k '{match}'"
    if html:
        args += " --html results.html"
    if verbose > 0:
        args += f" -{'v' * verbose}"
    ctx.run(f"python -m pytest {os.path.join(ROOT_DIR, 'tests')} {args}")


# -----------------------------------------------------------------------------
@task
def release_test(ctx):
    test(ctx, install=True)


# -----------------------------------------------------------------------------
test_tasks.add_task(test, default=True)
test_tasks.add_task(release_test, name="release")

# -----------------------------------------------------------------------------
# Project
# -----------------------------------------------------------------------------
project_tasks = Collection()
ns.add_collection(project_tasks, name="project")


# -----------------------------------------------------------------------------
@task
def lint(ctx, disable='C,R', errors_only=False):
    options = []
    if disable:
        options.append(f"--disable={disable}")
    if errors_only:
        options.append("-E")

    if errors_only:
        qualifier = ' (errors only)'
    else:
        qualifier = f' (disabled: {disable})' if disable else ''

    print(f">>> Running the linter{qualifier}...")
    try:
        ctx.run(f"pylint {' '.join(options)} bumble apps examples tasks.py")
        print("The linter is happy. ✅ 😊 🐝")
    except UnexpectedExit as exc:
        print("Please check your code against the linter messages. ❌")
        raise Exit(code=1) from exc


# -----------------------------------------------------------------------------
@task
def format_code(ctx, check=False, diff=False):
    options = []
    if check:
        options.append("--check")
    if diff:
        options.append("--diff")

    print(">>> Running the formatter...")
    try:
        ctx.run(f"black -S {' '.join(options)} .")
    except UnexpectedExit as exc:
        print("Please run 'invoke project.format' or 'black .' to format the code. ❌")
        raise Exit(code=1) from exc


# -----------------------------------------------------------------------------
@task
def check_types(ctx):
    checklist = ["apps", "bumble", "examples", "tests", "tasks.py"]
    try:
        ctx.run(f"mypy {' '.join(checklist)}")
    except UnexpectedExit as exc:
        print("Please check your code against the mypy messages.")
        raise Exit(code=1) from exc


# -----------------------------------------------------------------------------
@task(
    pre=[
        call(format_code, check=True),
        call(lint, errors_only=True),
        call(check_types),
        test,
    ]
)
def pre_commit(_ctx):
    print("All good!")


# -----------------------------------------------------------------------------
project_tasks.add_task(lint)
project_tasks.add_task(format_code, name="format")
project_tasks.add_task(check_types, name="check-types")
project_tasks.add_task(pre_commit)


# -----------------------------------------------------------------------------
# Web
# -----------------------------------------------------------------------------
web_tasks = Collection()
ns.add_collection(web_tasks, name="web")


# -----------------------------------------------------------------------------
@task
def serve(ctx, port=8000):
    """
    Run a simple HTTP server for the examples under the `web` directory.
    """
    import http.server

    address = ("", port)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory="web", **kwargs)

    server = http.server.HTTPServer(address, Handler)
    print(f"Now serving on port {port} 🕸️")
    server.serve_forever()


# -----------------------------------------------------------------------------
web_tasks.add_task(serve)
