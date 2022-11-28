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
import os

from invoke import task, Collection

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))

ns = Collection()

# Building
build_tasks = Collection()
ns.add_collection(build_tasks, name="build")

@task
def build(ctx, install=False):
    if install:
        ctx.run('python -m pip install .[build]')

    ctx.run("python -m build")

build_tasks.add_task(build, default=True)

@task
def release_build(ctx):
    build(ctx, install=True)

build_tasks.add_task(release_build, name="release")

@task
def mkdocs(ctx):
    ctx.run("mkdocs build -f docs/mkdocs/mkdocs.yml")

build_tasks.add_task(mkdocs, name="mkdocs")

# Testing
test_tasks = Collection()
ns.add_collection(test_tasks, name="test")


@task(incrementable=["verbose"])
def test(ctx, filter=None, junit=False, install=False, html=False, verbose=0):
    # Install the package before running the tests
    if install:
        ctx.run("python -m pip install .[test]")

    args = ""
    if junit:
        args += "--junit-xml test-results.xml"
    if filter is not None:
        args += f" -k '{filter}'"
    if html:
        args += " --html results.html"
    if verbose > 0:
        args += f" -{'v' * verbose}"
    ctx.run(f"python -m pytest {os.path.join(ROOT_DIR, 'tests')} {args}")

test_tasks.add_task(test, default=True)

@task
def release_test(ctx):
    test(ctx, install=True)

test_tasks.add_task(release_test, name="release")
