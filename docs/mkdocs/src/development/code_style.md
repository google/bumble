CODE STYLE
==========

The Python code style used in this project follows the [Black code style](https://black.readthedocs.io/en/stable/the_black_code_style/current_style.html). 

# Formatting

For now, we are configuring the `black` formatter with the option to leave quotes unchanged.
The preferred quote style is single quotes, which isn't a configurable option for `Black`, so we are not enforcing it. This may change in the future. 

## Ignoring Commit for Git Blame

The adoption of `Black` as a formatter came in late in the project, with already a large code base. As a result, a large number of files were changed in a single commit, which gets in the way of tracing authorship with `git blame`. The file `git-blame-ignore-revs` contains the commit hash of when that mass-formatting event occurred, which you can use to skip it in a `git blame` analysis:

!!! example "Ignoring a commit with `git blame`"
    ```
    $ git blame --ignore-revs-file .git-blame-ignore-revs
    ```

# Linting

The project includes a `pylint` configuration (see the `pyproject.toml` file for details). 
The `pre-commit` checks only enforce that there are no errors. But we strongly recommend that you run the linter with warnings enabled at least, and possibly the "Refactor" ('R') and "Convention" ('C') categories as well. 
To run the linter, use the `project.lint` invoke command. 

!!! example "Running the linter with default options"
    With the default settings, Errors and Warnings are enabled, but Refactor and Convention categories are not.
    ```
    $ invoke project.lint
    ```

!!! example "Running the linter with all categories"
    ```
    $ invoke project.lint --disable=""
    ```

# Editor/IDE Integration

## Visual Studio Code

The project includes a `.vscode/settings.json` file that specifies the `black` formatter and enables an editor ruler at 88 columns. 
You may want to configure your own environment to "format on save" with `black` if you find that useful. We are not making that choice at the workspace level.

