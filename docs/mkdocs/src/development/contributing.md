CONTRIBUTING TO THE PROJECT
===========================

To contribute some code to the project, you will need to submit a GitHub Pull Request (a.k.a PR). Please familiarize yourself with how that works (see [GitHub Pull Requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests))

You should follow the project's [code style](code_style.md), and pre-check your code before submitting a PR. The GitHub project is set up with some [Actions](https://github.com/features/actions) that will check that a PR passes at least the basic tests and complies with the coding style, but it is still recommended to check that for yourself before submitting a PR. 
To run the basic checks (essentially: running the tests, the linter, and the formatter), use the `project.pre-commit` `invoke` command, and address any issues found:

```
$ invoke project.pre-commit
```
