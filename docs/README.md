Bumble Documentation
====================

The documentation consists of a collection of markdown text files, with the root of the file
hierarchy at `docs/mkdocs/src`, starting with `docs/mkdocs/src/index.md`.
You can read the documentation as text, with any text viewer or your favorite markdown viewer,
or generate a static HTML "site" using `mkdocs`, which you can then open with any browser.

# Static HTML With MkDocs

[MkDocs](https://www.mkdocs.org/) is used to generate a static HTML documentation site.
The `mkdocs` directory contains all the data (actual documentation) and metadata (configuration) for the site.
`mkdocs/requirements.txt` includes the list of Python packages needed to build the site.
`mkdocs/mkdocs.yml` contains the site configuration.
`mkdocs/src/` is the directory where the actual documentation text, in markdown format, is located.

To build, from the project's root directory:
```
$ mkdocs build -f docs/mkdocs/mkdocs.yml
```

You can then open `docs/mkdocs/site/index.html` with any web browser.
