"""TODO(skarnataki): DO NOT SUBMIT without one-line documentation for dummy_file.

TODO(skarnataki): DO NOT SUBMIT without a detailed description of dummy_file.
"""

from collections.abc import Sequence

from absl import app


def main(argv: Sequence[str]) -> None:
  if len(argv) > 1:
    raise app.UsageError("Too many command-line arguments.")


if __name__ == "__main__":
  app.run(main)
