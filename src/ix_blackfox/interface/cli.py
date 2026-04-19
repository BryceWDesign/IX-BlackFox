"""
CLI entrypoint placeholder for IX-BlackFox.

The command surface remains intentionally small until the kernel and task
contracts are established. This file exists now so packaging and script
entrypoints are valid from the beginning.
"""

from __future__ import annotations

from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """
    Run the BlackFox command-line entrypoint.

    Parameters
    ----------
    argv:
        Optional argument sequence reserved for future parsing support.

    Returns
    -------
    int
        Process exit code. Zero indicates a clean no-op invocation.
    """
    _ = argv
    print("IX-BlackFox CLI is initialized. Core runtime modules are not wired yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
