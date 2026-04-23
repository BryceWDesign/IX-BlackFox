"""
Interface subsystem.

BlackFox exposes interfaces in stages: command line first, then
programmatic APIs, then richer operator surfaces once the kernel is
stable, governed, and testable.
"""

from ix_blackfox.interface.cli import main

__all__ = [
    "main",
]
