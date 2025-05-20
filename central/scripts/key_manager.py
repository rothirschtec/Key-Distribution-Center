"""Compatibility wrapper calling :mod:`kdc`.

This script existed in earlier versions of the repository.  It now simply
dispatches to ``kdc.py`` so that existing user workflows continue to work.
"""

from pathlib import Path
from importlib import import_module


def main(argv=None) -> int:
    kdc = import_module("kdc")
    return kdc.main(argv)


if __name__ == "__main__":  # pragma: no cover - direct execution
    raise SystemExit(main())