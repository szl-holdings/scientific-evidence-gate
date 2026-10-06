"""Finding the bundled fixtures and schemas, installed or in a source checkout.

The repository keeps its synthetic fixtures in ``fixtures/`` and its JSON
schemas in ``schemas/``, beside ``src/``. An installed wheel carries the same
two directories inside the package, as the data-only subpackages
``science_gate._fixtures`` and ``science_gate._schemas`` (see
``pyproject.toml``). ``demo`` needs the fixtures and ``package`` copies the
schemas, so both must work in either layout. This module is the one place
that knows the two layouts.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Mapping

__all__ = ["BUNDLED", "bundled_dir"]

_PACKAGE_DIR = Path(__file__).resolve().parent

#: Resource name -> (subpackage directory in an installed wheel, directory at the repository root).
BUNDLED: Mapping[str, tuple[str, str]] = MappingProxyType(
    {"fixtures": ("_fixtures", "fixtures"), "schemas": ("_schemas", "schemas")}
)


def _checkout_root() -> Path | None:
    """The repository root when the package runs from ``src/`` of a checkout.

    ``pyproject.toml`` beside ``src/`` is required, so an unrelated directory
    that happens to sit two levels above an installed package is never
    mistaken for the repository.
    """
    root = _PACKAGE_DIR.parent.parent
    if _PACKAGE_DIR.parent.name == "src" and (root / "pyproject.toml").is_file():
        return root
    return None


def bundled_dir(name: str) -> Path | None:
    """The directory holding the bundled ``name`` (``"fixtures"`` or ``"schemas"``), or None.

    The installed location is preferred. None means neither layout has it,
    which callers must report rather than treat as an empty set.
    """
    installed, checkout = BUNDLED[name]
    candidate = _PACKAGE_DIR / installed
    if candidate.is_dir():
        return candidate
    root = _checkout_root()
    if root is not None and (root / checkout).is_dir():
        return root / checkout
    return None
