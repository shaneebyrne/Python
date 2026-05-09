"""Dagda IDE - Languages package."""

from .base import (
    LanguageRunner,
    register,
    get_runner,
    from_extension,
    all_names,
    extension_map,
)

# Import runners to trigger @register decorators
from . import runners  # noqa: F401

__all__ = [
    "LanguageRunner",
    "register",
    "get_runner",
    "from_extension",
    "all_names",
    "extension_map",
]
