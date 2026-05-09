"""Dagda IDE - GUI package."""

from .terminal  import TerminalPanel
from .statusbar import StatusBar
from .toolbar   import Toolbar
from .tabs      import TabManager
from .menubar   import build_menubar

__all__ = [
    "TerminalPanel",
    "StatusBar",
    "Toolbar",
    "TabManager",
    "build_menubar",
]
