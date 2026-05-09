"""
Dagda IDE - Syntax Highlighting
Uses pygments for tokenisation, applies colour tags to a tkinter Text widget.
Falls back gracefully if pygments is not installed.
"""

from __future__ import annotations
import tkinter as tk
from typing import TYPE_CHECKING

try:
    from pygments import lex
    from pygments.lexers import get_lexer_by_name, TextLexer
    from pygments.token import (
        Token, Keyword, Name, String, Number, Operator,
        Punctuation, Comment, Generic, Literal, Error,
    )
    HAS_PYGMENTS = True
except ImportError:
    HAS_PYGMENTS = False

from ..theme import SYNTAX, TEXT as TEXT_COLOR, BG


# ── Token → tag name mapping ──────────────────────────────────────────────────
def _build_tag_map():
    if not HAS_PYGMENTS:
        return {}
    return {
        Token.Keyword:                "keyword",
        Token.Keyword.Declaration:    "keyword",
        Token.Keyword.Namespace:      "keyword",
        Token.Keyword.Type:           "keyword",
        Token.Keyword.Constant:       "constant",
        Token.Keyword.Reserved:       "keyword",
        Token.Keyword.Pseudo:         "keyword",

        Token.Name.Builtin:           "builtin",
        Token.Name.Builtin.Pseudo:    "builtin",
        Token.Name.Class:             "class_name",
        Token.Name.Function:          "func_name",
        Token.Name.Decorator:         "decorator",
        Token.Name.Attribute:         "attribute",
        Token.Name.Namespace:         "namespace",
        Token.Name.Exception:         "class_name",
        Token.Name.Tag:               "keyword",

        Token.String:                 "string",
        Token.String.Doc:             "string",
        Token.String.Interpol:        "string_esc",
        Token.String.Escape:          "string_esc",
        Token.String.Char:            "string",
        Token.String.Backtick:        "string",
        Token.String.Single:          "string",
        Token.String.Double:          "string",
        Token.String.Heredoc:         "string",

        Token.Number:                 "number",
        Token.Number.Integer:         "number",
        Token.Number.Float:           "number",
        Token.Number.Hex:             "number",
        Token.Number.Oct:             "number",
        Token.Number.Bin:             "number",

        Token.Operator:               "operator",
        Token.Operator.Word:          "keyword",

        Token.Punctuation:            "punctuation",
        Token.Literal:                "string",

        Token.Comment:                "comment",
        Token.Comment.Single:         "comment",
        Token.Comment.Multiline:      "comment",
        Token.Comment.Special:        "comment",
        Token.Comment.Preproc:        "preprocessor",

        Token.Generic.Heading:        "class_name",
        Token.Generic.Subheading:     "func_name",
        Token.Generic.Emph:           "string",
        Token.Generic.Strong:         "keyword",

        Token.Error:                  "error",
    }

_TAG_MAP = _build_tag_map()


class SyntaxHighlighter:
    """Manages syntax highlighting for a single Text widget."""

    def __init__(self, text_widget: tk.Text):
        self._widget = text_widget
        self._lexer_name = "text"
        self._lexer = None
        self._after_id = None
        self._configure_tags()

    def _configure_tags(self):
        w = self._widget
        w.configure(foreground=TEXT_COLOR, background=BG)
        for tag_name, color in SYNTAX.items():
            w.tag_configure(tag_name, foreground=color)
        # Selection styling
        w.tag_configure("sel", background="#45475a", foreground=TEXT_COLOR)

    def set_language(self, lexer_name: str):
        self._lexer_name = lexer_name
        if HAS_PYGMENTS:
            try:
                self._lexer = get_lexer_by_name(lexer_name, stripall=False)
            except Exception:
                self._lexer = TextLexer()
        self.highlight_all()

    def schedule_highlight(self, delay_ms: int = 300):
        """Debounce: cancel pending highlight and schedule a new one."""
        if self._after_id:
            self._widget.after_cancel(self._after_id)
        self._after_id = self._widget.after(delay_ms, self.highlight_all)

    def highlight_all(self):
        """Re-tokenise and apply tags to the entire document."""
        self._after_id = None
        if not HAS_PYGMENTS or self._lexer is None:
            return

        w = self._widget
        code = w.get("1.0", "end-1c")

        # Remove all syntax tags
        for tag in SYNTAX:
            w.tag_remove(tag, "1.0", "end")

        # Tokenise and apply
        pos = "1.0"
        try:
            for ttype, value in lex(code, self._lexer):
                tag = self._resolve_tag(ttype)
                end_pos = w.index(f"{pos}+{len(value)}c")
                if tag:
                    w.tag_add(tag, pos, end_pos)
                pos = end_pos
        except Exception:
            pass  # Never crash the editor over a highlighting failure

    def _resolve_tag(self, ttype) -> str | None:
        """Walk the token type hierarchy to find the closest tag mapping."""
        t = ttype
        while t:
            tag = _TAG_MAP.get(t)
            if tag:
                return tag
            t = t.parent if hasattr(t, "parent") else None
        return None
