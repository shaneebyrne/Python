"""
Dagda IDE - Language Runners
One file per conceptual language, all registered via @register decorator.
"""

from __future__ import annotations
import os
import sys
import subprocess
from typing import Optional, Callable

from .base import LanguageRunner, register


# ── Python ────────────────────────────────────────────────────────────────────
@register
class PythonRunner(LanguageRunner):
    name = "python"
    display_name = "Python"
    extensions = [".py", ".pyw"]
    lexer_name = "python3"
    comment_char = "#"

    def get_run_command(self, filepath: str) -> list[str]:
        return [sys.executable, filepath]

    def get_compile_command(self, filepath: str) -> Optional[list[str]]:
        return None  # Interpreted; compile step = syntax check only


# ── Rust ─────────────────────────────────────────────────────────────────────
@register
class RustRunner(LanguageRunner):
    name = "rust"
    display_name = "Rust"
    extensions = [".rs"]
    lexer_name = "rust"
    comment_char = "//"

    def get_compile_command(self, filepath: str) -> list[str]:
        outdir = os.path.dirname(filepath)
        base = os.path.splitext(os.path.basename(filepath))[0]
        out = os.path.join(outdir, base)
        return ["rustc", filepath, "-o", out]

    def get_run_command(self, filepath: str) -> list[str]:
        outdir = os.path.dirname(filepath)
        base = os.path.splitext(os.path.basename(filepath))[0]
        out = os.path.join(outdir, base)
        if sys.platform == "win32":
            out += ".exe"
        return [out]


# ── Java ──────────────────────────────────────────────────────────────────────
@register
class JavaRunner(LanguageRunner):
    name = "java"
    display_name = "Java"
    extensions = [".java"]
    lexer_name = "java"
    comment_char = "//"

    def get_compile_command(self, filepath: str) -> list[str]:
        return ["javac", filepath]

    def get_run_command(self, filepath: str) -> list[str]:
        dirpath = os.path.dirname(filepath)
        base = os.path.splitext(os.path.basename(filepath))[0]
        return ["java", "-cp", dirpath, base]


# ── JavaScript (Node.js) ──────────────────────────────────────────────────────
@register
class JavaScriptRunner(LanguageRunner):
    name = "javascript"
    display_name = "JavaScript (Node)"
    extensions = [".js", ".mjs", ".cjs"]
    lexer_name = "javascript"
    comment_char = "//"
    run_cmd = ["node", "{file}"]


# ── TypeScript ────────────────────────────────────────────────────────────────
@register
class TypeScriptRunner(LanguageRunner):
    name = "typescript"
    display_name = "TypeScript"
    extensions = [".ts"]
    lexer_name = "typescript"
    comment_char = "//"
    compile_cmd = ["tsc", "{file}"]

    def get_run_command(self, filepath: str) -> list[str]:
        js = os.path.splitext(filepath)[0] + ".js"
        return ["node", js]


# ── Ruby ──────────────────────────────────────────────────────────────────────
@register
class RubyRunner(LanguageRunner):
    name = "ruby"
    display_name = "Ruby"
    extensions = [".rb"]
    lexer_name = "ruby"
    comment_char = "#"
    run_cmd = ["ruby", "{file}"]


# ── PowerShell ────────────────────────────────────────────────────────────────
@register
class PowerShellRunner(LanguageRunner):
    name = "powershell"
    display_name = "PowerShell"
    extensions = [".ps1", ".psm1", ".psd1"]
    lexer_name = "powershell"
    comment_char = "#"

    def get_run_command(self, filepath: str) -> list[str]:
        if sys.platform == "win32":
            return [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", filepath
            ]
        else:
            return ["pwsh", "-NoProfile", "-File", filepath]


# ── Bash ──────────────────────────────────────────────────────────────────────
@register
class BashRunner(LanguageRunner):
    name = "bash"
    display_name = "Bash"
    extensions = [".sh"]
    lexer_name = "bash"
    comment_char = "#"

    def get_run_command(self, filepath: str) -> list[str]:
        if sys.platform == "win32":
            return ["bash", filepath]  # WSL or Git Bash
        return ["bash", filepath]


# ── Batch ─────────────────────────────────────────────────────────────────────
@register
class BatchRunner(LanguageRunner):
    name = "batch"
    display_name = "Batch (CMD)"
    extensions = [".bat", ".cmd"]
    lexer_name = "batch"
    comment_char = "REM"

    def get_run_command(self, filepath: str) -> list[str]:
        return ["cmd.exe", "/c", filepath]


# ── C ─────────────────────────────────────────────────────────────────────────
@register
class CRunner(LanguageRunner):
    name = "c"
    display_name = "C"
    extensions = [".c", ".h"]
    lexer_name = "c"
    comment_char = "//"

    def get_compile_command(self, filepath: str) -> list[str]:
        out = os.path.splitext(filepath)[0]
        if sys.platform == "win32":
            out += ".exe"
        return ["gcc", filepath, "-o", out]

    def get_run_command(self, filepath: str) -> list[str]:
        out = os.path.splitext(filepath)[0]
        if sys.platform == "win32":
            out += ".exe"
        return [out]


# ── C++ ───────────────────────────────────────────────────────────────────────
@register
class CppRunner(LanguageRunner):
    name = "cpp"
    display_name = "C++"
    extensions = [".cpp", ".cc", ".cxx", ".hpp"]
    lexer_name = "cpp"
    comment_char = "//"

    def get_compile_command(self, filepath: str) -> list[str]:
        out = os.path.splitext(filepath)[0]
        if sys.platform == "win32":
            out += ".exe"
        return ["g++", "-std=c++17", filepath, "-o", out]

    def get_run_command(self, filepath: str) -> list[str]:
        out = os.path.splitext(filepath)[0]
        if sys.platform == "win32":
            out += ".exe"
        return [out]


# ── Go ────────────────────────────────────────────────────────────────────────
@register
class GoRunner(LanguageRunner):
    name = "go"
    display_name = "Go"
    extensions = [".go"]
    lexer_name = "go"
    comment_char = "//"
    run_cmd = ["go", "run", "{file}"]


# ── Lua ───────────────────────────────────────────────────────────────────────
@register
class LuaRunner(LanguageRunner):
    name = "lua"
    display_name = "Lua"
    extensions = [".lua"]
    lexer_name = "lua"
    comment_char = "--"
    run_cmd = ["lua", "{file}"]


# ── Perl ──────────────────────────────────────────────────────────────────────
@register
class PerlRunner(LanguageRunner):
    name = "perl"
    display_name = "Perl"
    extensions = [".pl", ".pm"]
    lexer_name = "perl"
    comment_char = "#"
    run_cmd = ["perl", "{file}"]


# ── PHP ───────────────────────────────────────────────────────────────────────
@register
class PHPRunner(LanguageRunner):
    name = "php"
    display_name = "PHP"
    extensions = [".php"]
    lexer_name = "php"
    comment_char = "//"
    run_cmd = ["php", "{file}"]


# ── Swift ─────────────────────────────────────────────────────────────────────
@register
class SwiftRunner(LanguageRunner):
    name = "swift"
    display_name = "Swift"
    extensions = [".swift"]
    lexer_name = "swift"
    comment_char = "//"
    run_cmd = ["swift", "{file}"]


# ── Kotlin ────────────────────────────────────────────────────────────────────
@register
class KotlinRunner(LanguageRunner):
    name = "kotlin"
    display_name = "Kotlin"
    extensions = [".kt"]
    lexer_name = "kotlin"
    comment_char = "//"

    def get_compile_command(self, filepath: str) -> list[str]:
        out = os.path.splitext(filepath)[0] + ".jar"
        return ["kotlinc", filepath, "-include-runtime", "-d", out]

    def get_run_command(self, filepath: str) -> list[str]:
        jar = os.path.splitext(filepath)[0] + ".jar"
        return ["java", "-jar", jar]


# ── Plain text / Markdown ─────────────────────────────────────────────────────
@register
class PlainTextRunner(LanguageRunner):
    name = "text"
    display_name = "Plain Text"
    extensions = [".txt", ".text"]
    lexer_name = "text"
    comment_char = ""

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("Plain text cannot be run.")


@register
class MarkdownRunner(LanguageRunner):
    name = "markdown"
    display_name = "Markdown"
    extensions = [".md", ".markdown"]
    lexer_name = "markdown"
    comment_char = ""

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("Markdown cannot be run directly.")


# ── JSON / YAML / TOML ───────────────────────────────────────────────────────
@register
class JsonRunner(LanguageRunner):
    name = "json"
    display_name = "JSON"
    extensions = [".json", ".jsonc"]
    lexer_name = "json"
    comment_char = ""

    def get_run_command(self, filepath: str) -> list[str]:
        return [sys.executable, "-c",
                f"import json, sys; json.load(open(r'{filepath}')); print('Valid JSON')"]


@register
class YamlRunner(LanguageRunner):
    name = "yaml"
    display_name = "YAML"
    extensions = [".yaml", ".yml"]
    lexer_name = "yaml"
    comment_char = "#"

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("YAML cannot be run.")


@register
class TomlRunner(LanguageRunner):
    name = "toml"
    display_name = "TOML"
    extensions = [".toml"]
    lexer_name = "toml"
    comment_char = "#"

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("TOML cannot be run.")


# ── SQL ───────────────────────────────────────────────────────────────────────
@register
class SqlRunner(LanguageRunner):
    name = "sql"
    display_name = "SQL"
    extensions = [".sql"]
    lexer_name = "sql"
    comment_char = "--"

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("SQL requires a database connection.")


# ── HTML / CSS ────────────────────────────────────────────────────────────────
@register
class HtmlRunner(LanguageRunner):
    name = "html"
    display_name = "HTML"
    extensions = [".html", ".htm"]
    lexer_name = "html"
    comment_char = "<!--"

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("Open HTML in a browser.")


@register
class CssRunner(LanguageRunner):
    name = "css"
    display_name = "CSS"
    extensions = [".css"]
    lexer_name = "css"
    comment_char = "/*"

    def get_run_command(self, filepath: str) -> list[str]:
        raise NotImplementedError("CSS cannot be run standalone.")
