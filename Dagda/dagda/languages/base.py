"""
Dagda IDE - Language Base
Abstract base class and language registry for all supported languages.
"""

from __future__ import annotations
import subprocess
import sys
import os
import threading
import queue
from abc import ABC, abstractmethod
from typing import Optional, Callable


class LanguageRunner(ABC):
    """Abstract base for every language backend."""

    name: str = "Unknown"
    display_name: str = "Unknown"
    extensions: list[str] = []
    lexer_name: str = "text"          # pygments lexer alias
    comment_char: str = "#"

    # Subclasses set these to indicate what's needed
    run_cmd: Optional[list[str]] = None    # e.g. ["python", "{file}"]
    compile_cmd: Optional[list[str]] = None

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._thread:  Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── Override in subclasses for custom logic ───────────────────────────────
    def get_run_command(self, filepath: str) -> list[str]:
        if self.run_cmd:
            return [c.format(file=filepath) for c in self.run_cmd]
        raise NotImplementedError(f"{self.name} has no run command defined.")

    def get_compile_command(self, filepath: str) -> Optional[list[str]]:
        if self.compile_cmd:
            return [c.format(file=filepath) for c in self.compile_cmd]
        return None

    def execute(
        self,
        filepath: str,
        output_cb: Callable[[str, str], None],  # (text, tag)
        done_cb:   Callable[[int], None],
        cwd: Optional[str] = None,
    ) -> None:
        """Run the file in a background thread, streaming output via output_cb."""
        self._stop_event.clear()

        def _run():
            compile_cmd = self.get_compile_command(filepath)
            if compile_cmd:
                output_cb(f"[Dagda] Compiling: {' '.join(compile_cmd)}\n", "info")
                ok = self._run_cmd(compile_cmd, output_cb, cwd)
                if not ok:
                    output_cb("[Dagda] Compilation failed — aborting.\n", "error")
                    done_cb(1)
                    return
                output_cb("[Dagda] Compilation succeeded.\n", "success")

            run_cmd = self.get_run_command(filepath)
            output_cb(f"[Dagda] Running: {' '.join(run_cmd)}\n", "info")
            rc = self._run_cmd_streaming(run_cmd, output_cb, cwd)
            done_cb(rc)

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self):
        """Kill any running process."""
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            try:
                self._process.kill()
            except Exception:
                pass

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _run_cmd(
        self,
        cmd: list[str],
        output_cb: Callable[[str, str], None],
        cwd: Optional[str],
    ) -> bool:
        """Run a command to completion, capturing output. Returns True on success."""
        try:
            flags = 0
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                cmd, capture_output=True, text=True, cwd=cwd,
                creationflags=flags
            )
            if result.stdout:
                output_cb(result.stdout, "stdout")
            if result.stderr:
                output_cb(result.stderr, "stderr")
            return result.returncode == 0
        except FileNotFoundError as e:
            output_cb(f"[Dagda] Command not found: {cmd[0]}\n  {e}\n", "error")
            return False
        except Exception as e:
            output_cb(f"[Dagda] Error: {e}\n", "error")
            return False

    def _run_cmd_streaming(
        self,
        cmd: list[str],
        output_cb: Callable[[str, str], None],
        cwd: Optional[str],
    ) -> int:
        """Run a command and stream output line-by-line. Returns exit code."""
        try:
            flags = 0
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                creationflags=flags,
            )

            q: queue.Queue[tuple[str, str]] = queue.Queue()

            def _reader(stream, tag):
                for line in stream:
                    if self._stop_event.is_set():
                        break
                    q.put((line, tag))
                q.put(("__DONE__", tag))

            t1 = threading.Thread(target=_reader, args=(self._process.stdout, "stdout"), daemon=True)
            t2 = threading.Thread(target=_reader, args=(self._process.stderr, "stderr"), daemon=True)
            t1.start(); t2.start()

            done_count = 0
            while done_count < 2:
                try:
                    text, tag = q.get(timeout=0.1)
                    if text == "__DONE__":
                        done_count += 1
                    else:
                        output_cb(text, tag)
                except queue.Empty:
                    if self._stop_event.is_set():
                        break

            self._process.wait()
            return self._process.returncode

        except FileNotFoundError:
            output_cb(f"[Dagda] '{cmd[0]}' not found. Is it installed and on PATH?\n", "error")
            return 127
        except Exception as e:
            output_cb(f"[Dagda] Execution error: {e}\n", "error")
            return 1

    @staticmethod
    def check_available(cmd: str) -> bool:
        """Return True if a command is on PATH."""
        try:
            flags = 0
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW
            subprocess.run(
                [cmd, "--version"], capture_output=True, creationflags=flags
            )
            return True
        except FileNotFoundError:
            return False


# ── Language registry ─────────────────────────────────────────────────────────

_registry: dict[str, type[LanguageRunner]] = {}
_ext_map:  dict[str, str] = {}   # ".py" → "python"


def register(cls: type[LanguageRunner]) -> type[LanguageRunner]:
    """Decorator that registers a LanguageRunner subclass."""
    _registry[cls.name] = cls
    for ext in cls.extensions:
        _ext_map[ext.lower()] = cls.name
    return cls


def get_runner(name: str) -> Optional[LanguageRunner]:
    cls = _registry.get(name)
    return cls() if cls else None


def from_extension(ext: str) -> Optional[LanguageRunner]:
    name = _ext_map.get(ext.lower())
    return get_runner(name) if name else None


def all_names() -> list[str]:
    return sorted(_registry.keys())


def extension_map() -> dict[str, str]:
    return dict(_ext_map)
