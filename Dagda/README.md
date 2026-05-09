# ⚔ Dagda IDE

> *"The All-Father of Polyglot IDEs"*

Dagda is a lightweight, Python-based code editor and runner named after the Celtic deity — the great, good god who masters all arts. Like its namesake, Dagda is built to handle everything: write, run, and iterate in any language, from a single clean interface.

---

## ✨ Features

| Feature | Detail |
|---------|--------|
| **Multi-language support** | Python, Rust, Java, JavaScript, TypeScript, Ruby, PowerShell, Bash, Batch, C, C++, Go, Lua, Perl, PHP, Swift, Kotlin, JSON, YAML, HTML, CSS, SQL, Markdown |
| **Syntax highlighting** | Token-accurate via `pygments`, Catppuccin Mocha palette |
| **Multi-tab editor** | Open multiple files; tabs show unsaved indicator (●) |
| **Line numbers** | Synchronized gutter; click to select a line |
| **Smart indentation** | Tab → 4 spaces; auto-indent on Enter; backspace un-tabs |
| **Auto-pairs** | Brackets, quotes auto-close |
| **Comment toggle** | `Ctrl+/` comments/uncomments block using language-correct style |
| **Find / Replace** | Full-document search with case-sensitivity toggle |
| **Run panel** | Streamed stdout/stderr with colour-coded tags |
| **Stop button** | Kill the running process at any time |
| **Font scaling** | `Ctrl++/-/0` to resize editor font |
| **Catppuccin Mocha** | Full dark theme throughout — toolbar, tabs, terminal, dialogs |

---

## 🚀 Quick Start

### Windows
```
run.bat
```

### Linux / macOS
```bash
chmod +x run.sh
./run.sh
```

### Manual
```bash
python main.py
```

---

## 🗂 Project Structure

```
dagda/
├── main.py                    # Entry point
├── run.bat                    # Windows launcher
├── run.sh                     # Linux/macOS launcher
├── README.md
├── DEPENDENCIES.md            # Runtime requirements per language
├── SBOM.md                    # Software Bill of Materials
│
└── dagda/                     # Python package
    ├── app.py                 # Main application controller
    ├── theme.py               # Catppuccin Mocha palette + ttk styles
    ├── file_manager.py        # File I/O, extension→language detection
    │
    ├── editor/
    │   ├── editor_widget.py   # Text editor (gutter, indentation, pairs)
    │   └── syntax.py          # pygments-based syntax highlighting
    │
    ├── gui/
    │   ├── menubar.py         # Application menu bar
    │   ├── toolbar.py         # Run/Stop + language selector
    │   ├── tabs.py            # Tab manager (ttk.Notebook wrapper)
    │   ├── terminal.py        # Output panel (streamed, colour-tagged)
    │   └── statusbar.py       # Language / cursor / modified indicator
    │
    └── languages/
        ├── base.py            # LanguageRunner ABC + registry
        └── runners.py         # All language implementations
```

---

## ⌨ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New tab |
| `Ctrl+O` | Open file |
| `Ctrl+S` | Save |
| `Ctrl+Shift+S` | Save As |
| `Ctrl+W` | Close tab |
| `Ctrl+Q` | Quit |
| `F5` | Run file |
| `F6` | Stop process |
| `Ctrl+Z` | Undo |
| `Ctrl+Y` | Redo |
| `Ctrl+F` | Find / Replace |
| `Ctrl+/` | Toggle comment |
| `Ctrl+D` | Duplicate line |
| `Ctrl+A` | Select all |
| `Ctrl++` | Font larger |
| `Ctrl+-` | Font smaller |
| `Ctrl+0` | Font reset |
| `Ctrl+\`` | Toggle terminal panel |

---

## 🔌 Adding a Language

1. Open `dagda/languages/runners.py`
2. Subclass `LanguageRunner` and decorate with `@register`:

```python
@register
class ZigRunner(LanguageRunner):
    name         = "zig"
    display_name = "Zig"
    extensions   = [".zig"]
    lexer_name   = "zig"
    comment_char = "//"
    run_cmd      = ["zig", "run", "{file}"]
```

That's it. Dagda will automatically add it to the Language menu and toolbar combobox.

---

## 📜 Philosophy

Dagda is built on the same philosophy as the deity it's named for — **mastery through simplicity**. No Electron, no LSP servers, no heavy runtime, no mandatory network connection. Just Python + tkinter, always available, always lightweight. The system running it needs the language toolchains; Dagda just drives them.

---

## 📄 License

MIT — use it, modify it, make it your own.
