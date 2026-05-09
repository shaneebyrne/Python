# ⚔ Dagda IDE — Software Bill of Materials (SBOM)

**Document Version:** 1.0  
**Application:** Dagda IDE v1.0.0  
**Format:** Narrative SBOM (see CycloneDX / SPDX for machine-readable formats)  
**Date:** 2025  

---

## 1. Application Overview

| Field | Value |
|-------|-------|
| Name | Dagda IDE |
| Version | 1.0.0 |
| License | MIT |
| Language | Python 3.9+ |
| Purpose | Polyglot code editor and runner |
| Author | Tempo Communications IT Tools |

---

## 2. First-Party Components

All components listed below are original code written for this project and are included in the repository.

| Component | Path | License | Description |
|-----------|------|---------|-------------|
| `dagda.app` | `dagda/app.py` | MIT | Main application controller |
| `dagda.theme` | `dagda/theme.py` | MIT | Catppuccin Mocha palette and ttk styles |
| `dagda.file_manager` | `dagda/file_manager.py` | MIT | File open/save/detect |
| `dagda.editor.editor_widget` | `dagda/editor/editor_widget.py` | MIT | Code editor widget with gutter |
| `dagda.editor.syntax` | `dagda/editor/syntax.py` | MIT | Syntax highlighting bridge |
| `dagda.gui.menubar` | `dagda/gui/menubar.py` | MIT | Application menu bar |
| `dagda.gui.toolbar` | `dagda/gui/toolbar.py` | MIT | Toolbar: run, stop, language |
| `dagda.gui.tabs` | `dagda/gui/tabs.py` | MIT | Multi-tab manager |
| `dagda.gui.terminal` | `dagda/gui/terminal.py` | MIT | Output panel |
| `dagda.gui.statusbar` | `dagda/gui/statusbar.py` | MIT | Status bar |
| `dagda.languages.base` | `dagda/languages/base.py` | MIT | LanguageRunner ABC + registry |
| `dagda.languages.runners` | `dagda/languages/runners.py` | MIT | All language implementations |

---

## 3. Python Standard Library Dependencies

These are part of CPython and carry the **Python Software Foundation License (PSF)**. No installation required.

| Module | Version | Purpose |
|--------|---------|---------|
| `tkinter` | bundled | GUI framework (wraps Tcl/Tk) |
| `tkinter.ttk` | bundled | Themed widget set |
| `tkinter.filedialog` | bundled | File open/save dialogs |
| `tkinter.messagebox` | bundled | Alert dialogs |
| `tkinter.font` | bundled | Font introspection |
| `subprocess` | bundled | Launching language processes |
| `threading` | bundled | Background process I/O |
| `queue` | bundled | Thread-safe output streaming |
| `os` | bundled | Path manipulation |
| `sys` | bundled | Python interpreter discovery |
| `abc` | bundled | Abstract base classes |
| `time` | bundled | Execution timing |
| `typing` | bundled | Type annotations |

---

## 4. Third-Party Dependencies

### 4.1 Required

None. Dagda runs without any third-party packages.

### 4.2 Optional (Strongly Recommended)

| Package | Version | License | Source | Purpose |
|---------|---------|---------|--------|---------|
| `pygments` | ≥ 2.14 | BSD-2-Clause | https://pypi.org/project/Pygments/ | Syntax highlighting |

**pygments** is used solely for lexing source code to apply colour tags to the editor. If not installed, Dagda runs normally without syntax highlighting. The launchers attempt `pip install pygments` automatically.

#### pygments Sub-dependencies (pulled automatically by pip)

| Package | License | Notes |
|---------|---------|-------|
| No mandatory transitive deps | — | pygments is self-contained |

---

## 5. Runtime Language Toolchain Dependencies

These are **not** Python packages and are **not** bundled with Dagda. They are external tools that users must install separately to use each language. Dagda invokes them as subprocesses.

| Language | Tool | License | Source |
|----------|------|---------|--------|
| Python | CPython | PSF | https://python.org |
| Rust | rustc / cargo | Apache-2.0 / MIT | https://rustup.rs |
| Java | JDK (javac, java) | GPL-2.0-with-CE | https://adoptium.net |
| JavaScript | Node.js | MIT | https://nodejs.org |
| TypeScript | tsc (typescript) | Apache-2.0 | https://typescriptlang.org |
| Ruby | MRI Ruby | Ruby / BSD-2 | https://ruby-lang.org |
| PowerShell | PowerShell 7 | MIT | https://github.com/PowerShell/PowerShell |
| Bash | GNU Bash | GPL-3.0 | https://gnu.org/software/bash |
| Batch | cmd.exe | Proprietary (Microsoft) | Built into Windows |
| C | GCC | GPL-3.0 | https://gcc.gnu.org |
| C++ | G++ | GPL-3.0 | https://gcc.gnu.org |
| Go | Go toolchain | BSD-3-Clause | https://go.dev |
| Lua | PUC-Rio Lua | MIT | https://lua.org |
| Perl | Perl 5 | Artistic-2.0 / GPL-1+ | https://perl.org |
| PHP | PHP | PHP-3.01 | https://php.net |
| Swift | Swift compiler | Apache-2.0 | https://swift.org |
| Kotlin | kotlinc | Apache-2.0 | https://kotlinlang.org |

---

## 6. Colour Theme Attribution

| Theme | License | Source |
|-------|---------|--------|
| Catppuccin Mocha | MIT | https://github.com/catppuccin/catppuccin |

The Catppuccin Mocha palette colours are used in accordance with the Catppuccin MIT license. No Catppuccin code is bundled — only the colour hex values are referenced.

---

## 7. Platform-Specific Notes

| Platform | Tcl/Tk Version | Notes |
|----------|---------------|-------|
| Windows 10/11 | 8.6 (bundled with Python) | Full feature support |
| Ubuntu 22.04+ | 8.6 | Requires `python3-tk` package |
| macOS 12+ | 8.6 | `python-tk` via Homebrew recommended |

---

## 8. Security Considerations

- Dagda executes user-supplied source files as subprocesses with the **user's own privileges**. It does not sandbox or restrict what the code can do.  
- No network access is initiated by Dagda itself.  
- No telemetry, analytics, or remote update mechanisms are present.  
- `subprocess.CREATE_NO_WINDOW` is applied on Windows to suppress console windows.  
- The optional `pip install pygments` step in the launchers contacts PyPI over HTTPS.

---

## 9. SBOM Generation

For machine-readable SBOM generation:

```bash
# CycloneDX format
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.cyclonedx.json

# SPDX format via syft
syft dir:. -o spdx-json > sbom.spdx.json
```

---

*This SBOM was generated manually. For production environments, use an automated tool such as Syft, CycloneDX-BOM, or FOSSA to keep it current.*
