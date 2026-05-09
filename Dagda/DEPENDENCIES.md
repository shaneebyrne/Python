# ⚔ Dagda IDE — Language Dependencies

Dagda itself requires only **Python 3.9+** and **tkinter** (included with standard Python on Windows; see below for Linux/macOS). Syntax highlighting requires `pygments` — the launcher scripts attempt to install it automatically.

---

## 🐍 Dagda Runtime (Required)

| Dependency | Version | Notes |
|------------|---------|-------|
| Python | 3.9 or newer | https://python.org |
| tkinter | bundled with Python | On Linux: `sudo apt install python3-tk` |
| pygments | 2.x | `pip install pygments` — optional, enables syntax highlighting |

---

## Language-Specific Dependencies

Each section below lists what must be installed on the **host system** for Dagda to compile and/or run that language. Dagda does not install these — it delegates to them.

---

### 🐍 Python
| Item | Notes |
|------|-------|
| Python 3.x | Already installed (Dagda uses the same interpreter) |
| No extra steps | Runs immediately |

---

### 🦀 Rust
| Item | Install |
|------|---------|
| `rustc` compiler | https://rustup.rs → `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| `cargo` (for projects) | Installed with rustup automatically |
| Windows | Use rustup-init.exe from https://rustup.rs |

**Test:** `rustc --version`

---

### ☕ Java
| Item | Install |
|------|---------|
| JDK 11+ (`javac`, `java`) | https://adoptium.net (Temurin) or `sudo apt install default-jdk` |
| Windows | Download from https://adoptium.net, add `%JAVA_HOME%\bin` to PATH |

**Test:** `javac --version && java --version`

---

### 🟨 JavaScript / TypeScript (Node.js)
| Item | Install |
|------|---------|
| Node.js 18+ (`node`) | https://nodejs.org or `sudo apt install nodejs npm` |
| TypeScript (`tsc`) | `npm install -g typescript` |
| Windows | Use the .msi installer from https://nodejs.org |

**Test:** `node --version` / `tsc --version`

---

### 💎 Ruby
| Item | Install |
|------|---------|
| Ruby 3.x (`ruby`) | https://www.ruby-lang.org or `sudo apt install ruby` |
| Windows | Use RubyInstaller: https://rubyinstaller.org |

**Test:** `ruby --version`

---

### 🟦 PowerShell
| Item | Install |
|------|---------|
| PowerShell 5.1 | Built into Windows 10/11 (`powershell.exe`) |
| PowerShell 7+ (`pwsh`) | https://github.com/PowerShell/PowerShell/releases — required on Linux/macOS |

**Test:** `powershell -Command "$PSVersionTable"` / `pwsh --version`

---

### 🐚 Bash
| Item | Install |
|------|---------|
| Bash | Pre-installed on Linux/macOS |
| Windows | Git for Windows (https://git-scm.com) installs Git Bash, or enable WSL |

**Test:** `bash --version`

---

### 🪟 Batch (CMD)
| Item | Install |
|------|---------|
| `cmd.exe` | Built into all Windows versions — no install needed |
| Linux/macOS | Not natively supported (use Wine or skip) |

---

### ⚙ C (GCC)
| Item | Install |
|------|---------|
| GCC (`gcc`) | Linux: `sudo apt install gcc` · macOS: `xcode-select --install` |
| Windows | MSYS2 + MinGW-w64: https://www.msys2.org, then `pacman -S mingw-w64-ucrt-x86_64-gcc` |
| Clang alternative | `sudo apt install clang` then symlink `gcc → clang` |

**Test:** `gcc --version`

---

### ⚙ C++ (G++)
| Item | Install |
|------|---------|
| G++ (`g++`) | Linux: `sudo apt install g++` · macOS: `xcode-select --install` |
| Windows | Same as C (MSYS2 + MinGW-w64) |

**Test:** `g++ --version`

---

### 🐹 Go
| Item | Install |
|------|---------|
| Go 1.18+ (`go`) | https://go.dev/dl/ or `sudo apt install golang` |

**Test:** `go version`

---

### 🌙 Lua
| Item | Install |
|------|---------|
| Lua 5.x (`lua`) | `sudo apt install lua5.4` · macOS: `brew install lua` |
| Windows | https://luabinaries.sourceforge.net or `winget install DEVCOM.Lua` |

**Test:** `lua -v`

---

### 🐪 Perl
| Item | Install |
|------|---------|
| Perl 5 (`perl`) | Pre-installed on Linux/macOS |
| Windows | Strawberry Perl: https://strawberryperl.com |

**Test:** `perl --version`

---

### 🐘 PHP
| Item | Install |
|------|---------|
| PHP 8.x (`php`) | `sudo apt install php` · macOS: `brew install php` |
| Windows | https://windows.php.net/download |

**Test:** `php --version`

---

### 🦅 Swift
| Item | Install |
|------|---------|
| Swift 5.9+ (`swift`) | macOS: included with Xcode / `xcode-select --install` |
| Linux | https://www.swift.org/install/linux |
| Windows | https://www.swift.org/install/windows (experimental) |

**Test:** `swift --version`

---

### 🟣 Kotlin
| Item | Install |
|------|---------|
| JDK 11+ | (see Java above) |
| Kotlin compiler (`kotlinc`) | https://kotlinlang.org/docs/command-line.html or `sdk install kotlin` |
| Windows | Download ZIP from https://github.com/JetBrains/kotlin/releases |

**Test:** `kotlinc -version`

---

## Notes on PATH

All of the above tools must be accessible on your system's **PATH** for Dagda's terminal to find them. On Windows, when installing via an official installer, opt in to "Add to PATH" during setup. You may need to restart Dagda (or your shell) after installing new tools.

---

## Quick Check Script

Run this in Dagda's terminal (Python):

```python
import shutil
tools = ["python","rustc","javac","node","ruby","pwsh","bash","gcc","g++","go","lua","php","perl","swift","kotlinc"]
for t in tools:
    found = shutil.which(t)
    status = "✓" if found else "✗"
    print(f"  {status}  {t:12s} {'— ' + found if found else '— NOT FOUND'}")
```
