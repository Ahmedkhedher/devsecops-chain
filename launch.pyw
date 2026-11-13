"""One-click launcher for the desktop interface.

Double-click this file on Windows: `.pyw` runs under pythonw, so the GUI opens
without a console window. Startup failures are shown in a dialog instead of
vanishing into a detached process.

Terminal users can keep running `py gui/app.py`.
"""

from __future__ import annotations

import os
import runpy
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _show_error(detail: str) -> None:
    try:
        from tkinter import Tk, messagebox

        root = Tk()
        root.withdraw()
        messagebox.showerror(
            "DevSecOps Chain failed to start",
            f"{detail}\n\nPython: {sys.executable}\nProject: {ROOT}",
        )
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    # Double-clicked launchers start in System32; anchor file dialogs and
    # relative paths to the project instead.
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    try:
        runpy.run_path(str(ROOT / "gui" / "app.py"), run_name="__main__")
    except Exception:
        _show_error(traceback.format_exc(limit=6))
