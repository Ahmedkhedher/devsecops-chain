"""One-click launcher for the local web interface.

Double-click on Windows: starts the server on 127.0.0.1 and opens the default
browser. `.pyw` keeps the console hidden; the page has a Stop server button and
the process exits on its own after 30 idle minutes.

Terminal users can keep running `py -m web.server`.
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
            "DevSecOps Chain web UI failed to start",
            f"{detail}\n\nPython: {sys.executable}\nProject: {ROOT}",
        )
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    try:
        runpy.run_module("web.server", run_name="__main__")
    except SystemExit:
        raise
    except Exception:
        _show_error(traceback.format_exc(limit=6))
