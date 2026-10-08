"""cPanel Passenger entry point for the PharmaFlow FastAPI application.

cPanel/CloudLinux Passenger loads the WSGI callable named `application`.
The repository keeps the ASGI app in `main.py`; a2wsgi bridges FastAPI to
Passenger without requiring a separate server process.
"""

from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent
WEB_DIR = BACKEND_DIR.parent

# Passenger may start from a different working directory.
# Keep imports deterministic regardless of the process cwd.
for path in (BACKEND_DIR, WEB_DIR):
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)

from a2wsgi import ASGIMiddleware
from main import app

application = ASGIMiddleware(app)
