"""Passenger entry point for PharmaFlow on cPanel/CloudLinux.

Passenger expects a WSGI callable. PharmaFlow itself is a FastAPI (ASGI)
application, so a2wsgi provides the ASGI-to-WSGI bridge.

The explicit path setup is intentional: cPanel Passenger can start the
application with a working directory different from this file's directory.
"""

from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent
WEB_DIR = BACKEND_DIR.parent

# Make both Backend and web import roots deterministic under Passenger.
for path in (str(BACKEND_DIR), str(WEB_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from a2wsgi import ASGIMiddleware
from main import app

application = ASGIMiddleware(app)
