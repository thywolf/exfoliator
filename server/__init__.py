"""Server package."""
from .handlers import dummy
from .server import app, create_app

__all__ = ["app", "create_app", "dummy"]
