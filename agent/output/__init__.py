# agent/output/__init__.py
# Exposes EventWriter and Alerter for clean imports.

from .event_writer import EventWriter
from .alerter      import Alerter

__all__ = ["EventWriter", "Alerter"]
