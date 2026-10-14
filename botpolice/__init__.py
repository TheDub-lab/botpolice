"""botpolice -- a defensive honeypot and canary-token system.

Detects AI-driven worm / automated-agent activity inside a network you control.
Detection and logging only: it never attacks, scans, or contacts any outside
system (the sole outbound connection is the alert webhook you configure).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
