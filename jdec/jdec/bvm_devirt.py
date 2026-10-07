"""Backward-compatibility facade for jdec.devirt.

This module re-exports all identifiers from jdec.devirt to preserve backwards
compatibility with existing callers.
"""

from __future__ import annotations

from .devirt import *  # noqa: F401, F403
