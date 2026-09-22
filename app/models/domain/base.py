"""
Reusable UUID primary key and UTC audit timestamps.

This module provides the base model class for all domain entities,
delegating to the authoritative app.db.base.BaseModel.
"""

from app.db.base import BaseModel


class TimestampedModel(BaseModel):
    """
    Abstract base model providing stable IDs and audit timestamps.
    Inherits from the authoritative app.db.base.BaseModel.
    """
    __abstract__ = True