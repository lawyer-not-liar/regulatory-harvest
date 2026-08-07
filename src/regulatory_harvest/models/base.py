"""Shared strict model behavior."""

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base for versioned public models that reject unknown fields."""

    model_config = ConfigDict(extra="forbid")

