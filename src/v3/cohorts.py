"""Cohort tag helpers for multi-wave training and blind evaluation."""

from __future__ import annotations

# Ordered waves; each tag's training pool includes new_train from itself and all prior tags.
WAVES = ("v3", "v3.1", "v3.2")


def train_cohorts_for_tag(tag: str) -> list[tuple[str, tuple[str, ...]]]:
    if tag not in WAVES:
        raise ValueError(f"Unknown cohort tag {tag!r}; expected one of {WAVES}")
    idx = WAVES.index(tag)
    return [(t, ("new_train",)) for t in WAVES[: idx + 1]]


def prior_tags(tag: str) -> tuple[str, ...]:
    if tag not in WAVES:
        return ()
    idx = WAVES.index(tag)
    return WAVES[:idx]
