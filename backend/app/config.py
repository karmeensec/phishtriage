"""Application configuration helpers."""

import os


TRUE_VALUES = {
    "1",
    "true",
    "yes",
    "on",
}


def public_demo_mode_enabled() -> bool:
    """Return whether public-demo privacy mode is enabled."""

    value = os.getenv(
        "PUBLIC_DEMO_MODE",
        "false",
    )

    return value.strip().casefold() in TRUE_VALUES