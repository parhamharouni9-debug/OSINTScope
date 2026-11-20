import math
import os
from dataclasses import dataclass
from pathlib import Path


def data_directory() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "osintscope"


def default_database() -> Path:
    return Path(
        os.environ.get("OSINTSCOPE_DB") or data_directory() / "history.sqlite3"
    ).expanduser()


@dataclass(frozen=True)
class NetworkSettings:
    timeout: float = 10.0
    retries: int = 1

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 60:
            raise ValueError("Timeout must be greater than 0 and at most 60 seconds.")
        if not 0 <= self.retries <= 3:
            raise ValueError("Retries must be between 0 and 3.")
