import os
import sys
from collections.abc import Mapping
from pathlib import Path

DEFAULT_DATABASE_FILENAME = "monitoring.db"


def default_monitoring_database_path(
    *,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    platform: str | None = None,
) -> Path:
    """Return a platform-appropriate per-user monitoring database path."""

    environment = os.environ if environ is None else environ
    home_directory = Path.home() if home is None else Path(home)
    current_platform = sys.platform if platform is None else platform

    if current_platform == "win32":
        local_app_data = environment.get("LOCALAPPDATA")
        data_root = (
            Path(local_app_data)
            if local_app_data
            else home_directory / "AppData" / "Local"
        )
        data_directory = data_root / "LotusWatch"
    elif current_platform == "darwin":
        data_directory = (
            home_directory / "Library" / "Application Support" / "LotusWatch"
        )
    else:
        xdg_data_home = environment.get("XDG_DATA_HOME")
        data_root = (
            Path(xdg_data_home)
            if xdg_data_home
            else home_directory / ".local" / "share"
        )
        data_directory = data_root / "lotuswatch"

    return data_directory / DEFAULT_DATABASE_FILENAME


def resolve_monitoring_database_path(
    database_path: str | os.PathLike[str] | None = None,
) -> Path:
    """Resolve an explicit database path or use the platform default."""

    selected_path = (
        default_monitoring_database_path()
        if database_path is None
        else Path(database_path).expanduser()
    )
    return Path(os.path.abspath(selected_path))


__all__ = [
    "DEFAULT_DATABASE_FILENAME",
    "default_monitoring_database_path",
    "resolve_monitoring_database_path",
]
