from pathlib import Path

from lotuswatch.storage import (
    default_monitoring_database_path,
    resolve_monitoring_database_path,
)


def test_windows_default_path_uses_local_app_data() -> None:
    result = default_monitoring_database_path(
        environ={"LOCALAPPDATA": "C:/Users/Test/AppData/Local"},
        home=Path("C:/Users/Test"),
        platform="win32",
    )

    assert result == Path("C:/Users/Test/AppData/Local/LotusWatch/monitoring.db")


def test_windows_default_path_has_home_fallback() -> None:
    result = default_monitoring_database_path(
        environ={},
        home=Path("C:/Users/Test"),
        platform="win32",
    )

    assert result == Path("C:/Users/Test/AppData/Local/LotusWatch/monitoring.db")


def test_linux_default_path_uses_xdg_data_home() -> None:
    result = default_monitoring_database_path(
        environ={"XDG_DATA_HOME": "/data/user"},
        home=Path("/home/test"),
        platform="linux",
    )

    assert result == Path("/data/user/lotuswatch/monitoring.db")


def test_linux_default_path_has_home_fallback() -> None:
    result = default_monitoring_database_path(
        environ={},
        home=Path("/home/test"),
        platform="linux",
    )

    assert result == Path("/home/test/.local/share/lotuswatch/monitoring.db")


def test_macos_default_path_uses_application_support() -> None:
    result = default_monitoring_database_path(
        environ={},
        home=Path("/Users/test"),
        platform="darwin",
    )

    assert result == Path(
        "/Users/test/Library/Application Support/LotusWatch/monitoring.db"
    )


def test_explicit_database_path_is_absolute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    assert resolve_monitoring_database_path("data/monitoring.db") == (
        tmp_path / "data" / "monitoring.db"
    )
