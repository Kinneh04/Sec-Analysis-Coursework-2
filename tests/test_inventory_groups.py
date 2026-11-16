from pathlib import Path

from src.inventory import _benign_group_id


def test_benign_group_id_groups_same_directory():
    root = Path("C:/Program Files/7-Zip")
    a = root / "7z.exe"
    b = root / "7zG.exe"
    assert _benign_group_id(root, a) == _benign_group_id(root, b)


def test_benign_group_id_separates_different_install_roots():
    root_a = Path("C:/Program Files/7-Zip")
    root_b = Path("C:/Program Files/Mozilla Firefox")
    path = Path("app.exe")
    assert _benign_group_id(root_a, root_a / path) != _benign_group_id(root_b, root_b / path)
