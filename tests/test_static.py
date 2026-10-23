from pathlib import Path
from importlib import util


def test_required_files():
    root=Path(__file__).resolve().parents[1]
    for p in ("app.py", "Dockerfile", "requirements.txt", "static/index.html", "README.md"):
        assert (root/p).is_file()


def test_ui_has_controls():
    html=(Path(__file__).resolve().parents[1]/"static/index.html").read_text()
    for text in ("id=\"url\"", "id=\"password\"", "id=\"logList\"", "id=\"links\"", "/api/inspect"):
        assert text in html
