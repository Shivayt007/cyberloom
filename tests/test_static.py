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


def test_vps_browser_diagnostics_present():
    root = Path(__file__).resolve().parents[1]
    backend = (root / "app.py").read_text()
    frontend = (root / "static/index.html").read_text()
    assert "async def page_diagnostics(page)" in backend
    assert "async def preview_image(page)" in backend
    assert 'yield event("screenshot", image=preview' in backend
    assert 'id="previewSection"' in frontend
    assert "event.type==='screenshot'" in frontend


def test_server_app_parses():
    import ast
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    ast.parse(source)


def test_stackmint_custom_continue_button_support():
    root = Path(__file__).resolve().parents[1]
    backend = (root / "app.py").read_text()
    assert "frame.get_by_text(specific)" in backend
    assert "continue_candidates: ctas" in backend
    assert "click_detail = await click_continue(tab)" in backend
    assert "No actionable Continue control detected" in backend
