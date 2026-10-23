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


def test_live_browser_streaming_wired():
    root = Path(__file__).resolve().parents[1]
    backend = (root / "app.py").read_text()
    frontend = (root / "static/index.html").read_text()
    assert 'live: bool = Field(default=True)' in backend
    assert 'yield event("frame", image=capture' in backend
    assert 'body.timeout, body.settle, body.live' in backend
    assert 'id="liveStatus"' in frontend
    assert 'id="toggleLive"' in frontend
    assert "event.type==='frame'" in frontend
    assert "live:true" in frontend
    assert 'previewSection").classList.add' not in frontend


def test_continue_click_actionability_safety():
    """Regression guard: don't reintroduce forced clicks or bad mouse args."""
    import ast
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    tree = ast.parse(source)
    routine = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                   and n.name == "click_continue")
    handler = ast.get_source_segment(source, routine)
    assert "frame.get_by_role" in handler
    assert "document.elementFromPoint" in handler
    assert "owner.contains(hit)" in handler
    assert "page.mouse.click" in handler
    assert "force=True" not in handler
    for node in ast.walk(routine):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "click" and isinstance(node.func.value, ast.Attribute):
                if node.func.value.attr == "mouse":
                    assert not any(arg.arg == "timeout" for arg in node.keywords)


def test_blocked_overlay_logging_and_throttle():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    source = (root / "app.py").read_text()
    assert 'const blocker = !safe && hit ? {' in source
    assert 'pointerEvents: hs.pointerEvents' in source
    assert 'zIndex: hs.zIndex' in source
    assert 'json.dumps(blocker, ensure_ascii=False)' in source
    assert 'last_click_by_tab[tab] = time.monotonic()' in source
    assert 'await control.click(timeout=1600)' in source



def test_verification_popup_dismissal_respects_close_control():
    import ast
    root = Path(__file__).resolve().parents[1]
    source = (root / "app.py").read_text()
    tree = ast.parse(source)
    helper = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "close_visible_verification_popup")
    code = ast.get_source_segment(source, helper)
    assert "aria-label*=" in code
    assert "modal-close" in code
    assert "close.click(" in code
    assert "needs_human_verification(page)" in code
    assert "force=True" not in code
    assert ".remove()" not in code
    assert "pointerEvents =" not in code
    assert "dismissed, details = await close_visible_verification_popup" in source
