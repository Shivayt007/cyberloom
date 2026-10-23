from pathlib import Path
from importlib import util


def test_required_files():
    root=Path(__file__).resolve().parents[1]
    for p in ("app.py", "Dockerfile", "requirements.txt", "static/index.html", "README.md"):
        assert (root/p).is_file()


def test_ui_has_controls():
    html=(Path(__file__).resolve().parents[1]/"static/index.html").read_text()
    for text in ("id=\"url\"", "id=\"logList\"", "id=\"links\"", "/api/inspect"):
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
    assert 'body.live' in backend
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



def test_ready_cta_href_is_checked_before_navigation():
    import ast
    from urllib.parse import urlsplit, parse_qs

    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    module = ast.parse(source)
    validator = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "validated_continue_url"
    )
    ns = {"urlsplit": urlsplit, "parse_qs": parse_qs}
    exec(compile(ast.Module(body=[validator], type_ignores=[]), "cta_validator", "exec"), ns)
    valid = ns["validated_continue_url"]
    assert valid("https://www.cyberloom.best/out?t=cH9v9Uyp0lP6zuSi%2BO%2Btz")
    assert valid("https://cyberloom.best/out?t=anotherToken")
    assert not valid("http://www.cyberloom.best/out?t=token")
    assert not valid("https://evil.example/out?t=token")
    assert not valid("https://cyberloom.best.attacker.test/out?t=token")
    assert not valid("https://www.cyberloom.best/in?t=token")
    assert not valid("https://www.cyberloom.best/out")
    assert not valid("https://www.cyberloom.best/out?t=")
    assert not valid("https://user:secret@www.cyberloom.best/out?t=token")

    assert 'frame.locator("a#cta[href]")' in source
    assert 'await ready_continue_href(tab)' in source
    assert 'await tab.goto(href, wait_until="domcontentloaded", timeout=18000)' in source
    assert "followed_continue_hrefs.add(href)" in source


def test_m1_direct_url_preserves_signed_query():
    """The user-supplied CDN example shape must survive scraping intact."""
    import ast
    import html
    import re
    from urllib.parse import urljoin, urlsplit

    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    tree = ast.parse(source)
    names = {"is_m1_direct_label", "link_score", "collect_candidate", "public_link_for_log"}
    declarations = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    scope = {
        "re": re,
        "html": html,
        "urljoin": urljoin,
        "urlsplit": urlsplit,
        "SUSPICIOUS_LINK_KEYS": ("gofile.io", "download", "pixeldrain"),
        "SKIP_PATHS": ("/login", "/register", "/terms", "/privacy"),
    }
    exec(compile(ast.Module(body=declarations, type_ignores=[]),
                 "m1_extract_tests", "exec"), scope)

    signed = (
        "https://cdn.juicybits.site/files/example.zip?"
        "token=test-token-123&exp=1792767679"
    )
    assert scope["is_m1_direct_label"]("[M1] DIRECT")
    assert scope["is_m1_direct_label"]("M1 Direct")
    assert not scope["is_m1_direct_label"]("M2 DIRECT")
    assert scope["link_score"](signed, "[M1] DIRECT") == "M1 DIRECT"
    assert scope["link_score"](signed, "Direct ZIP") == "Direct file"
    results = {}
    scope["collect_candidate"](signed.replace("&", "&amp;"),
                               "[M1] DIRECT", "https://messycloud.ink/file", results)
    assert signed in results
    assert results[signed]["kind"] == "M1 DIRECT"
    assert "token=" not in scope["public_link_for_log"](signed)
    assert "exp=" not in scope["public_link_for_log"](signed)
    assert 'id="m1Section"' in (
        Path(__file__).resolve().parents[1] / "static/index.html"
    ).read_text()



def test_messycloud_all_link_extraction_without_network():
    """Offline fake page: signed M1, other server, generic page and data URL."""
    import ast
    import asyncio
    import html
    import re
    from urllib.parse import urljoin, urlsplit

    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    module = ast.parse(source)
    names = {"is_m1_direct_label", "link_score", "collect_candidate",
             "visible_download_link", "extract_links"}
    nodes = [node for node in module.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name in names]
    class FakePlaywrightError(Exception):
        pass
    scope = {
        "re": re, "html": html, "urljoin": urljoin, "urlsplit": urlsplit,
        "PlaywrightError": FakePlaywrightError,
        "SUSPICIOUS_LINK_KEYS": ("gofile.io", "download", "pixeldrain"),
        "SKIP_PATHS": ("/login", "/register", "/terms", "/privacy"),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]),
                 "messycloud_links", "exec"), scope)
    class Frame:
        url = "https://messycloud.ink/files/demo"
        async def evaluate(self, script):
            assert "a[href]" in script
            assert "data-download-url" in script
            return [
                {"url": "https://cdn.juicybits.site/files/test.mkv?token=a&amp;exp=1",
                 "label": "[M1] DIRECT"},
                {"url": "https://cdn2.example.org/stream?id=abc",
                 "label": "[M2] STREAM"},
                {"url": "/faq", "label": "FAQ"},
                {"url": "https://download.example.org/example.zip",
                 "label": "Download Backup"},
                {"url": "https://cdn.juicybits.site/files/test.mkv?token=a&amp;exp=1",
                 "label": "Generic server duplicate"},
            ]
        async def content(self):
            return '<script>const file="https://cdn.juicybits.site/files/extra.zip?token=b&amp;exp=2";</script>'

    class Page:
        frames = [Frame()]
    links = asyncio.run(scope["extract_links"](Page()))
    by_url = {entry["url"]: entry for entry in links}
    assert len(by_url) == 5
    assert by_url["https://cdn.juicybits.site/files/test.mkv?token=a&exp=1"]["kind"] == "M1 DIRECT"
    assert by_url["https://cdn2.example.org/stream?id=abc"]["kind"] == "Server link"
    assert by_url["https://messycloud.ink/faq"]["kind"] == "Other link"
    assert "https://cdn.juicybits.site/files/extra.zip?token=b&exp=2" in by_url
    front = (Path(__file__).resolve().parents[1] / "static/index.html").read_text()
    assert 'id="linkFilter"' in front
    assert "All MessyCloud links" in front
    assert "existingIndex!==-1" in front



def test_link_event_kind_does_not_collide_with_event_type():
    """Exercise the exact scenario that crashed after reaching MessyCloud."""
    import ast
    import json
    import time
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    module = ast.parse(source)
    declaration = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "event"
    )
    ns = {"json": json, "time": time}
    exec(compile(ast.Module(body=[declaration], type_ignores=[]),
                 "event_test", "exec"), ns)
    link = {
        "url": "https://cdn.juicybits.site/files/example.mkv?token=abc&exp=1792767915",
        "label": "[M1] DIRECT",
        "kind": "M1 DIRECT",
    }
    parsed = json.loads(ns["event"]("link", **link).decode("utf-8"))
    assert parsed["type"] == "link"
    assert parsed["kind"] == "M1 DIRECT"
    assert parsed["url"] == link["url"]
    assert parsed["label"] == "[M1] DIRECT"
    assert "time" in parsed


def test_public_multi_link_discovery_and_password_removal():
    import ast
    import html
    import re
    from html.parser import HTMLParser
    from contextlib import suppress
    from urllib.parse import urlsplit
    root = Path(__file__).resolve().parents[1]
    source = (root / "app.py").read_text()
    module = ast.parse(source)
    declarations = [
        node for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and
        node.name in ("CyberloomFinder", "discover_cyberloom_links", "is_short_link")
    ]
    env = {
        "HTMLParser": HTMLParser, "re": re, "html": html, "urlsplit": urlsplit,
        "suppress": suppress, "ALLOWED_START": {"cyberloom.best", "www.cyberloom.best"},
        "MAX_BATCH_LINKS": 8
    }
    env["CYBERLOOM_SHORT_PATTERN"] = re.compile(
        r"(?:https?:)?//(?:www\\.)?cyberloom\\.best/l/"
        r"[A-Za-z0-9_%\\-]+(?:\\?[A-Za-z0-9_%&=+\\-./]*)?", re.I
    )
    exec(compile(ast.Module(body=declarations, type_ignores=[]),
                 "discovery_test", "exec"), env)
    markup = """
      <a href="https://www.cyberloom.best/l/first">1</a>
      <a href="https://cyberloom.best/l/second?t=abc&amp;p=2">2</a>
      <script>const x = "https:\\/\\/www.cyberloom.best\\/l\\/third";</script>
      <a href="https://www.cyberloom.best/l/first">repeat</a>
      <a href="https://evil.example/l/nope">bad</a>
      <a href="https://www.cyberloom.best/out?t=secret">not short</a>
    """
    links = env["discover_cyberloom_links"](markup)
    assert len(links) == 3, links
    assert links[0] == "https://www.cyberloom.best/l/first"
    assert "https://cyberloom.best/l/second?t=abc&p=2" in links
    assert "https://www.cyberloom.best/l/third" in links
    many = " ".join(f"https://www.cyberloom.best/l/L{i}" for i in range(40))
    assert len(env["discover_cyberloom_links"](many)) == 8

    front = (root / "static/index.html").read_text()
    assert 'id="password"' not in front
    assert "X-API-Key" not in front
    assert 'id="batchList"' in front
    assert "event.type==='discovered'" in front
    assert "def verify_token(" not in source
    assert "APP_PASSWORD" not in source
    assert "PublicOnlyResolver" in source
    assert "allow_redirects=False" in source
    assert 'yield event("batch_done"' in source


def test_public_url_prevents_private_and_custom_ports():
    import ast
    import ipaddress
    from urllib.parse import urlsplit
    class HTTPException(Exception):
        def __init__(self, status_code, detail):
            self.status_code = status_code
            self.detail = detail
    root = Path(__file__).resolve().parents[1]
    source = (root / "app.py").read_text()
    mod = ast.parse(source)
    validator = next(x for x in mod.body if
                     isinstance(x, ast.FunctionDef)
                     and x.name == "basic_public_url")
    env = {"urlsplit": urlsplit, "ipaddress": ipaddress,
           "HTTPException": HTTPException}
    exec(compile(ast.Module(body=[validator], type_ignores=[]),
                 "validation_test", "exec"), env)
    valid = env["basic_public_url"]
    assert valid("https://example.org/page") == "https://example.org/page"
    for url in ("http://127.0.0.1/secret", "http://169.254.169.254/latest",
                "http://localhost/admin", "http://10.0.0.1/",
                "http://[::1]/", "https://example.org:8080/page",
                "file:///etc/passwd", "https://a:b@example.org/"):
        try:
            valid(url)
        except HTTPException as exc:
            assert exc.status_code == 400
        else:
            raise AssertionError(f"Accepted unsafe URL: {url}")
