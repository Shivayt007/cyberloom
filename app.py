"""Cyberloom Link Inspector — single-user, password-protected Playwright website."""
from __future__ import annotations

import asyncio
import base64
import hmac
import html
import ipaddress
import json
import os
import re
import socket
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright, Error as PlaywrightError, TimeoutError as PlaywrightTimeout

ROOT = Path(__file__).parent
TOKEN = os.getenv("APP_PASSWORD", "")
ALLOWED_START = {v.strip().lower() for v in os.getenv("ALLOWED_START_HOSTS", "cyberloom.best,www.cyberloom.best").split(",") if v.strip()}
TARGET_HOSTS = {v.strip().lower() for v in os.getenv("TARGET_HOSTS", "messycloud.ink,www.messycloud.ink").split(",") if v.strip()}
SUSPICIOUS_LINK_KEYS = ("gofile.io", "pixeldrain", "vikingfile", "r2.dev", "workers.dev", "download", "mediafire.com", "mega.nz", "drive.google.com", "1fichier.com")
SKIP_PATHS = ("/login", "/register", "/terms", "/privacy", "/contact", "/about", "/dmca")
# Redirect domains observed during normal browser navigation. An advertising page
# can also appear between them; we log it but do not click controls on ad pages.
REDIRECT_HOSTS = {
    "stackmint.ink", "www.stackmint.ink",
    "inkvoyage.xyz", "www.inkvoyage.xyz",
    "linkvoyage.xyz", "www.linkvoyage.xyz",
}
app = FastAPI(title="Cyberloom Link Inspector", docs_url=None, redoc_url=None, openapi_url=None)
RUN_LOCK = asyncio.Lock()


class InspectRequest(BaseModel):
    url: str = Field(min_length=12, max_length=2048)
    timeout: int = Field(default=120, ge=30, le=180)
    settle: int = Field(default=12, ge=3, le=25)


def target_url(url: str) -> bool:
    try:
        p = urlsplit(url)
        return p.scheme in ("http", "https") and p.hostname and p.hostname.lower() in TARGET_HOSTS
    except ValueError:
        return False


def validate_start(url: str) -> str:
    try:
        p = urlsplit(url.strip())
        if p.scheme not in ("http", "https") or not p.hostname or p.hostname.lower() not in (ALLOWED_START | TARGET_HOSTS):
            raise ValueError("Enter a permitted Cyberloom short URL or a verified MessyCloud URL")
        if p.username or p.password or (p.port and p.port not in (80, 443)):
            raise ValueError("Credential URLs and custom ports are not allowed")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return url.strip()


def verify_token(token: str | None) -> None:
    if not TOKEN:
        raise HTTPException(status_code=503, detail="APP_PASSWORD is not configured on the server")
    if not token or not hmac.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="Incorrect access password")


def event(kind: str, **data) -> bytes:
    return (json.dumps({"type": kind, "time": time.strftime("%H:%M:%S"), **data}, ensure_ascii=False) + "\n").encode()


def link_score(url: str) -> str:
    return "Likely download" if any(k in url.lower() for k in SUSPICIOUS_LINK_KEYS) else "Other link"


def collect_candidate(url: str, text: str, base: str, out: dict[str, dict]) -> None:
    if not url or url.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return
    full = urljoin(base, html.unescape(url.strip()))
    try:
        parsed = urlsplit(full)
    except ValueError:
        return
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return
    if parsed.username or parsed.password:
        return
    if full.rstrip("/") == base.rstrip("/"):
        return
    if any(parsed.path.lower().startswith(x) for x in SKIP_PATHS):
        return
    if len(full) > 4096:
        return
    if full not in out and len(out) < 150:
        out[full] = {"url": full, "label": text[:100] or parsed.hostname, "kind": link_score(full)}


async def extract_links(page) -> list[dict]:
    """Read hyperlinks and URL-bearing data attributes from all accessible frames."""
    found: dict[str, dict] = {}
    for frame in page.frames:
        try:
            items = await frame.evaluate("""() => Array.from(document.querySelectorAll('a[href], [data-url], [data-href]')).slice(0, 500).map(el => ({
                url: el.getAttribute('href') || el.getAttribute('data-url') || el.getAttribute('data-href'),
                label: (el.innerText || el.textContent || '').trim().slice(0,100)
            }))""")
            for item in items:
                collect_candidate(item.get("url", ""), item.get("label", ""), frame.url, found)
            markup = await frame.content()
            for match in re.findall(r'https?://[^\s"\'<>\\]+', markup):
                candidate = html.unescape(match).rstrip(');,}')
                if any(k in candidate.lower() for k in SUSPICIOUS_LINK_KEYS):
                    collect_candidate(candidate, "Embedded URL", frame.url, found)
        except (PlaywrightError, ValueError):
            continue
    return sorted(found.values(), key=lambda entry: (entry["kind"] != "Likely download", entry["url"]))


async def can_request_public(hostname: str, cache: dict[str, bool]) -> bool:
    """Defense in depth: prevent the browser from requesting local/private IPs.

    DNS rebinding is still possible between this check and Chromium resolution.
    Keep the app password-protected and restrict your VPS network as appropriate.
    """
    host = (hostname or "").lower().strip(".")
    if host in cache:
        return cache[host]
    try:
        addresses = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, None), timeout=3)
        ok = bool(addresses) and all(ipaddress.ip_address(addr[4][0].split('%')[0]).is_global for addr in addresses)
    except (OSError, ValueError, asyncio.TimeoutError):
        ok = False
    cache[host] = ok
    return ok


async def click_continue(page) -> tuple[bool, str]:
    """Click a visible, enabled Continue control in the current browser tab.

    Stackmint's purple CTA can be rendered as a styled <div>/<span> rather
    than a native button. Playwright's get_by_text() clicks the rendered
    text and bubbles the user click to its handler, without forcing clicks
    through overlays or human-verification challenges.
    """
    specific = re.compile(r"continue\\s+to\\s+destination", re.I)
    generic = re.compile(r"\\b(continue|proceed|get\\s*link|open\\s*link|next\\s*step)\\b", re.I)
    errors: list[str] = []
    detected: list[str] = []

    for frame in page.frames:
        # Highest priority: the exact CTA seen in Stackmint screenshot.
        text_locator = frame.get_by_text(specific)
        try:
            text_count = min(await text_locator.count(), 8)
        except (PlaywrightError, PlaywrightTimeout) as exc:
            errors.append("Text scan failed: " + str(exc).splitlines()[0][:90])
            continue
        for i in range(text_count):
            control = text_locator.nth(i)
            try:
                if not await control.is_visible() or not await control.is_enabled():
                    continue
                tag = await control.evaluate("(el) => el.tagName.toLowerCase()", timeout=900)
                detected.append("Continue to Destination <" + tag + ">")
                await control.click(timeout=2300)
                return True, "Continue to Destination <" + tag + ">"
            except (PlaywrightError, PlaywrightTimeout) as exc:
                errors.append("Text CTA click blocked: " + str(exc).splitlines()[0][:145])

        # Some sites use a labelled anchor, div with click handler, or
        # accessibility role instead of the expected text node.
        selector = (
            "a:visible, button:visible, [role=button]:visible, "
            "[onclick]:visible, [tabindex]:visible, "
            "input[type=button]:visible, input[type=submit]:visible"
        )
        try:
            matches = frame.locator(selector).filter(has_text=generic)
            count = min(await matches.count(), 16)
            for i in range(count):
                control = matches.nth(i)
                try:
                    if not await control.is_visible() or not await control.is_enabled():
                        continue
                    tag = await control.evaluate("(el) => el.tagName.toLowerCase()", timeout=900)
                    label = (await control.inner_text(timeout=900)).strip()[:75]
                    detected.append(label or "<" + tag + ">")
                    await control.click(timeout=2300)
                    return True, (label or "Continue") + " <" + tag + ">"
                except (PlaywrightError, PlaywrightTimeout) as exc:
                    errors.append("Control click blocked: " + str(exc).splitlines()[0][:145])
            inputs = frame.locator('input[value]:visible')
            for i in range(min(await inputs.count(), 12)):
                control = inputs.nth(i)
                try:
                    label = (await control.get_attribute("value")) or ""
                    if generic.search(label) and await control.is_enabled():
                        detected.append(label[:65] + " <input>")
                        await control.click(timeout=2300)
                        return True, label[:65] + " <input>"
                except (PlaywrightError, PlaywrightTimeout) as exc:
                    errors.append("Input click blocked: " + str(exc).splitlines()[0][:145])
        except (PlaywrightError, PlaywrightTimeout) as exc:
            errors.append("Control scan failed: " + str(exc).splitlines()[0][:110])

    if errors:
        return False, "; ".join(errors[:2])
    if detected:
        return False, "Found a Continue control, but could not activate it"
    return False, "No actionable Continue control detected"


async def needs_human_verification(page) -> bool:
    """Recognize a visible verification prompt, without attempting to defeat it."""
    markers = (
        "verify you're human",
        "verify you’re human",
        "i'm human",
        "i’m human",
        "confirm you are human",
        "human verification required",
        "please verify you are human",
        "verify that you are human",
    )
    for frame in page.frames:
        try:
            text = (await frame.locator("body").inner_text(timeout=800)).lower()
            if any(marker in text for marker in markers):
                return True
        except (PlaywrightError, PlaywrightTimeout):
            continue
    return False


async def is_final_messycloud_page(page) -> bool:
    """Recognize the actual file/server page instead of an intermediate
    MessyCloud 'Continue to Destination' countdown. Both may use one URL.
    """
    if not target_url(page.url):
        return False
    try:
        body = (await page.locator("body").inner_text(timeout=1000)).lower()
    except (PlaywrightError, PlaywrightTimeout):
        return False
    if "continue to destination" in body and "choose a server to download" not in body:
        return False
    return (
        "choose a server to download" in body
        or "supports resume" in body
        or ("back to home" in body and "direct" in body)
    )


async def page_diagnostics(page) -> dict:
    """Report visible browser state without reading submitted form values."""
    try:
        return await page.evaluate("""() => {
            const visible = el => {
                const r = el.getBoundingClientRect();
                const st = getComputedStyle(el);
                return r.width > 0 && r.height > 0 &&
                       st.visibility !== 'hidden' && st.display !== 'none';
            };
            const body = (document.body?.innerText || '').toLowerCase();
            const buttons = Array.from(document.querySelectorAll(
                'a, button, [role="button"], [onclick], [tabindex], input[type="submit"], input[type="button"]'))
                .filter(visible).slice(0, 12).map(el => ({
                    text: (el.innerText || el.value || el.getAttribute('aria-label') || '')
                        .trim().slice(0, 75),
                    disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
                    tag: el.tagName.toLowerCase()
                }));
            const ctas = Array.from(document.querySelectorAll('a, button, div, span, [role="button"]'))
                .filter(el => visible(el) && /continue\\s+to\\s+destination/i.test(
                    (el.innerText || '').trim()) &&
                    (el.innerText || '').length < 100)
                .slice(-6).map(el => ({
                    tag: el.tagName.toLowerCase(),
                    role: el.getAttribute('role') || '',
                    text: (el.innerText || '').trim().slice(0,80),
                    pointer: getComputedStyle(el).cursor
                }));
            const frames = Array.from(document.querySelectorAll('iframe'));
            const challenge = /(verify|verification|captcha|human)/i.test(body)
                && /(human|captcha|challenge)/i.test(body)
                || frames.some(el => /captcha|turnstile|challenge/i.test(el.src || ''));
            return {
                title: document.title.slice(0, 90),
                headings: Array.from(document.querySelectorAll('h1,h2,h3'))
                    .filter(visible).slice(0, 5)
                    .map(el => (el.innerText || '').trim().slice(0, 85)),
                buttons,
                continue_candidates: ctas,
                iframe_count: frames.length,
                body_present: body.trim().length > 15,
                human_challenge: challenge,
                countdown_visible: /countdown|seconds remaining|wait \d+ seconds/i.test(body),
                ready_visible: /continue to destination|ready!/i.test(body)
            };
        }""")
    except (PlaywrightError, PlaywrightTimeout):
        return {"error": "Page DOM could not be inspected"}


async def preview_image(page) -> str | None:
    """Small in-memory screenshot; no files or cookies are saved on the VPS."""
    try:
        data = await page.screenshot(type="jpeg", quality=48, full_page=False, timeout=4500)
        if len(data) > 450000:
            return None
        return "data:image/jpeg;base64," + base64.b64encode(data).decode("ascii")
    except (PlaywrightError, PlaywrightTimeout):
        return None


async def inspect(url: str, timeout: int, settle: int):
    started = time.monotonic()
    deadline = started + timeout
    visited: list[str] = []
    current_url = url
    yield event("stage", step=1, status="active", detail="Launching Chromium")
    yield event("log", level="info", message=f"Opening {url}")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 800}, accept_downloads=False)
        dns_cache: dict[str, bool] = {}
        rejected_hosts: set[str] = set()
        failed_resource_hosts: dict[str, int] = {}

        def on_request_failed(request):
            try:
                hostname = urlsplit(request.url).hostname or "unknown"
                failed_resource_hosts[hostname] = failed_resource_hosts.get(hostname, 0) + 1
            except (TypeError, ValueError):
                pass

        context.on("requestfailed", on_request_failed)

        async def public_only(route):
            parsed = urlsplit(route.request.url)
            if parsed.scheme not in ("http", "https"):
                await route.abort()
            elif await can_request_public(parsed.hostname or "", dns_cache):
                await route.continue_()
            else:
                if parsed.hostname:
                    rejected_hosts.add(parsed.hostname.lower())
                await route.abort()

        await context.route("**/*", public_only)
        page = await context.new_page()
        try:
            try:
                first_response = await page.goto(url, wait_until="domcontentloaded", timeout=25000)
                if first_response and first_response.status >= 400:
                    yield event("log", level="warn",
                                message=f"Initial page returned HTTP {first_response.status}; site may be rejecting automation")
            except PlaywrightTimeout:
                yield event("log", level="warn", message="Initial navigation timed out; checking available pages")
            yield event("stage", step=1, status="done", detail="Browser launched")
            yield event("stage", step=2, status="active", detail="Waiting for countdown / Continue")
            last_seen = ""
            seen_tabs = {page}
            last_click = 0.0
            click_count = 0
            verification_since = None
            verification_page = None
            chosen = None
            logged_interstitials = set()
            next_progress_log = time.monotonic() + 10
            last_click_by_tab = {}
            click_count_by_tab = {}
            last_click_report = {}
            last_stackmint_url = None
            stackmint_since = None
            snapshot_sent = False
            while time.monotonic() < deadline:
                pages = [p for p in context.pages if not p.is_closed()]
                # Inspect every tab for the final destination, but do not let
                # an advertising popup take over the original countdown tab.
                for index, tab in enumerate(pages, start=1):
                    if tab not in seen_tabs:
                        seen_tabs.add(tab)
                        yield event("log", level="warn", message=f"New tab #{index} opened: {tab.url[:250]}")
                    if tab.url not in visited and tab.url not in ("about:blank", "chrome-error://chromewebdata/"):
                        visited.append(tab.url)
                        yield event("log", level="info", message=f"Tab #{index} URL: {tab.url[:250]}")
                # A MessyCloud URL may still show another "Continue" screen.
                # Only finish when the file page (including server options) is visible.
                chosen = None
                for tab in pages:
                    if target_url(tab.url):
                        if await is_final_messycloud_page(tab):
                            chosen = tab
                            break
                        if tab not in logged_interstitials:
                            logged_interstitials.add(tab)
                            yield event("log", level="info",
                                        message="MessyCloud intermediate page detected; waiting for the actual file/server page")
                if chosen:
                    break

                # Don't waste two minutes silently on a human-verification gate.
                # This cannot be solved by synthetic button presses in Chromium.
                challenged = None
                for tab in pages:
                    if (urlsplit(tab.url).hostname or "").lower() in (REDIRECT_HOSTS | TARGET_HOSTS):
                        if await needs_human_verification(tab):
                            challenged = tab
                            break
                if challenged is not None:
                    if verification_page is challenged and verification_since is not None:
                        if time.monotonic() - verification_since >= 3:
                            diagnosis = await page_diagnostics(challenged)
                            yield event("log", level="warn",
                                        message="Detected verification gate: " +
                                                json.dumps(diagnosis, ensure_ascii=False)[:950])
                            preview = await preview_image(challenged)
                            if preview:
                                yield event("screenshot", image=preview, url=challenged.url)
                            yield event("stage", step=2, status="error",
                                        detail="Manual human verification required")
                            yield event("log", level="warn",
                                        message="Redirect page shows a human-verification prompt. Headless Playwright cannot complete it.")
                            yield event("manual", url=challenged.url,
                                        message="Open the link in your own browser, complete verification, then paste the final MessyCloud URL into this website.")
                            yield event("error",
                                        message="Stopped at a human-verification page; increasing the countdown timeout will not fix this.",
                                        visited=visited)
                            return
                    else:
                        verification_page = challenged
                        verification_since = time.monotonic()
                else:
                    verification_page = None
                    verification_since = None

                now = time.monotonic()
                # Capture what headless Chromium actually sees. A URL alone
                # cannot tell whether JS loaded, a button is disabled, or a
                # human-verification iframe prevented progression.
                stackmint = next(
                    (tab for tab in pages if
                     (urlsplit(tab.url).hostname or "").lower()
                     in ("stackmint.ink", "www.stackmint.ink")),
                    None
                )
                if stackmint and stackmint.url == last_stackmint_url:
                    if stackmint_since is not None and not snapshot_sent and now - stackmint_since >= 18:
                        snapshot_sent = True
                        diagnosis = await page_diagnostics(stackmint)
                        yield event("log", level="warn",
                                    message="Stackmint has not navigated for 18s; browser state: " +
                                            json.dumps(diagnosis, ensure_ascii=False)[:950])
                        if rejected_hosts:
                            yield event("log", level="warn",
                                        message="Blocked non-public/unresolved resource hosts: " +
                                                ", ".join(sorted(rejected_hosts))[:600])
                        if failed_resource_hosts:
                            yield event("log", level="warn",
                                        message="Failed resource requests by host: " +
                                                ", ".join(f"{host}={n}" for host, n in
                                                          sorted(failed_resource_hosts.items()))[:600])
                        preview = await preview_image(stackmint)
                        if preview:
                            yield event("screenshot", image=preview, url=stackmint.url)
                        if diagnosis.get("human_challenge"):
                            yield event("stage", step=2, status="error",
                                        detail="Human verification displayed")
                            yield event("manual", url=stackmint.url,
                                        message="The VPS browser shows a human-verification challenge. Open the link in your own browser, complete it, then paste the final MessyCloud URL.")
                            yield event("error", message="Stackmint human verification cannot be completed automatically.", visited=visited)
                            return
                elif stackmint:
                    last_stackmint_url = stackmint.url
                    stackmint_since = now
                    snapshot_sent = False
                else:
                    last_stackmint_url = None
                    stackmint_since = None
                    snapshot_sent = False

                if now >= next_progress_log:
                    active = " | ".join(
                        f"#{idx}: {tab.url[:135]}"
                        for idx, tab in enumerate(pages, start=1)
                    )
                    yield event("log", level="info",
                                message=f"Elapsed {int(now-started)}s/{timeout}s; tabs: {active[:950]}")
                    next_progress_log = now + 10

                # Do not click generic Continue buttons on unrelated ad domains.
                # Prefer a MessyCloud interstitial when present, otherwise use
                # the original chain tab or recognized redirect domains.
                candidates = [
                    tab for tab in pages
                    if (urlsplit(tab.url).hostname or "").lower()
                    in (ALLOWED_START | REDIRECT_HOSTS | TARGET_HOSTS)
                ]
                candidates.sort(key=lambda tab: (not target_url(tab.url), tab is not page))
                for tab in candidates:
                    if click_count_by_tab.get(tab, 0) >= 12:
                        continue
                    if now - last_click_by_tab.get(tab, 0) < 5:
                        continue
                    clicked, click_detail = await click_continue(tab)
                    if clicked:
                        click_count_by_tab[tab] = click_count_by_tab.get(tab, 0) + 1
                        last_click_by_tab[tab] = time.monotonic()
                        yield event("log", level="success",
                                    message=f"Clicked {click_detail} on tab #{pages.index(tab)+1}"
                                            f" (attempt {click_count_by_tab[tab]})")
                        break
                    # Show a useful failed-action reason, but only once per 12s
                    # to prevent overwhelming the mobile live-terminal UI.
                    if click_detail != "No actionable Continue control detected":
                        last = last_click_report.get(tab, 0)
                        if time.monotonic() - last >= 12:
                            yield event("log", level="warn",
                                        message=f"Tab #{pages.index(tab)+1}: {click_detail[:220]}")
                            last_click_report[tab] = time.monotonic()
                await asyncio.sleep(1)
            if not chosen:
                yield event("stage", step=2, status="error", detail="Final MessyCloud file page was not reached")
                tabs = [f"#{i}: {tab.url}" for i, tab in enumerate(context.pages, start=1) if not tab.is_closed()]
                yield event("log", level="warn", message="Tabs at timeout: " + " | ".join(tabs)[:1600])
                yield event("error", message=f"Final MessyCloud file page was not reached within {timeout}s. Check for a human-verification prompt or changed intermediate redirect.", visited=visited)
                return
            current_url = chosen.url
            if current_url not in visited:
                visited.append(current_url)
            yield event("stage", step=2, status="done", detail="Redirect completed")
            yield event("stage", step=3, status="done", detail="Verified MessyCloud file page")
            yield event("log", level="success", message=f"Final MessyCloud file page found: {current_url}")
            yield event("destination", url=current_url, visited=visited)
            yield event("stage", step=4, status="active", detail="Watching links appear")
            found: dict[str, dict] = {}
            try:
                file_text = (await chosen.locator("body").inner_text(timeout=1000)).lower()
                if "m1" in file_text and "direct" in file_text:
                    yield event("log", level="success",
                                message="MessyCloud shows an M1 DIRECT server option; link capture depends on whether the page exposes its URL")
            except (PlaywrightError, PlaywrightTimeout):
                pass
            settle_until = time.monotonic() + settle
            while time.monotonic() < settle_until:
                for link in await extract_links(chosen):
                    if link["url"] not in found:
                        found[link["url"]] = link
                        yield event("link", **link)
                        yield event("log", level="success", message=f"Found link: {link['url'][:160]}")
                await asyncio.sleep(1)
            yield event("stage", step=4, status="done", detail=f"{len(found)} link(s) collected")
            yield event("done", destination=current_url, links=list(found.values()), visited=visited, elapsed=round(time.monotonic() - started, 1))
        except (PlaywrightError, OSError, ValueError) as exc:
            yield event("error", message=f"Browser error: {exc}", visited=visited)
        finally:
            with suppress(Exception):
                await context.close()
            with suppress(Exception):
                await browser.close()


@app.get("/")
async def home():
    return FileResponse(ROOT / "static" / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/inspect")
async def inspect_api(body: InspectRequest, request: Request, x_api_key: str | None = Header(default=None)):
    verify_token(x_api_key)
    safe_url = validate_start(body.url)
    if RUN_LOCK.locked():
        raise HTTPException(status_code=429, detail="Another scan is currently running. Try again when it finishes.")

    async def feed():
        async with RUN_LOCK:
            try:
                async for message in inspect(safe_url, body.timeout, body.settle):
                    if await request.is_disconnected():
                        break
                    yield message
            except Exception as exc:
                # Do not reveal secrets in an exception trace.
                yield event("error", message=f"Unexpected inspection error: {type(exc).__name__}: {exc}")
    return StreamingResponse(feed(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "X-Content-Type-Options": "nosniff"})
