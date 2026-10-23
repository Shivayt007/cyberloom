"""Cyberloom Link Inspector — single-user, password-protected Playwright website."""
from __future__ import annotations

import asyncio
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
        if p.scheme not in ("http", "https") or not p.hostname or p.hostname.lower() not in ALLOWED_START:
            raise ValueError(f"Only these start domains are allowed: {', '.join(sorted(ALLOWED_START))}")
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


async def click_continue(page) -> bool:
    selector = (
        "button:visible, a:visible, input[type=button]:visible, input[type=submit]:visible, "
        "[role=button]:visible"
    )
    pattern = re.compile(r"\b(continue|proceed|get\s*link|open\s*link|next\s*step)\b", re.I)
    for frame in page.frames:
        try:
            matches = frame.locator(selector).filter(has_text=pattern)
            # Playwright input elements may not have textContent: check their value below.
            count = min(await matches.count(), 12)
            for i in range(count):
                btn = matches.nth(i)
                if await btn.is_enabled():
                    await btn.click(timeout=2000)
                    return True
            inputs = frame.locator("input[value]:visible")
            for i in range(min(await inputs.count(), 12)):
                el = inputs.nth(i)
                if pattern.search((await el.get_attribute("value")) or "") and await el.is_enabled():
                    await el.click(timeout=2000)
                    return True
        except (PlaywrightError, asyncio.TimeoutError):
            continue
    return False


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

        async def public_only(route):
            parsed = urlsplit(route.request.url)
            if parsed.scheme not in ("http", "https"):
                await route.abort()
            elif await can_request_public(parsed.hostname or "", dns_cache):
                await route.continue_()
            else:
                await route.abort()

        await context.route("**/*", public_only)
        page = await context.new_page()
        try:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=25000)
            except PlaywrightTimeout:
                yield event("log", level="warn", message="Initial navigation timed out; checking available pages")
            yield event("stage", step=1, status="done", detail="Browser launched")
            yield event("stage", step=2, status="active", detail="Waiting for countdown / Continue")
            last_seen = ""
            last_click = 0.0
            click_count = 0
            chosen = None
            while time.monotonic() < deadline:
                pages = [p for p in context.pages if not p.is_closed()]
                chosen = next((p for p in pages if target_url(p.url)), None)
                if chosen:
                    break
                best = next((p for p in reversed(pages) if p.url not in ("about:blank", "chrome-error://chromewebdata/")), page)
                if best.url != last_seen:
                    if last_seen:
                        yield event("log", level="info", message=f"Navigation: {best.url}")
                    if best.url not in visited:
                        visited.append(best.url)
                    last_seen = best.url
                now = time.monotonic()
                if now - last_click >= 4 and click_count < 12:
                    if await click_continue(best):
                        click_count += 1
                        last_click = now
                        yield event("log", level="info", message=f"Clicked Continue / Proceed (attempt {click_count})")
                if (int(now - started) % 10 == 0) and now - started > 1:
                    pass
                await asyncio.sleep(1)
            if not chosen:
                yield event("stage", step=2, status="error", detail="Target destination was not reached")
                yield event("error", message=f"MessyCloud was not reached within {timeout}s. The site may require a manual CAPTCHA, an extra button, or could be blocking automation.", visited=visited)
                return
            current_url = chosen.url
            if current_url not in visited:
                visited.append(current_url)
            yield event("stage", step=2, status="done", detail="Redirect completed")
            yield event("stage", step=3, status="done", detail="Verified MessyCloud destination")
            yield event("log", level="success", message=f"Destination found: {current_url}")
            yield event("destination", url=current_url, visited=visited)
            yield event("stage", step=4, status="active", detail="Watching links appear")
            found: dict[str, dict] = {}
            settle_until = min(deadline, time.monotonic() + settle)
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
