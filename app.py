"""Cyberloom Link Inspector — single-user, password-protected Playwright website."""
from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import json
import os
import re
import socket
import time
from contextlib import suppress
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
import aiohttp
from aiohttp.abc import AbstractResolver
from playwright.async_api import async_playwright, Error as PlaywrightError, TimeoutError as PlaywrightTimeout

ROOT = Path(__file__).parent
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
START_TIMES = deque()
PER_CLIENT_STARTS: dict[str, deque] = {}
MAX_BATCH_LINKS = 8
MAX_GLOBAL_STARTS_PER_HOUR = 35
MAX_CLIENT_STARTS_PER_HOUR = 12
MAX_SOURCE_BYTES = 2_000_000


class InspectRequest(BaseModel):
    url: str = Field(min_length=12, max_length=2048)
    timeout: int = Field(default=120, ge=30, le=180)
    settle: int = Field(default=12, ge=3, le=25)
    live: bool = Field(default=True)


def target_url(url: str) -> bool:
    try:
        p = urlsplit(url)
        return p.scheme in ("http", "https") and p.hostname and p.hostname.lower() in TARGET_HOSTS
    except ValueError:
        return False


def basic_public_url(url: str) -> str:
    """Validate the source webpage URL before network access."""
    value = url.strip()
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ("https", "http") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 80, 443)
                or len(value) > 2048):
            raise ValueError("Enter a public http(s) URL (ports 80/443 only)")
        host = parsed.hostname.lower().strip(".")
        if host == "localhost" or host.endswith((".local", ".internal")):
            raise ValueError("Private/local addresses are not supported")
        try:
            numeric = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not numeric.is_global:
                raise ValueError("Private/nonpublic IP address rejected")
        return value
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def is_short_link(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme in ("http", "https")
                and (parsed.hostname or "").lower() in ALLOWED_START
                and parsed.path.startswith("/l/") and len(parsed.path) > 3)
    except ValueError:
        return False


def validate_start(url: str) -> str:
    """Only known destination hosts run in Playwright."""
    value = basic_public_url(url)
    if not (is_short_link(value) or target_url(value)):
        raise HTTPException(status_code=400, detail="Only Cyberloom /l/ and MessyCloud URLs can be inspected directly")
    return value


class CyberloomFinder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.candidates: list[str] = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if value and key in (
                "href", "data-url", "data-href", "data-link", "data-target",
                "data-download-url", "content"
            ):
                self.candidates.append(value)


CYBERLOOM_SHORT_PATTERN = re.compile(
    r'(?:https?:)?//(?:www\.)?cyberloom\.best/l/'
    r'[A-Za-z0-9_%\-]+(?:\?[A-Za-z0-9_%&=+\-./]*)?',
    re.I
)


def discover_cyberloom_links(markup: str) -> list[str]:
    """Find unique Cyberloom /l/ links in static HTML, attributes and text."""
    parser = CyberloomFinder()
    with suppress(ValueError):
        parser.feed(markup)
    found: dict[str, None] = {}
    candidates = parser.candidates + [
        markup.replace("\\/", "/"), html.unescape(markup)
    ]
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        cleaned = html.unescape(candidate.replace("\\/", "/"))
        for match in CYBERLOOM_SHORT_PATTERN.finditer(cleaned):
            raw = match.group(0).rstrip(".,;)")
            if raw.startswith("//"):
                raw = "https:" + raw
            try:
                parsed = urlsplit(raw)
                normalized = parsed._replace(scheme="https", fragment="").geturl()
            except ValueError:
                continue
            if is_short_link(normalized):
                found.setdefault(normalized, None)
                if len(found) >= MAX_BATCH_LINKS:
                    return list(found)
    return list(found)


class SourcePageMetadataParser(HTMLParser):
    """Extract the forum post title and primary thumbnail from source HTML.

    Target the nested title span inside h1.ipsType_pageTitle, rather than
    unrelated badge text. Prefer img.ipsImage_thumbnailed; keep OG metadata
    as fallback for pages using another layout.
    """
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img",
                 "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.stack: list[tuple[str, set[str]]] = []
        self.active_depth: int | None = None
        self.title_parts: list[str] = []
        self.title = ""
        self.poster_url = ""
        self.poster_alt = ""
        self.og_title = ""
        self.og_image = ""

    def image_url(self, raw: str) -> str:
        if not raw:
            return ""
        resolved = urljoin(self.base_url, html.unescape(raw.strip()))
        try:
            parsed = urlsplit(resolved)
            if (parsed.scheme in ("http", "https") and parsed.hostname
                    and parsed.username is None and parsed.password is None
                    and parsed.port in (None, 80, 443)
                    and len(resolved) <= 2048):
                return resolved
        except ValueError:
            pass
        return ""

    def handle_starttag(self, tag: str, attrs) -> None:
        props = dict(attrs)
        classes = set((props.get("class") or "").split())
        if tag == "meta":
            property_name = (props.get("property") or props.get("name") or "").lower()
            if property_name in ("og:title", "twitter:title") and not self.og_title:
                self.og_title = props.get("content") or ""
            if property_name in ("og:image", "twitter:image") and not self.og_image:
                self.og_image = self.image_url(props.get("content") or "")
        if tag == "img" and "ipsImage_thumbnailed" in classes and not self.poster_url:
            self.poster_url = self.image_url(
                props.get("src") or props.get("data-src") or ""
            )
            self.poster_alt = (props.get("alt") or "")[:200]
        if (tag == "span" and self.active_depth is None
                and self.stack
                and self.stack[-1][0] == "span"
                and {"ipsType_break", "ipsContained"}.issubset(self.stack[-1][1])
                and any(item_tag == "h1" and "ipsType_pageTitle" in item_classes
                        for item_tag, item_classes in self.stack)):
            self.active_depth = len(self.stack) + 1
            self.title_parts = []
        if tag not in self.VOID_TAGS:
            self.stack.append((tag, classes))

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID_TAGS:
            self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self.active_depth is not None:
            self.title_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack:
            return
        index = next((i for i in range(len(self.stack)-1, -1, -1)
                      if self.stack[i][0] == tag), None)
        if index is None:
            return
        if self.active_depth is not None and index < self.active_depth:
            candidate = " ".join(" ".join(self.title_parts).split())
            if candidate and not self.title:
                self.title = html.unescape(candidate)[:700]
            self.active_depth = None
            self.title_parts = []
        del self.stack[index:]

    def result(self) -> dict[str, str]:
        title = self.title or " ".join(self.og_title.split())[:700]
        poster = self.poster_url or self.og_image
        return {"title": title, "poster_url": poster,
                "poster_alt": self.poster_alt}


def extract_source_metadata(markup: str, base_url: str) -> dict[str, str]:
    parser = SourcePageMetadataParser(base_url)
    with suppress(ValueError):
        parser.feed(markup)
    return parser.result()


class PublicOnlyResolver(AbstractResolver):
    """Resolve each source host to publicly routable addresses only.

    aiohttp connects to the returned IPs, rather than performing a second
    unchecked DNS lookup after validation (DNS-rebinding protection).
    """

    async def resolve(self, host: str, port: int = 0,
                      family: int = socket.AF_UNSPEC):
        try:
            entries = await asyncio.wait_for(
                asyncio.to_thread(
                    socket.getaddrinfo, host, port, family,
                    socket.SOCK_STREAM
                ),
                timeout=3
            )
            records = []
            for af, socktype, proto, name, addr in entries:
                ip = ipaddress.ip_address(addr[0].split("%")[0])
                if not ip.is_global:
                    raise OSError("Private or nonpublic source DNS address rejected")
                records.append({
                    "hostname": host, "host": str(ip), "port": port,
                    "family": af, "proto": proto, "flags": socket.AI_NUMERICHOST
                })
            if not records:
                raise OSError("No public DNS results for source website")
            return records
        except (OSError, ValueError, asyncio.TimeoutError) as exc:
            raise OSError(f"Source website host cannot be resolved safely: {exc}") from exc

    async def close(self):
        pass


async def discover_from_website(url: str) -> tuple[list[str], str, dict[str, str]]:
    """HTML-only discovery, 2MB max, public DNS only, <=3 redirects."""
    current = basic_public_url(url)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CyberloomLinkInspector/2.0)",
        "Accept": "text/html,text/plain;q=0.8,*/*;q=0.2",
    }
    connector = aiohttp.TCPConnector(
        resolver=PublicOnlyResolver(), use_dns_cache=False, limit=2
    )
    timeout = aiohttp.ClientTimeout(total=25, connect=8, sock_read=12)
    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout,
        trust_env=False, headers=headers
    ) as client:
        for hop in range(4):
            basic_public_url(current)
            async with client.get(current, allow_redirects=False) as response:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("Source redirect has no Location header")
                    current = urljoin(current, location)
                    continue
                response.raise_for_status()
                content_type = response.headers.get("content-type", "").lower()
                if content_type and not any(
                    item in content_type for item in (
                        "text/html", "text/plain", "application/xhtml"
                    )
                ):
                    raise ValueError("Source is not an HTML/text webpage")
                chunks = bytearray()
                async for part in response.content.iter_chunked(65536):
                    chunks.extend(part)
                    if len(chunks) > MAX_SOURCE_BYTES:
                        raise ValueError("Source exceeds the 2 MB discovery limit")
                markup = chunks.decode("utf-8", errors="replace")
                return (discover_cyberloom_links(markup), current,
                        extract_source_metadata(markup, current))
    raise ValueError("Source redirected more than three times")


def enforce_public_rate_limit(client_id: str) -> None:
    """Basic single-instance limits for the password-free public website."""
    now = time.monotonic()
    while START_TIMES and now - START_TIMES[0] > 3600:
        START_TIMES.popleft()
    if len(START_TIMES) >= MAX_GLOBAL_STARTS_PER_HOUR:
        raise HTTPException(status_code=429, detail="Scanner hourly capacity reached. Try again later.")
    starts = PER_CLIENT_STARTS.setdefault(client_id, deque())
    while starts and now - starts[0] > 3600:
        starts.popleft()
    if len(starts) >= MAX_CLIENT_STARTS_PER_HOUR:
        raise HTTPException(status_code=429, detail="Hourly scan limit reached for this visitor.")
    starts.append(now)
    START_TIMES.append(now)


def event(event_type: str, **data) -> bytes:
    return (json.dumps({"type": event_type, "time": time.strftime("%H:%M:%S"), **data}, ensure_ascii=False) + "\n").encode()


def is_m1_direct_label(label: str) -> bool:
    """Recognize a visible [M1] DIRECT server button."""
    return bool(re.search(r"\[?\s*m1\s*\]?\s*direct\b", label or "", re.I))


def link_score(url: str, label: str = "") -> str:
    if is_m1_direct_label(label):
        return "M1 DIRECT"
    if re.search(r"\[\s*m\d+\s*\]", label or "", re.I):
        return "Server link"
    parsed = urlsplit(url)
    if (parsed.hostname == "cdn.juicybits.site"
            or re.search(r"\.(?:zip|mp4|mkv|rar|7z|pdf|avi|webm)(?:$|[?#])",
                         parsed.path, re.I)):
        return "Direct file"
    if any(k in url.lower() for k in SUSPICIOUS_LINK_KEYS):
        return "Likely download"
    return "Other link"


def public_link_for_log(url: str) -> str:
    """Do not echo signed CDN tokens in terminal logs."""
    try:
        parsed = urlsplit(url)
        return parsed._replace(
            query="[signed parameters hidden]" if parsed.query else "",
            fragment=""
        ).geturl()
    except ValueError:
        return "[unavailable URL]"


def collect_candidate(url: str, text: str, base: str,
                      out: dict[str, dict]) -> None:
    if not isinstance(url, str) or not url:
        return
    # Decode HTML entities once; e.g. token=x&amp;exp=y becomes token=x&exp=y.
    raw = html.unescape(url.strip()).replace("\\/", "/")
    if raw.lower().startswith(("#", "javascript:", "data:", "mailto:",
                                "tel:", "blob:")):
        return
    full = urljoin(base, raw)
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
    label = (text or "").strip()[:100] or parsed.hostname
    kind = link_score(full, label)
    old = out.get(full)
    priority = {"M1 DIRECT": 0, "Server link": 1, "Direct file": 2,
                "Likely download": 3, "Other link": 4}
    if old:
        if priority.get(kind, 9) < priority.get(old["kind"], 9):
            out[full] = {"url": full, "label": label, "kind": kind}
        return
    if len(out) < 250:
        out[full] = {"url": full, "label": label, "kind": kind}


def visible_download_link(label: str, href: str) -> bool:
    """Identify a download URL embedded in JS/HTML without fetching files."""
    if re.search(r"\[\s*m\d+\s*\]|download|direct|server", label or "", re.I):
        return True
    try:
        parsed = urlsplit(href)
    except ValueError:
        return False
    return (
        parsed.hostname == "cdn.juicybits.site"
        or bool(re.search(r"\.(?:zip|mp4|mkv|rar|7z|pdf|avi|webm)$",
                          parsed.path, re.I))
        or "/files/" in parsed.path.lower()
    )


async def extract_links(page) -> list[dict]:
    """Read all navigable URLs offered by the final MessyCloud page.

    Extract links from the page and accessible iframe DOMs, including
    visible download server buttons, other anchors, data-* URL attributes,
    and file URLs embedded in scripts/onclick. Don't click or download files.
    """
    found: dict[str, dict] = {}
    for frame in page.frames:
        try:
            # A user-provided example uses:
            # <a class="download-btn" href="https://cdn.juicybits.site/files/...
            # ?token=...&amp;exp=...">[M1] DIRECT</a>.
            items = await frame.evaluate("""() => {
                const attrs = ['href', 'data-download-url', 'data-url',
                    'data-href', 'data-link', 'data-download', 'data-target',
                    'data-file', 'data-src'];
                const elements = Array.from(document.querySelectorAll(
                    'a[href], button, [role="button"], [onclick], ' +
                    '[data-download-url], [data-url], [data-href], [data-link],' +
                    '[data-download], [data-target], [data-file], [data-src]'
                )).slice(0, 1200);
                const out = [];
                for (const el of elements) {
                    const parent = el.closest('a,button,[role="button"]') || el;
                    const label = (parent.innerText || parent.textContent ||
                        parent.getAttribute('aria-label') || '')
                        .trim().replace(/\\s+/g, ' ').slice(0, 100);
                    for (const key of attrs) {
                        const value = el.getAttribute(key);
                        if (value) out.push({url: value, label});
                    }
                    const clickCode = el.getAttribute('onclick') || '';
                    const matches = clickCode.match(/https?:\\/\\/[^\\s"'<>\\\\]+/g) || [];
                    for (const url of matches.slice(0, 12)) {
                        out.push({url, label: label || 'Onclick URL'});
                    }
                }
                return out.slice(0, 1800);
            }""")
            for item in items:
                collect_candidate(item.get("url", ""), item.get("label", ""),
                                  frame.url, found)

            # Some download links are embedded in inline JS or in a
            # pre-rendered HTML attribute. Only capture download-looking
            # URLs from raw markup to avoid collecting stylesheet/tracker URLs.
            markup = await frame.content()
            for match in re.findall(r'https?://[^\s"\'<>\\]+', markup):
                url = html.unescape(match).rstrip(');,}')
                if visible_download_link("", url):
                    collect_candidate(url, "Embedded file URL", frame.url,
                                      found)
        except (PlaywrightError, ValueError):
            continue
    priority = {"M1 DIRECT": 0, "Server link": 1, "Direct file": 2,
                "Likely download": 3, "Other link": 4}
    return sorted(found.values(), key=lambda link:
                  (priority.get(link["kind"], 9), link["label"].lower(),
                   link["url"]))


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
    """Activate visible Continue controls using normal browser clicks.

    Try the interactive parent before text spans. If the locator's actionability
    check times out, make one physical Playwright mouse click only when
    hit-testing confirms the actual CTA is unobstructed. Do not force-click
    through an overlay or verification challenge.
    """
    if await needs_human_verification(page):
        return False, "Human verification present; automatic clicks are disabled"

    specific = re.compile(r"continue\s+to\s+destination", re.I)
    generic = re.compile(r"\b(continue|proceed|get\s*link|open\s*link|next\s*step)\b", re.I)
    errors: list[str] = []

    def why_click_failed(exc: Exception) -> str:
        detail = str(exc)
        for needle, summary in (
            ("intercepts pointer events", "another element intercepts pointer events"),
            ("element is not stable", "element is moving or animating"),
            ("element is outside of the viewport", "control is outside the viewport"),
            ("Element is not attached", "control was replaced in the page"),
            ("element is not enabled", "control is disabled"),
        ):
            if needle.lower() in detail.lower():
                return summary
        return detail.splitlines()[0][:120] if detail else "click failed"

    async def try_click(control, label: str) -> tuple[bool, str] | None:
        try:
            if not await control.is_visible() or not await control.is_enabled():
                return None
        except (PlaywrightError, PlaywrightTimeout):
            return None

        before_url = page.url
        before_tabs = len(page.context.pages)
        try:
            # More time than the former 2300ms; the target can be animating.
            await control.click(timeout=1600)
            return True, label + " · normal click"
        except (PlaywrightError, PlaywrightTimeout) as exc:
            # A slow redirect/pop-up may already have been triggered.
            if page.url != before_url or len(page.context.pages) > before_tabs:
                return True, label + " · navigation triggered"

            reason = why_click_failed(exc)
            # Playwright locator.click can time out if a transform never
            # becomes stable. In that case use the browser's real mouse, but
            # only if the intended Continue control receives the pointer.
            try:
                info = await control.evaluate("""el => {
                    const r = el.getBoundingClientRect();
                    const x = r.left + r.width / 2;
                    const y = r.top + r.height / 2;
                    const hit = document.elementFromPoint(x, y);
                    const owner = el.closest(
                        'a,button,[role="button"],[onclick],[tabindex]'
                    );
                    const safe = !!hit && (
                        hit === el || el.contains(hit) ||
                        (!!owner && (hit === owner || owner.contains(hit)))
                    );
                    const hs = hit ? getComputedStyle(hit) : null;
                    const hr = hit ? hit.getBoundingClientRect() : null;
                    const blocker = !safe && hit ? {
                        tag: hit.tagName.toLowerCase(),
                        id: (hit.id || "").slice(0, 60),
                        class: String(hit.className || "").slice(0, 100),
                        position: hs.position,
                        zIndex: hs.zIndex,
                        pointerEvents: hs.pointerEvents,
                        opacity: hs.opacity,
                        ariaLabel: (hit.getAttribute("aria-label") || "").slice(0, 60),
                        role: (hit.getAttribute("role") || "").slice(0, 35),
                        text: (hit.innerText || "").trim().slice(0, 85),
                        bounds: hr ? {
                            width: Math.round(hr.width),
                            height: Math.round(hr.height)
                        } : null
                    } : null;
                    return {
                        safe,
                        tag: el.tagName.toLowerCase(),
                        hit: hit ? hit.tagName.toLowerCase() : "none",
                        blocker,
                        centerVisible: x >= 0 && y >= 0 &&
                            x < window.innerWidth && y < window.innerHeight
                    };
                }""", timeout=1200)
                box = await control.bounding_box(timeout=1200)
                if info.get("safe") and info.get("centerVisible") and box:
                    if box["width"] >= 3 and box["height"] >= 3:
                        # Frame element coordinates are already mapped to the
                        # main viewport by Playwright's bounding_box().
                        await page.mouse.click(
                            box["x"] + box["width"] / 2,
                            box["y"] + box["height"] / 2,
                        )
                        return True, label + " · verified unobstructed mouse click"
                blocker = info.get("blocker")
                if blocker:
                    errors.append(label + ": " + reason + "; blocker=" +
                                  json.dumps(blocker, ensure_ascii=False)[:330])
                else:
                    errors.append(label + ": " + reason +
                                  "; center not reachable (tag " +
                                  str(info.get("tag")) + ")")
            except (PlaywrightError, PlaywrightTimeout) as detail_exc:
                errors.append(label + ": " + reason + " · hit-test: " +
                              why_click_failed(detail_exc))
            return None

    for frame in page.frames:
        # Prioritize clickable elements; clicking a text-only span can cause
        # Playwright to wait on a non-interactive child rather than its parent.
        groups = [
            ("destination link", frame.get_by_role("link", name=specific)),
            ("destination button", frame.get_by_role("button", name=specific)),
            ("destination clickable", frame.locator(
                'a:visible,button:visible,[role="button"]:visible,'
                '[onclick]:visible,[tabindex]:visible'
            ).filter(has_text=specific)),
            ("destination text", frame.get_by_text(specific)),
        ]
        found_specific = False
        for label, group in groups:
            try:
                count = min(await group.count(), 3)
            except (PlaywrightError, PlaywrightTimeout):
                continue
            if count:
                found_specific = True
            # Prefer the innermost matching text target after interactive groups.
            for i in reversed(range(count)):
                result = await try_click(group.nth(i), label)
                if result and result[0]:
                    return result
                if errors:
                    return False, errors[-1]

        if found_specific:
            continue

        # Generic Continue controls for other steps in the chain.
        group = frame.locator(
            'a:visible,button:visible,[role="button"]:visible,'
            '[onclick]:visible,[tabindex]:visible'
        ).filter(has_text=generic)
        try:
            count = min(await group.count(), 4)
            for i in reversed(range(count)):
                result = await try_click(group.nth(i), "Continue")
                if result and result[0]:
                    return result
                if errors:
                    return False, errors[-1]
        except (PlaywrightError, PlaywrightTimeout):
            pass

    if errors:
        return False, " | ".join(errors[:2])[:460]
    return False, "No actionable Continue control detected"


def validated_continue_url(url: str) -> bool:
    """Only allow the regular Cyberloom /out destination URL.

    The query token is read from the rendered link, never forged or guessed.
    Neither arbitrary URLs nor alternate ports are accepted.
    """
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and (parsed.hostname or "").lower()
                in {"www.cyberloom.best", "cyberloom.best"}
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
            and parsed.path == "/out"
            and bool(parse_qs(parsed.query).get("t", [""])[0])
        )
    except ValueError:
        return False


async def ready_continue_href(page) -> str | None:
    """Read the ordinary #cta href after the page displays Ready!.

    We follow the page's own validated anchor URL with Chromium; no CAPTCHA,
    client-side verification result, or token is forged.
    """
    for frame in page.frames:
        try:
            ready = frame.get_by_role("heading", name=re.compile(r"^ready!$", re.I))
            if not await ready.count() or not await ready.first.is_visible():
                continue
            links = frame.locator("a#cta[href]")
            for i in range(min(await links.count(), 3)):
                anchor = links.nth(i)
                if not await anchor.is_visible() or not await anchor.is_enabled():
                    continue
                label = (await anchor.inner_text(timeout=700)).strip()
                if not re.search(r"continue\s+to\s+destination", label, re.I):
                    continue
                href = await anchor.get_attribute("href", timeout=700)
                if not href:
                    continue
                resolved = urljoin(frame.url, href)
                if validated_continue_url(resolved):
                    return resolved
        except (PlaywrightError, PlaywrightTimeout, ValueError):
            continue
    return None


async def close_visible_verification_popup(page) -> tuple[bool, str]:
    """Use a popup's visible close/X control, if one exists.

    This is a normal user-facing dismissal, not CAPTCHA completion.
    Never delete overlay nodes, disable pointer events, force a click or
    click the obscured Continue link through a verification layer.
    """
    modal_selectors = (
        '[role="dialog"], [aria-modal="true"], .modal, .popup, '
        '.dialog, .verification-modal, .signin-modal'
    )
    close_selectors = (
        'button[aria-label*="close" i], [role="button"][aria-label*="close" i], '
        '[title*="close" i], [data-dismiss="modal"], [data-bs-dismiss="modal"], '
        '.modal-close, .popup-close, .close-modal, .close-button, '
        '.modal .close, .popup .close, [role="dialog"] .close, '
        'button:has-text("×"), button:has-text("✕"), '
        'button:has-text("✖")'
    )
    saw_popup = False
    for frame in page.frames:
        try:
            body_text = (await frame.locator("body").inner_text(timeout=900)).lower()
        except (PlaywrightError, PlaywrightTimeout):
            continue
        has_verification_text = any(
            marker in body_text for marker in (
                "verify you're human", "verify you’re human", "i'm human",
                "i’m human", "sign in", "human verification"
            )
        )
        modal = frame.locator(modal_selectors)
        try:
            count = min(await modal.count(), 6)
            visible_modals = []
            for i in range(count):
                block = modal.nth(i)
                if await block.is_visible():
                    visible_modals.append(block)
        except (PlaywrightError, PlaywrightTimeout):
            visible_modals = []
        if not has_verification_text and not visible_modals:
            continue
        saw_popup = True

        # Prefer an actual modal's controls. A global close selector is only
        # permitted if the page visibly contains verification/sign-in text.
        roots = visible_modals[:]
        if has_verification_text:
            roots.append(frame.locator("body"))
        for root in roots:
            buttons = root.locator(close_selectors)
            try:
                count = min(await buttons.count(), 12)
            except (PlaywrightError, PlaywrightTimeout):
                continue
            for index in range(count):
                close = buttons.nth(index)
                try:
                    if not await close.is_visible() or not await close.is_enabled():
                        continue
                    tag = await close.evaluate("el => el.tagName.toLowerCase()", timeout=800)
                    # Playwright checks visibility, overlays and hit-testing:
                    # a blocked close is NOT force-clicked.
                    await close.click(timeout=2200)
                    await asyncio.sleep(0.4)
                    still_challenged = await needs_human_verification(page)
                    if still_challenged:
                        return True, "Clicked popup close <" + tag + ">; verification may still be active"
                    return True, "Dismissed verification/sign-in popup via close <" + tag + ">"
                except (PlaywrightError, PlaywrightTimeout):
                    continue
    if saw_popup:
        return False, "Verification popup detected, but no accessible/receiving close control"
    return False, "No visible verification popup or close control found"


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
        or is_m1_direct_label(body)
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
                .filter(el => visible(el) && /continue\s+to\s+destination/i.test(
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


async def inspect(url: str, timeout: int, settle: int, live: bool = True):
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
            popup_close_attempts = set()
            followed_continue_hrefs: set[str] = set()
            last_stackmint_url = None
            stackmint_since = None
            snapshot_sent = False
            next_live_capture = 0.0
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
                    # Only try a real, visible X/Close action once for each
                    # tab and URL. The popup may legitimately be dismissible.
                    key = (challenged, challenged.url)
                    if key not in popup_close_attempts:
                        popup_close_attempts.add(key)
                        dismissed, details = await close_visible_verification_popup(challenged)
                        yield event("log", level="info" if dismissed else "warn",
                                    message=details)
                        if dismissed:
                            verification_page = None
                            verification_since = None
                            continue
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
                # Near-live view: capture a small compressed JPEG every ~2.5s.
                # The existing authenticated NDJSON stream carries these frames;
                # nothing is saved on disk. This is a passive view, not remote control.
                if live and now >= next_live_capture:
                    next_live_capture = now + 2.5
                    watched = next(
                        (tab for tab in reversed(pages)
                         if (urlsplit(tab.url).hostname or "").lower()
                         in (ALLOWED_START | REDIRECT_HOSTS | TARGET_HOSTS)),
                        page
                    )
                    if watched and not watched.is_closed():
                        capture = await preview_image(watched)
                        if capture:
                            yield event("frame", image=capture, url=watched.url,
                                        tab=pages.index(watched) + 1,
                                        elapsed=round(time.monotonic() - started, 1))
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
                followed_anchor = False
                for tab in candidates:
                    # Prefer the site's actual published href once "Ready!" is
                    # visible. On Stackmint/Inkvoyage a fullscreen advertising
                    # div can intercept clicks although the real #cta link is
                    # already available. We do not remove or click through it.
                    host = (urlsplit(tab.url).hostname or "").lower()
                    if host not in REDIRECT_HOSTS:
                        continue
                    if await needs_human_verification(tab):
                        continue
                    href = await ready_continue_href(tab)
                    if not href or href in followed_continue_hrefs:
                        continue
                    followed_continue_hrefs.add(href)
                    yield event("log", level="info",
                                message=f"Ready! Found validated #cta link on tab #{pages.index(tab)+1}: {href}")
                    try:
                        await tab.goto(href, wait_until="domcontentloaded", timeout=18000)
                        yield event("log", level="success",
                                    message=f"Followed Continue URL; browser now at {tab.url}")
                    except PlaywrightTimeout:
                        yield event("log", level="warn",
                                    message=f"Continue URL navigation timed out; browser now at {tab.url}")
                    except PlaywrightError as exc:
                        yield event("log", level="warn",
                                    message=f"Continue URL navigation error: {str(exc).splitlines()[0][:180]}")
                    last_click_by_tab[tab] = time.monotonic()
                    followed_anchor = True
                    break
                if followed_anchor:
                    await asyncio.sleep(1)
                    continue
                for tab in candidates:
                    if click_count_by_tab.get(tab, 0) >= 12:
                        continue
                    if now - last_click_by_tab.get(tab, 0) < 5:
                        continue
                    clicked, click_detail = await click_continue(tab)
                    if not clicked and "blocker=" in click_detail:
                        # If a popup overlays a Ready button, click its
                        # ordinary close button rather than clicking through.
                        key = (tab, tab.url)
                        if key not in popup_close_attempts:
                            popup_close_attempts.add(key)
                            dismissed, details = await close_visible_verification_popup(tab)
                            yield event("log", level="info" if dismissed else "warn",
                                        message=details)
                            if dismissed:
                                last_click_by_tab[tab] = time.monotonic()
                                continue
                    # Throttle failures too, so Playwright screenshot streaming
                    # stays responsive while an overlay blocks the control.
                    last_click_by_tab[tab] = time.monotonic()
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
                                        message=f"Tab #{pages.index(tab)+1}: {click_detail[:620]}")
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
                if live and time.monotonic() >= next_live_capture and not chosen.is_closed():
                    next_live_capture = time.monotonic() + 2.5
                    capture = await preview_image(chosen)
                    if capture:
                        yield event("frame", image=capture, url=chosen.url,
                                    tab=context.pages.index(chosen) + 1,
                                    elapsed=round(time.monotonic() - started, 1))
                for link in await extract_links(chosen):
                    existing = found.get(link["url"])
                    if existing == link:
                        continue
                    found[link["url"]] = link
                    yield event("link", **link)
                    if link["kind"] == "M1 DIRECT":
                        yield event("log", level="success",
                                    message="Found M1 DIRECT CDN URL (signed parameters preserved for Copy)")
                    yield event("log", level="success",
                                message=f"Found {link['kind']}: {public_link_for_log(link['url'])[:180]}")
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


@app.post("/api/discover")
async def discover_api(body: InspectRequest, request: Request):
    """Short request: discover Cyberloom URLs separately from long scans."""
    safe_url = basic_public_url(body.url)
    enforce_public_rate_limit(request.client.host if request.client else "unknown")
    try:
        if is_short_link(safe_url) or target_url(safe_url):
            return {"links": [validate_start(safe_url)], "source": safe_url,
                    "total": 1, "max_batch": MAX_BATCH_LINKS,
                    "metadata": {"title": "", "poster_url": "", "poster_alt": ""}}
        links, final_page, metadata = await discover_from_website(safe_url)
        return {"links": links, "source": final_page,
                "metadata": metadata, "total": len(links),
                "max_batch": MAX_BATCH_LINKS}
    except (aiohttp.ClientError, OSError, ValueError,
            asyncio.TimeoutError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Source discovery failed: {str(exc)[:210]}"
        ) from exc


@app.post("/api/inspect")
async def inspect_api(body: InspectRequest, request: Request):
    source_url = basic_public_url(body.url)
    if RUN_LOCK.locked():
        raise HTTPException(
            status_code=429, detail="Another scan is running. Retry when it finishes."
        )
    client_id = request.client.host if request.client else "unknown"
    enforce_public_rate_limit(client_id)

    async def feed():
        async with RUN_LOCK:
            processed = completed = failed = 0
            try:
                if is_short_link(source_url) or target_url(source_url):
                    links = [validate_start(source_url)]
                    yield event("log", level="info",
                                message="Direct link: skipping webpage discovery")
                else:
                    yield event("stage", step=1, status="active",
                                detail="Discovering Cyberloom links")
                    yield event("log", level="info",
                                message=f"Searching source webpage {public_link_for_log(source_url)[:220]}")
                    links, effective_source, metadata = await discover_from_website(source_url)
                    yield event("source_metadata", **metadata)
                    yield event("log", level="info",
                                message=f"Source inspected: {public_link_for_log(effective_source)[:220]}")
                    yield event("stage", step=1, status="done",
                                detail=f"Found {len(links)} Cyberloom links")

                yield event("discovered", links=links, total=len(links),
                            max_batch=MAX_BATCH_LINKS)
                if not links:
                    yield event("log", level="warn",
                                message="No Cyberloom /l/ links in source HTML. Pages generating links only with JavaScript may require a direct Cyberloom URL.")
                    yield event("batch_done", total=0, completed=0, failed=0)
                    return

                for index, link in enumerate(links, 1):
                    if await request.is_disconnected():
                        return
                    processed += 1
                    yield event("item_start", index=index, total=len(links),
                                source=link)
                    succeeded = False
                    encountered_error = False
                    try:
                        async for payload in inspect(link, body.timeout, body.settle,
                                                     body.live):
                            if await request.is_disconnected():
                                return
                            parsed = json.loads(payload)
                            parsed.update(source=link, index=index,
                                          total=len(links))
                            typ = parsed.get("type")
                            if typ == "done":
                                succeeded = True
                                parsed["type"] = "item_done"
                            elif typ == "error":
                                encountered_error = True
                                parsed["type"] = "item_error"
                            yield (json.dumps(parsed, ensure_ascii=False) + "\n").encode()
                    except Exception as exc:
                        encountered_error = True
                        yield event("item_error", source=link, index=index,
                                    total=len(links),
                                    message=f"Unexpected inspection error: {type(exc).__name__}")
                    if succeeded:
                        completed += 1
                    else:
                        failed += 1
                        if not encountered_error:
                            yield event("item_error", source=link, index=index,
                                        total=len(links),
                                        message="This Cyberloom link did not complete.")
                    yield event("item_finish", source=link, index=index,
                                total=len(links), success=succeeded)
                yield event("batch_done", total=processed,
                            completed=completed, failed=failed)
            except (aiohttp.ClientError, OSError, ValueError, HTTPException, asyncio.TimeoutError) as exc:
                yield event("error", message=f"Unable to discover Cyberloom links: {str(exc)[:220]}")
            except Exception as exc:
                yield event("error", message=f"Unexpected scanner error: {type(exc).__name__}")

    return StreamingResponse(
        feed(), media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no",
                 "X-Content-Type-Options": "nosniff"}
    )
