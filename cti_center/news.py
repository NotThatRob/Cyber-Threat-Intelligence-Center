"""RSS feed client for fetching security news articles."""

import logging
import re
import time
import urllib.parse
import urllib.robotparser
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from time import mktime

import feedparser
import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "CTI-Center/0.1 (vulnerability-aggregator)"

RSS_FEEDS: dict[str, str] = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
}

# Match CVE IDs case-insensitively with Unicode hyphen support.
# Hyphens: ASCII dash, Unicode dashes U+2010-U+2015, minus sign U+2212.
_CVE_PATTERN = re.compile(
    r"\bCVE[-\u2010-\u2015\u2212]\d{4}[-\u2010-\u2015\u2212]\d{4,7}\b",
    re.IGNORECASE,
)

_CURRENT_YEAR = datetime.now(timezone.utc).year

# Minimum seconds between full-page fetches (ethical scraping).
PAGE_FETCH_DELAY = 2.0

# Tags whose text content should be ignored when extracting from HTML.
_SKIP_TAGS = frozenset({"script", "style", "head", "noscript", "template"})


class _TextExtractor(HTMLParser):
    """HTMLParser subclass that extracts visible text, skipping scripts/styles."""

    def __init__(self):
        super().__init__()
        self._pieces: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._pieces.append(data)

    def handle_entityref(self, name):
        if self._skip_depth == 0:
            self._pieces.append(f"&{name};")

    def handle_charref(self, name):
        if self._skip_depth == 0:
            try:
                if name.startswith(("x", "X")):
                    self._pieces.append(chr(int(name[1:], 16)))
                else:
                    self._pieces.append(chr(int(name)))
            except (ValueError, OverflowError):
                pass

    def get_text(self) -> str:
        return " ".join(self._pieces)


# Fallback regex for when HTMLParser fails.
_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


def _html_to_text(html: str) -> str:
    """Convert HTML to plain text using stdlib HTMLParser.

    Falls back to regex stripping if the parser encounters an error.
    """
    try:
        parser = _TextExtractor()
        parser.feed(html)
        return parser.get_text()
    except Exception:
        logger.debug("HTMLParser failed, falling back to regex strip.", exc_info=True)
        return _HTML_TAG_PATTERN.sub(" ", html)


def _normalize_cve_id(raw: str) -> str | None:
    """Normalize a raw CVE match to canonical ``CVE-YYYY-NNNNN`` form.

    Returns None if the year is out of the valid 1999–current_year range.
    """
    # Replace any Unicode dash with ASCII hyphen.
    normalized = re.sub(r"[\u2010-\u2015\u2212]", "-", raw).upper()
    parts = normalized.split("-")
    if len(parts) != 3:
        return None
    try:
        year = int(parts[1])
    except ValueError:
        return None
    if year < 1999 or year > _CURRENT_YEAR:
        return None
    return normalized


def _extract_cve_ids(text: str) -> list[str]:
    """Extract unique, normalized CVE IDs from text."""
    seen: dict[str, None] = {}
    for match in _CVE_PATTERN.findall(text):
        normalized = _normalize_cve_id(match)
        if normalized and normalized not in seen:
            seen[normalized] = None
    return list(seen)


def _robots_allow(
    client: httpx.Client,
    url: str,
    cache: dict[str, urllib.robotparser.RobotFileParser],
) -> bool:
    """Check whether robots.txt allows fetching *url* for our user-agent.

    Parses robots.txt once per domain (cached in *cache*).  Fails open on
    network errors so that a broken robots.txt doesn't block ingestion.
    """
    parsed = urllib.parse.urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in cache:
        rp = urllib.robotparser.RobotFileParser()
        robots_url = f"{origin}/robots.txt"
        try:
            resp = client.get(robots_url, headers={"User-Agent": USER_AGENT})
            resp.raise_for_status()
            rp.parse(resp.text.splitlines())
        except Exception:
            # Fail open — treat as fully allowed.
            logger.debug("Could not fetch robots.txt for %s, allowing.", origin)
            rp.parse([])  # Empty ruleset = everything allowed
        cache[origin] = rp
    return cache[origin].can_fetch(USER_AGENT, url)


def _fetch_article_cve_ids(client: httpx.Client, url: str) -> list[str]:
    """Fetch the full article page and extract CVE IDs from its body."""
    if not url.startswith(("http://", "https://")):
        return []
    try:
        resp = client.get(url, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        plain = _html_to_text(resp.text)
        return _extract_cve_ids(plain)
    except httpx.HTTPError:
        logger.debug("Failed to fetch article page: %s", url, exc_info=True)
        return []


def _get_content_encoded(entry) -> str:
    """Extract the ``content:encoded`` body from a feedparser entry, if any."""
    content_list = getattr(entry, "content", None)
    if content_list and isinstance(content_list, list):
        for c in content_list:
            value = c.get("value", "")
            if value:
                return value
    return ""


def fetch_news(days_back: int = 7) -> list[dict]:
    """Fetch recent articles from RSS feeds.

    Args:
        days_back: Only include articles published within this many days.

    Returns:
        List of dicts with keys: url, title, source_name, published_date,
        summary, cve_ids.
    """
    cutoff = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) - timedelta(days=days_back)

    articles: list[dict] = []
    seen_urls: set[str] = set()
    page_fetch_count = 0
    t_start = time.monotonic()
    last_page_fetch_time = 0.0
    robots_cache: dict[str, urllib.robotparser.RobotFileParser] = {}

    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        for source_name, feed_url in RSS_FEEDS.items():
            logger.info("Fetching RSS feed: %s", source_name)
            try:
                response = client.get(
                    feed_url,
                    headers={"User-Agent": USER_AGENT},
                )
                response.raise_for_status()
            except httpx.HTTPError:
                logger.error("Failed to fetch feed: %s", source_name, exc_info=True)
                continue

            feed = feedparser.parse(response.text)

            for entry in feed.entries:
                url = entry.get("link", "")
                if not url or url in seen_urls:
                    continue

                # Parse published date
                published_date = None
                time_struct = entry.get("published_parsed") or entry.get("updated_parsed")
                if time_struct:
                    try:
                        dt = datetime.fromtimestamp(mktime(time_struct), tz=timezone.utc)
                        if dt < cutoff:
                            continue
                        published_date = dt.date()
                    except (ValueError, OverflowError):
                        published_date = date.today()
                else:
                    published_date = date.today()

                title = entry.get("title", "").strip()
                summary = entry.get("summary", "").strip()

                # --- Stage 1: title + summary (run through HTML-to-text) ---
                combined_text = f"{title} {_html_to_text(summary)}"
                cve_ids_set: dict[str, None] = {}
                for cve_id in _extract_cve_ids(combined_text):
                    cve_ids_set[cve_id] = None

                # --- Stage 2: content:encoded (full RSS body, no network) ---
                content_body = _get_content_encoded(entry)
                if content_body:
                    content_text = _html_to_text(content_body)
                    for cve_id in _extract_cve_ids(content_text):
                        if cve_id not in cve_ids_set:
                            cve_ids_set[cve_id] = None
                    if cve_ids_set:
                        logger.debug(
                            "Found %d CVE(s) in RSS content for: %s",
                            len(cve_ids_set), url,
                        )

                # --- Stage 3: full-page fetch (only if stages 1+2 found nothing) ---
                if not cve_ids_set:
                    if _robots_allow(client, url, robots_cache):
                        # Rate-limit full-page fetches.
                        elapsed_since_last = time.monotonic() - last_page_fetch_time
                        if elapsed_since_last < PAGE_FETCH_DELAY:
                            time.sleep(PAGE_FETCH_DELAY - elapsed_since_last)

                        page_cves = _fetch_article_cve_ids(client, url)
                        last_page_fetch_time = time.monotonic()

                        if page_cves:
                            for cve_id in page_cves:
                                cve_ids_set[cve_id] = None
                            logger.debug(
                                "Found %d CVE(s) in full page: %s",
                                len(page_cves), url,
                            )
                        page_fetch_count += 1
                    else:
                        logger.debug("Robots.txt disallows fetching: %s", url)

                cve_ids = list(cve_ids_set)

                seen_urls.add(url)
                articles.append({
                    "url": url,
                    "title": title[:500],
                    "source_name": source_name,
                    "published_date": published_date,
                    "summary": summary[:2000] if summary else None,
                    "cve_ids": cve_ids,
                })
                logger.debug(
                    "News article: %s [%s] CVEs: %s",
                    title[:80],
                    source_name,
                    cve_ids or "none",
                )

            logger.info("Parsed %d entries from %s.", len(feed.entries), source_name)

    elapsed = time.monotonic() - t_start
    logger.info(
        "News fetch complete: %d articles in %.1fs (%d full-page fetches).",
        len(articles), elapsed, page_fetch_count,
    )
    return articles
