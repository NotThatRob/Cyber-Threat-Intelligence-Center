"""RSS feed client for fetching security news articles."""

import logging
import re
import time
from datetime import date, datetime, timedelta, timezone
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

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


def _extract_cve_ids(text: str) -> list[str]:
    """Extract unique CVE IDs from text using regex."""
    return list(dict.fromkeys(_CVE_PATTERN.findall(text)))


def _fetch_article_cve_ids(client: httpx.Client, url: str) -> list[str]:
    """Fetch the full article page and extract CVE IDs from its body."""
    if not url.startswith(("http://", "https://")):
        return []
    try:
        resp = client.get(url, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        # Strip HTML tags to get plain text, then search for CVE IDs
        plain = _HTML_TAG_PATTERN.sub(" ", resp.text)
        return _extract_cve_ids(plain)
    except httpx.HTTPError:
        logger.debug("Failed to fetch article page: %s", url, exc_info=True)
        return []


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

                # Extract CVE IDs from title and summary first
                combined_text = f"{title} {summary}"
                cve_ids = _extract_cve_ids(combined_text)

                # If none found in RSS content, try the full article page
                if not cve_ids:
                    page_cves = _fetch_article_cve_ids(client, url)
                    if page_cves:
                        cve_ids = page_cves
                        logger.debug(
                            "Found %d CVE(s) in full page: %s",
                            len(page_cves), url,
                        )
                        page_fetch_count += 1

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
