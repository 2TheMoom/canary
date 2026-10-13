# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import html
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from genlayer import *

MIN_PHRASE = 8
MAX_PHRASE = 200
MIN_WINDOW = 100
MAX_WINDOW = 2000
MIN_AGE_DAYS = 1
MAX_AGE_DAYS = 400
MAX_URL_LENGTH = 300
MAX_HTML_BYTES = 2_000_000
MAX_OCCURRENCES = 20
MIN_CHECK_INTERVAL = 300  # seconds between checks of one canary
HISTORY_LEN = 12
RAW_TEXT_TAGS = ("script", "style", "noscript", "svg", "template")
REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,text/plain",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}
LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
# Names that only ever resolve inside someone's own network. Validators must
# not be usable as a probe of their own internal networks.
INTERNAL_SUFFIXES = ("local", "internal", "lan", "localhost", "home", "corp", "intranet", "localdomain", "arpa")

# Status values, from best to worst. "unchecked" is only the state before the
# first check.
ALIVE = "alive"  # statement present, dated, and fresh
STALE = "stale"  # statement present and dated, but older than max_age_days
UNDATED = "undated"  # statement present, no usable date next to it
CHANGED = "changed"  # page reachable, but the statement is no longer on it
REMOVED = "removed"  # the page is gone (404 or 410)
UNCHECKED = "unchecked"

MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8,
    "sept": 9, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_MONTH_RE = "(" + "|".join(sorted(MONTHS, key=len, reverse=True)) + ")"
_ISO = re.compile(r"(?<![0-9])(20[0-9]{2})[-/.]([0-9]{1,2})[-/.]([0-9]{1,2})(?![0-9])")
_MDY = re.compile(r"(?<![a-z])" + _MONTH_RE + r"\.? ([0-9]{1,2})(?:st|nd|rd|th)?,? (20[0-9]{2})(?![0-9])")
_DMY = re.compile(r"(?<![0-9])([0-9]{1,2})(?:st|nd|rd|th)? (?:of )?" + _MONTH_RE + r"\.?,? (20[0-9]{2})(?![0-9])")


# -- validation (deterministic) --


def _bad(cond: bool, msg: str) -> None:
    if cond:
        raise gl.vm.UserError(msg)


def _norm(s: str) -> str:
    """Case-folded, whitespace-collapsed text with typographic quotes made
    plain, so a statement matches however the page happens to style it."""
    for a, b in (("\u2019", "'"), ("\u2018", "'"), ("\u201c", '"'), ("\u201d", '"'), ("\u00a0", " ")):
        s = s.replace(a, b)
    return re.sub(r"\s+", " ", s).strip().lower()


def _clean_url(url) -> str:
    """The canonical form of a canary URL, or a UserError. https only, a
    real domain name (no IP address, port, credentials or internal name)."""
    _bad(not isinstance(url, str), "url must be text")
    _bad(not url.startswith("https://"), "url must start with https://")
    _bad(len(url) > MAX_URL_LENGTH, f"url must be at most {MAX_URL_LENGTH} characters")
    for ch in url:
        _bad(ch.isspace() or ch in "\"'<>\\`", "url contains a forbidden character")
    rest = url[8:]
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].lower()
    _bad("@" in host, "url may not contain credentials")
    _bad(":" in host, "url may not set a port")
    labels = host.split(".")
    _bad(len(labels) < 2, "url host must be a domain name")
    for label in labels:
        _bad(not (1 <= len(label) <= 63), "invalid url host")
        _bad(label[0] == "-" or label[-1] == "-", "invalid url host")
        for ch in label:
            _bad(ch not in LABEL_CHARS, "invalid url host")
    _bad(not any(ch.isalpha() for ch in labels[-1]), "url host must be a domain name, not an IP address")
    _bad(labels[-1] in INTERNAL_SUFFIXES, "url host must be a public domain name")
    path = rest[len(rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]):]
    path = path.split("#", 1)[0]
    return "https://" + host + path


def _clean_phrase(phrase) -> str:
    _bad(not isinstance(phrase, str), "phrase must be text")
    p = _norm(phrase)
    _bad(len(p) < MIN_PHRASE, f"phrase must be at least {MIN_PHRASE} characters")
    _bad(len(p) > MAX_PHRASE, f"phrase must be at most {MAX_PHRASE} characters")
    _bad(not any(ch.isalpha() for ch in p), "phrase must contain letters")
    return p


def _key(url: str, phrase: str, max_age_days: int, window: int) -> str:
    """One canary is one (page, statement, freshness rule). Because the id is
    derived from all of them, nobody can squat the id of someone else's
    canary with a different rule, and registering the same canary twice is
    simply refused."""
    return f"{url}|{phrase}|{max_age_days}|{window}"


# -- reading a page (pure, so every rule is testable on its own) --


def _page_text(body: bytes) -> str:
    """Readable text from a page: scripts, styles and markup removed,
    entities decoded, whitespace collapsed. One forward pass that never
    revisits text, because regex stripping backtracks quadratically on
    hostile markup and one page could otherwise time out every validator."""
    s = body[:MAX_HTML_BYTES].decode("utf-8", errors="replace")
    low = s.lower()
    n = len(s)
    out: list = []
    i = 0
    while i < n:
        j = s.find("<", i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        out.append(" ")
        if low.startswith("<!--", j):
            k = s.find("-->", j + 4)
            if k < 0:
                break
            i = k + 3
            continue
        k = s.find(">", j + 1)
        if k < 0:
            break
        raw = ""
        for tag in RAW_TEXT_TAGS:
            end = j + 1 + len(tag)
            if low.startswith(tag, j + 1) and (end >= n or not low[end].isalnum()):
                raw = tag
                break
        if raw:
            close = low.find("</" + raw, k + 1)
            if close < 0:
                break
            k = s.find(">", close)
            if k < 0:
                break
        i = k + 1
    return re.sub(r"\s+", " ", html.unescape("".join(out))).strip()


def _make_date(y: int, m: int, d: int):
    try:
        if 2000 <= y <= 2100:
            return date(y, m, d)
    except ValueError:
        pass
    return None


def _dates_in(text: str, today) -> list:
    """Every real calendar date in `text` that is not in the future, in the
    formats 2026-09-30, September 30, 2026 and 30 September 2026. A date a
    couple of days ahead is allowed for clock skew, but a statement dated
    well into the future, or a "next update" date, never counts as fresh."""
    low = text.lower()
    found: list = []
    limit = today + timedelta(days=1)
    for m in _ISO.finditer(low):
        found.append(_make_date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
    for m in _MDY.finditer(low):
        found.append(_make_date(int(m.group(3)), MONTHS[m.group(1)], int(m.group(2))))
    for m in _DMY.finditer(low):
        found.append(_make_date(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1))))
    return [d for d in found if d is not None and d <= limit]


def _extract(text: str, phrase: str, window: int, today) -> tuple:
    """(statement found, newest non-future date within `window` characters of
    the statement, as ISO text or ""). Only dates beside the statement count,
    so a news sidebar or a footer with today's date cannot make an old
    statement look fresh."""
    hay = _norm(text)
    found = False
    newest = None
    start = 0
    for _ in range(MAX_OCCURRENCES):
        i = hay.find(phrase, start)
        if i < 0:
            break
        found = True
        near = hay[max(0, i - window): i + len(phrase) + window]
        for d in _dates_in(near, today):
            if newest is None or d > newest:
                newest = d
        start = i + len(phrase)
    return found, (newest.isoformat() if newest else "")


def _status(kind: str, found: bool, latest: str, today, max_age_days: int) -> str:
    """The canary's state from the facts validators agreed on. Whether a
    statement is fresh is decided here, after consensus, from the contract's
    own clock, so a validator running a few seconds off cannot split the vote."""
    if kind == "gone":
        return REMOVED
    if not found:
        return CHANGED
    if latest == "":
        return UNDATED
    age = (today - date.fromisoformat(latest)).days
    return ALIVE if age <= max_age_days else STALE


@allow_storage
@dataclass
class Watch:
    url: str
    phrase: str
    max_age_days: u256
    window: u256
    registrant: Address
    registered_at: u256
    status: str
    last_date: str  # newest date found beside the statement at the last check
    checked_at: u256
    last_alive_at: u256
    checks: u256
    events: u256  # status changes ever recorded


@allow_storage
@dataclass
class Event:
    at: u256
    status: str
    date: str


class Canary(gl.Contract):
    """On-chain warrant-canary and dead-man's-switch monitor.

    A canary is a public statement ("we have not received any gag orders")
    that its publisher keeps re-dating. When it disappears, is reworded, or
    stops being updated, that silence is the warning. Nobody reliably watches
    for it, and no contract could react to it.

    Canary makes it checkable. Anyone registers a page, the exact statement
    to look for, and how old its date may be. Anyone can then call check():
    validators each fetch the page and independently extract two facts, with
    no LLM, and the contract derives the status from what they agree on:
    alive, stale, undated, changed or removed. Other contracts gate on
    is_alive().

    An error is never treated as absence. A timeout, a 5xx, a 403 or a 429
    reverts check() and changes nothing; only a real 404/410 counts as
    removal, and only a reachable page without the statement counts as changed.
    """

    canaries: TreeMap[str, Watch]
    canary_ids: DynArray[str]
    history: TreeMap[str, DynArray[Event]]

    def __init__(self):
        pass

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _get(self, canary_id: str) -> Watch:
        _bad(not isinstance(canary_id, str) or canary_id not in self.canaries, "Unknown canary")
        return self.canaries[canary_id]

    @gl.public.view
    def canary_id(self, url: str, phrase: str, max_age_days: int, window: int) -> str:
        """The id a canary with these exact settings has (or would have)."""
        _bad(isinstance(max_age_days, bool) or not isinstance(max_age_days, int), "max_age_days must be a whole number")
        _bad(isinstance(window, bool) or not isinstance(window, int), "window must be a whole number")
        return _key(_clean_url(url), _clean_phrase(phrase), max_age_days, window)

    @gl.public.write
    def register(self, url: str, phrase: str, max_age_days: int, window: int) -> None:
        _bad(isinstance(max_age_days, bool) or not isinstance(max_age_days, int), "max_age_days must be a whole number")
        _bad(isinstance(window, bool) or not isinstance(window, int), "window must be a whole number")
        _bad(not (MIN_AGE_DAYS <= max_age_days <= MAX_AGE_DAYS), f"max_age_days must be {MIN_AGE_DAYS} to {MAX_AGE_DAYS}")
        _bad(not (MIN_WINDOW <= window <= MAX_WINDOW), f"window must be {MIN_WINDOW} to {MAX_WINDOW}")
        clean_url = _clean_url(url)
        clean_phrase = _clean_phrase(phrase)
        cid = _key(clean_url, clean_phrase, max_age_days, window)
        _bad(cid in self.canaries, "This canary is already registered")
        self.canaries[cid] = Watch(
            url=clean_url,
            phrase=clean_phrase,
            max_age_days=max_age_days,
            window=window,
            registrant=gl.message.sender_address,
            registered_at=self._now(),
            status=UNCHECKED,
            last_date="",
            checked_at=0,
            last_alive_at=0,
            checks=0,
            events=0,
        )
        self.canary_ids.append(cid)

    def _read(self, url: str, phrase: str, window: int, today) -> dict:
        def leader_fn() -> dict:
            try:
                resp = gl.nondet.web.request(url, method="GET", headers=REQUEST_HEADERS)
            except Exception:
                return {"kind": "unreachable", "found": False, "latest": ""}
            if resp.status in (404, 410):
                return {"kind": "gone", "found": False, "latest": ""}
            # Anything else that is not a clean read (5xx, 403, 429, a blank
            # body) says nothing about the canary, so it must not look like one.
            if resp.status != 200 or not resp.body:
                return {"kind": "unreachable", "found": False, "latest": ""}
            found, latest = _extract(_page_text(resp.body), phrase, window, today)
            return {"kind": "ok", "found": found, "latest": latest}

        def validator_fn(leaders_res) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            theirs = leaders_res.calldata
            if not isinstance(theirs, dict):
                return False
            if theirs.get("kind") not in ("ok", "gone", "unreachable"):
                return False
            if not isinstance(theirs.get("found"), bool) or not isinstance(theirs.get("latest"), str):
                return False
            mine = leader_fn()
            return (
                mine["kind"] == theirs["kind"]
                and mine["found"] == theirs["found"]
                and mine["latest"] == theirs["latest"]
            )

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

    @gl.public.write
    def check(self, canary_id: str) -> None:
        """Permissionless. Reads the page and records the canary's status."""
        w = self._get(canary_id)
        now = self._now()
        _bad(
            int(w.checks) > 0 and now < int(w.checked_at) + MIN_CHECK_INTERVAL,
            "This canary was checked a moment ago, try again shortly",
        )
        today = datetime.fromtimestamp(now, timezone.utc).date()
        facts = self._read(w.url, w.phrase, int(w.window), today)
        _bad(
            facts["kind"] == "unreachable",
            "The page could not be read cleanly (timeout, server error or blocked), so nothing was recorded. Try again shortly.",
        )
        status = _status(facts["kind"], facts["found"], facts["latest"], today, int(w.max_age_days))
        changed = status != w.status or facts["latest"] != w.last_date
        w.status = status
        w.last_date = facts["latest"]
        w.checked_at = now
        w.checks = int(w.checks) + 1
        if status == ALIVE:
            w.last_alive_at = now
        if changed:
            events = self.history.get_or_insert_default(canary_id)
            ev = Event(at=now, status=status, date=facts["latest"])
            n = int(w.events)
            if n < HISTORY_LEN:
                events.append(ev)
            else:
                events[n % HISTORY_LEN] = ev
            w.events = n + 1

    @gl.public.view
    def is_alive(self, canary_id: str, max_check_age_seconds: int) -> bool:
        """True only if the last check found the canary alive AND that check
        is recent enough. Never reverts: an unknown id, a bad argument, an
        unchecked or stale-checked canary all answer False."""
        if not isinstance(canary_id, str) or canary_id not in self.canaries:
            return False
        if isinstance(max_check_age_seconds, bool) or not isinstance(max_check_age_seconds, int) or max_check_age_seconds < 0:
            return False
        w = self.canaries[canary_id]
        if w.status != ALIVE:
            return False
        return self._now() - int(w.checked_at) <= max_check_age_seconds

    @gl.public.view
    def status_of(self, canary_id: str) -> str:
        if not isinstance(canary_id, str) or canary_id not in self.canaries:
            return "unknown"
        return self.canaries[canary_id].status

    @gl.public.view
    def get_canary(self, canary_id: str) -> dict:
        w = self._get(canary_id)
        return {
            "url": w.url,
            "phrase": w.phrase,
            "max_age_days": int(w.max_age_days),
            "window": int(w.window),
            "registrant": w.registrant.as_hex,
            "registered_at": int(w.registered_at),
            "status": w.status,
            "last_date": w.last_date,
            "checked_at": int(w.checked_at),
            "last_alive_at": int(w.last_alive_at),
            "checks": int(w.checks),
            "events": int(w.events),
        }

    @gl.public.view
    def get_history(self, canary_id: str) -> list:
        """The last HISTORY_LEN status changes, oldest first."""
        w = self._get(canary_id)
        n = int(w.events)
        if n == 0:
            return []
        events = self.history[canary_id]
        order = list(range(n)) if n <= HISTORY_LEN else [(n + i) % HISTORY_LEN for i in range(HISTORY_LEN)]
        return [{"at": int(events[i].at), "status": events[i].status, "date": events[i].date} for i in order]

    @gl.public.view
    def get_all_ids(self) -> list:
        return list(self.canary_ids)
