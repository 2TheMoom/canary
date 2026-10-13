"""Direct-mode tests for Canary.

Canary has no LLM. Every rule is a deterministic fact extracted from a page,
so the tests mock the page, run check(), and assert the status; the pure
helpers (date parsing, statement matching) are also tested directly.
"""

import sys
import time
from datetime import date

import pytest

CONTRACT = "contracts/canary.py"

T0 = "2026-10-13T12:00:00Z"
T0_TS = 1791892800  # 2026-10-13T12:00:00Z
TODAY = date(2026, 10, 13)
DAY = 86400

URL = "https://example-vpn.com/canary"
PHRASE = "has not received any national security letters"
AGE = 35
WINDOW = 400

PAGE_FMT = "<html><body><h1>Warrant Canary</h1><p>Last updated: {d}</p><p>ExampleVPN {p}.</p></body></html>"


def _mod(contract):
    return sys.modules[type(contract).__module__]


def _page(d="2026-10-01", phrase=PHRASE):
    return PAGE_FMT.format(d=d, p=phrase)


def _mock(vm, body=None, status=200, url=URL):
    vm.clear_mocks()
    vm.mock_web("^" + url.replace(".", r"\.") + "$", {"status": status, "body": _page() if body is None else body})


def _register(contract, vm, sender, *, url=URL, phrase=PHRASE, age=AGE, window=WINDOW):
    vm.sender = sender
    contract.register(url, phrase, age, window)
    return contract.canary_id(url, phrase, age, window)


def _setup(direct_vm, direct_deploy, sender, **kw):
    contract = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    return contract, _register(contract, direct_vm, sender, **kw)


def _check(contract, vm, cid, body=None, status=200, url=URL, when=None):
    if when:
        vm.warp(when)
    _mock(vm, body=body, status=status, url=url)
    contract.check(cid)


# ---------------------------------------------------------------------------
# register / canary_id
# ---------------------------------------------------------------------------


def test_register_stores_the_canary(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    c = contract.get_canary(cid)
    assert c["url"] == URL and c["phrase"] == PHRASE
    assert (c["max_age_days"], c["window"], c["status"], c["checks"]) == (AGE, WINDOW, "unchecked", 0)
    assert contract.get_all_ids() == [cid]
    assert contract.status_of(cid) == "unchecked"


def test_id_is_derived_from_every_setting(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    base = contract.canary_id(URL, PHRASE, AGE, WINDOW)
    assert contract.canary_id(URL, PHRASE, AGE + 1, WINDOW) != base
    assert contract.canary_id(URL, PHRASE, AGE, WINDOW + 1) != base
    assert contract.canary_id(URL, PHRASE + " today", AGE, WINDOW) != base
    assert contract.canary_id(URL + "/x", PHRASE, AGE, WINDOW) != base


def test_id_ignores_host_case_and_phrase_styling(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    a = contract.canary_id("https://Example-VPN.com/canary", PHRASE, AGE, WINDOW)
    b = contract.canary_id(URL, "  HAS  not received\nany National Security Letters ", AGE, WINDOW)
    assert a == b == contract.canary_id(URL, PHRASE, AGE, WINDOW)


def test_nobody_can_squat_another_canarys_id(direct_vm, direct_deploy, direct_alice, direct_bob):
    """A different rule on the same page is a different canary."""
    contract = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    a = _register(contract, direct_vm, direct_alice)
    b = _register(contract, direct_vm, direct_bob, phrase="some other statement")
    assert a != b


def test_registering_twice_is_refused(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract, _ = _setup(direct_vm, direct_deploy, direct_alice)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("already registered"):
        contract.register(URL, PHRASE, AGE, WINDOW)


@pytest.mark.parametrize(
    "url,msg",
    [
        ("http://example-vpn.com/c", "https://"),
        ("ftp://example-vpn.com/c", "https://"),
        ("https://user:pw@example-vpn.com/c", "credentials"),
        ("https://example-vpn.com:8443/c", "port"),
        ("https://127.0.0.1/c", "not an IP"),
        ("https://10.0.0.5/c", "not an IP"),
        ("https://[::1]/c", "port"),
        ("https://localhost/c", "domain name"),
        ("https://intranet/c", "domain name"),
        ("https://myserver/c", "domain name"),  # a bare host, not on any blocklist
        ("https://printer.local/c", "public domain"),
        ("https://db.internal/c", "public domain"),
        ("https://nas.lan/c", "public domain"),
        ("https://-bad.example.com/c", "invalid"),
        ("https://exa mple.com/c", "forbidden"),
        ("https://example.com/<x>", "forbidden"),
        ("https://" + "a" * 64 + ".com/c", "invalid"),
        ("https://example.com/" + "p" * 300, "at most"),
    ],
)
def test_register_refuses_unsafe_urls(direct_vm, direct_deploy, direct_alice, url, msg):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert(msg):
        contract.register(url, PHRASE, AGE, WINDOW)


def test_register_validates_the_phrase(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("at least"):
        contract.register(URL, "short", AGE, WINDOW)
    with direct_vm.expect_revert("at most"):
        contract.register(URL, "x" * 201, AGE, WINDOW)
    with direct_vm.expect_revert("letters"):
        contract.register(URL, "12345678 9", AGE, WINDOW)


@pytest.mark.parametrize("age,window,msg", [(0, 400, "max_age_days"), (401, 400, "max_age_days"), (30, 99, "window"), (30, 2001, "window")])
def test_register_validates_the_bounds(direct_vm, direct_deploy, direct_alice, age, window, msg):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert(msg):
        contract.register(URL, PHRASE, age, window)


def test_register_refuses_non_integers(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("whole number"):
        contract.register(URL, PHRASE, True, WINDOW)
    with direct_vm.expect_revert("whole number"):
        contract.register(URL, PHRASE, AGE, "400")


# ---------------------------------------------------------------------------
# date parsing (pure)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Last updated: 2026-09-30", date(2026, 9, 30)),
        ("updated 2026/9/3", date(2026, 9, 3)),
        ("updated 2026.09.03", date(2026, 9, 3)),
        ("October 1, 2026", date(2026, 10, 1)),
        ("Oct 1 2026", date(2026, 10, 1)),
        ("Oct. 1, 2026", date(2026, 10, 1)),
        ("Sept 9, 2026", date(2026, 9, 9)),
        ("September 9th, 2026", date(2026, 9, 9)),
        ("1 October 2026", date(2026, 10, 1)),
        ("1st of October 2026", date(2026, 10, 1)),
        ("Fri 01 May 2026", date(2026, 5, 1)),
        ("SEPTEMBER 30, 2026", date(2026, 9, 30)),
    ],
)
def test_dates_in_understands_the_common_formats(direct_vm, direct_deploy, direct_alice, text, expected):
    contract = direct_deploy(CONTRACT)
    assert _mod(contract)._dates_in(text, TODAY) == [expected]


@pytest.mark.parametrize(
    "text",
    [
        "2026-02-30",  # not a real day
        "2026-13-01",
        "February 30, 2026",
        "31 April 2026",
        "1999-12-31",  # before 2000
        "2101-01-01",
        "10/13/2026",  # ambiguous, deliberately unsupported
        "version 20260930",
        "build 2026-10-1337",
        "Mayday 5, 2026",  # not the month May
        "Dismay 5, 2026",  # ends in "may" but is not the month
        "Coordec 5, 2026",  # ends in "dec" but is not the month
        "no dates here at all",
    ],
)
def test_dates_in_rejects_what_is_not_a_clear_date(direct_vm, direct_deploy, direct_alice, text):
    contract = direct_deploy(CONTRACT)
    assert _mod(contract)._dates_in(text, TODAY) == []


def test_future_dates_never_count(direct_vm, direct_deploy, direct_alice):
    """A "next update" date or a pre-dated statement must not look fresh."""
    contract = direct_deploy(CONTRACT)
    f = _mod(contract)._dates_in
    assert f("Next update: November 1, 2026", TODAY) == []
    assert f("signed 2099-01-01", TODAY) == []
    assert f("2026-10-14", TODAY) == [date(2026, 10, 14)]  # one day of clock skew is allowed
    assert f("2026-10-15", TODAY) == []


# ---------------------------------------------------------------------------
# statement matching (pure)
# ---------------------------------------------------------------------------


def test_extract_matches_the_statement_however_it_is_styled(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    ex = _mod(contract)._extract
    phrase = "we haven't received any gag orders"
    for text in (
        "We haven't received any gag orders. Updated 2026-10-01",
        "WE   HAVEN'T\n RECEIVED any GAG ORDERS. Updated 2026-10-01",
        "We haven’t received any gag orders. Updated 2026-10-01",  # curly apostrophe
    ):
        assert ex(text, phrase, 400, TODAY) == (True, "2026-10-01"), text


def test_extract_only_counts_dates_beside_the_statement(direct_vm, direct_deploy, direct_alice):
    """The whole point of the window: a sidebar dated today must not rescue a
    statement that was last dated months ago."""
    contract = direct_deploy(CONTRACT)
    ex = _mod(contract)._extract
    filler = "x" * 1000
    page = f"Latest news: 2026-10-12. {filler} {PHRASE}. Updated 2026-03-01. {filler} Footer 2026-10-13"
    assert ex(page, PHRASE, 400, TODAY) == (True, "2026-03-01")
    # A wider window reaches the sidebar date: that is the registrant's explicit choice.
    assert ex(page, PHRASE, 2000, TODAY) == (True, "2026-10-13")


def test_extract_takes_the_newest_date_in_the_window(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    ex = _mod(contract)._extract
    page = f"History: 2026-01-01, 2026-04-01, 2026-09-01. {PHRASE}. Next update 2026-12-01."
    assert ex(page, PHRASE, 400, TODAY) == (True, "2026-09-01")


def test_extract_uses_every_occurrence(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    ex = _mod(contract)._extract
    page = f"{PHRASE}. 2026-01-01. " + "y" * 900 + f" {PHRASE}. 2026-09-01."
    assert ex(page, PHRASE, 200, TODAY) == (True, "2026-09-01")


def test_extract_reports_a_missing_statement(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    ex = _mod(contract)._extract
    assert ex("Updated 2026-10-01. We value your privacy.", PHRASE, 400, TODAY) == (False, "")
    assert ex("", PHRASE, 400, TODAY) == (False, "")


def test_extract_is_bounded_on_a_hostile_page(direct_vm, direct_deploy, direct_alice):
    """Thousands of occurrences and dates must not make validators time out."""
    contract = direct_deploy(CONTRACT)
    ex = _mod(contract)._extract
    page = (PHRASE + " 2026-10-01 ") * 20000
    t = time.time()
    found, latest = ex(page, PHRASE, 2000, TODAY)
    assert (found, latest) == (True, "2026-10-01")
    assert time.time() - t < 5


# ---------------------------------------------------------------------------
# check(): every status
# ---------------------------------------------------------------------------


def test_fresh_dated_statement_is_alive(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=_page("2026-10-01"))
    c = contract.get_canary(cid)
    assert (c["status"], c["last_date"], c["checks"], c["checked_at"], c["last_alive_at"]) == ("alive", "2026-10-01", 1, T0_TS, T0_TS)
    assert contract.is_alive(cid, 3600) is True


def test_age_boundary_is_exact(direct_vm, direct_deploy, direct_alice):
    """max_age_days = 35: a date 35 days old is still alive, 36 is stale."""
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=_page("2026-09-08"))  # 35 days before 2026-10-13
    assert contract.status_of(cid) == "alive"
    direct_vm.warp("2026-10-13T12:10:00Z")
    _check(contract, direct_vm, cid, body=_page("2026-09-07"))  # 36 days
    assert contract.status_of(cid) == "stale"
    assert contract.is_alive(cid, 3600) is False


def test_statement_without_a_date_is_undated_not_alive(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=f"<p>ExampleVPN {PHRASE}.</p>")
    assert contract.status_of(cid) == "undated"
    assert contract.is_alive(cid, 3600) is False


def test_a_future_dated_statement_is_undated(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=_page("2099-01-01"))
    assert contract.status_of(cid) == "undated"


def test_missing_statement_on_a_reachable_page_is_changed(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body="<p>Last updated: 2026-10-01. We value your privacy.</p>")
    assert contract.status_of(cid) == "changed"
    assert contract.is_alive(cid, 3600) is False


@pytest.mark.parametrize("code", [404, 410])
def test_a_gone_page_is_removed(direct_vm, direct_deploy, direct_alice, code):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, status=code, body="Not found")
    assert contract.status_of(cid) == "removed"
    assert contract.is_alive(cid, 3600) is False


def test_a_soft_404_is_changed_not_alive(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body="<h1>Page not found</h1><p>Updated 2026-10-12</p>")
    assert contract.status_of(cid) == "changed"


def test_markup_and_scripts_do_not_hide_or_fake_the_statement(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    body = (
        "<html><head><script>var s='" + PHRASE + " 2026-10-12';</script><style>/* 2026-10-12 */</style></head>"
        "<body><!-- " + PHRASE + " 2026-10-12 --><p>Updated 2026-09-20</p><p>ExampleVPN <b>has not</b> received any "
        "<a href='/nsl'>national security letters</a>.</p></body></html>"
    )
    _check(contract, direct_vm, cid, body=body)
    c = contract.get_canary(cid)
    assert (c["status"], c["last_date"]) == ("alive", "2026-09-20")  # the script/comment dates did not count


# ---------------------------------------------------------------------------
# errors are never absence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [500, 502, 503, 429, 403, 401, 400, 451, 301, 204])
def test_a_bad_response_reverts_and_changes_nothing(direct_vm, direct_deploy, direct_alice, code):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=_page("2026-10-01"))  # alive first
    before = contract.get_canary(cid)
    direct_vm.warp("2026-10-13T13:00:00Z")
    _mock(direct_vm, status=code, body="oops")
    with direct_vm.expect_revert("could not be read cleanly"):
        contract.check(cid)
    assert contract.get_canary(cid) == before  # still alive, nothing recorded
    assert contract.status_of(cid) == "alive"


def test_a_blank_200_is_an_error_not_a_removal(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body="")
    with direct_vm.expect_revert("could not be read cleanly"):
        contract.check(cid)
    assert contract.status_of(cid) == "unchecked"


def test_a_network_failure_is_an_error_not_a_removal(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    direct_vm.clear_mocks()  # nothing mocked: the request itself fails
    with direct_vm.expect_revert("could not be read cleanly"):
        contract.check(cid)
    assert contract.status_of(cid) == "unchecked"


# ---------------------------------------------------------------------------
# transitions, history, rate limit
# ---------------------------------------------------------------------------


def test_full_lifecycle_alive_stale_changed_removed_and_back(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    steps = [
        ("2026-10-13T12:00:00Z", dict(body=_page("2026-10-01")), "alive"),
        ("2026-10-13T12:10:00Z", dict(body=_page("2026-08-01")), "stale"),
        ("2026-10-13T12:20:00Z", dict(body="<p>privacy</p>"), "changed"),
        ("2026-10-13T12:30:00Z", dict(status=404, body="gone"), "removed"),
        ("2026-10-13T12:40:00Z", dict(body=_page("2026-10-13")), "alive"),
    ]
    for when, kw, expected in steps:
        _check(contract, direct_vm, cid, when=when, **kw)
        assert contract.status_of(cid) == expected
    hist = contract.get_history(cid)
    assert [e["status"] for e in hist] == ["alive", "stale", "changed", "removed", "alive"]
    assert contract.get_canary(cid)["checks"] == 5


def test_an_unchanged_recheck_adds_no_history(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=_page("2026-10-01"))
    _check(contract, direct_vm, cid, body=_page("2026-10-01"), when="2026-10-13T12:10:00Z")
    assert len(contract.get_history(cid)) == 1
    assert contract.get_canary(cid)["checks"] == 2
    # A re-dated statement is a change worth recording.
    _check(contract, direct_vm, cid, body=_page("2026-10-12"), when="2026-10-13T12:20:00Z")
    assert [e["date"] for e in contract.get_history(cid)] == ["2026-10-01", "2026-10-12"]


def test_history_keeps_only_the_latest_events_oldest_first(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    mod = _mod(contract)
    n = mod.HISTORY_LEN + 5
    for i in range(n):
        d = f"2026-09-{(i % 28) + 1:02d}"
        _check(contract, direct_vm, cid, body=_page(d), when=f"2026-10-13T{12 + (i * 10) // 60:02d}:{(i * 10) % 60:02d}:00Z")
    hist = contract.get_history(cid)
    assert len(hist) == mod.HISTORY_LEN
    assert [e["at"] for e in hist] == sorted(e["at"] for e in hist)
    expect = [f"2026-09-{(i % 28) + 1:02d}" for i in range(n - mod.HISTORY_LEN, n)]
    assert [e["date"] for e in hist] == expect


def test_checks_are_rate_limited_per_canary(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid)
    direct_vm.warp("2026-10-13T12:04:59Z")
    with direct_vm.expect_revert("a moment ago"):
        contract.check(cid)
    _check(contract, direct_vm, cid, when="2026-10-13T12:05:00Z")
    assert contract.get_canary(cid)["checks"] == 2


def test_a_failed_check_does_not_start_the_rate_limit(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, status=503, body="down")
    with direct_vm.expect_revert("could not be read cleanly"):
        contract.check(cid)
    _check(contract, direct_vm, cid)  # immediately retryable
    assert contract.status_of(cid) == "alive"


def test_anyone_can_check(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    direct_vm.sender = direct_bob
    _check(contract, direct_vm, cid)
    assert contract.status_of(cid) == "alive"


def test_checking_an_unknown_canary_fails(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    with direct_vm.expect_revert("Unknown canary"):
        contract.check("nope")


# ---------------------------------------------------------------------------
# is_alive: the view other contracts rely on
# ---------------------------------------------------------------------------


def test_is_alive_needs_a_recent_check(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid)
    assert contract.is_alive(cid, 3600) is True
    direct_vm.warp("2026-10-13T12:59:59Z")
    assert contract.is_alive(cid, 3599) is True
    direct_vm.warp("2026-10-13T13:00:01Z")
    assert contract.is_alive(cid, 3600) is False  # the check itself has gone stale
    assert contract.is_alive(cid, 7200) is True


def test_is_alive_is_false_before_any_check(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    assert contract.is_alive(cid, 10**9) is False


def test_is_alive_never_reverts_on_bad_input(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid)
    for bad_id in ("", "nope", 123, None, True, [], {}):
        assert contract.is_alive(bad_id, 3600) is False
    for bad_age in (-1, True, False, "3600", None, [], {}):  # calldata cannot carry floats
        assert contract.is_alive(cid, bad_age) is False
    assert contract.status_of(123) == "unknown"
    assert contract.status_of("nope") == "unknown"


# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------


def _facts(kind="ok", found=True, latest="2026-10-01"):
    return {"kind": kind, "found": found, "latest": latest}


def _validate(vm, contract, cid, leader, **mock):
    """Run a validator against what the leader claimed, with the validator's own page mocked."""
    _mock(vm, **mock)
    return vm.run_validator(leader_result=leader)


def test_validator_agrees_when_it_reads_the_same_facts(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _call_check_collecting_validator(contract, direct_vm, cid)


def _call_check_collecting_validator(contract, vm, cid):
    # check() runs the leader; run_nondet_unsafe then asks the validator function
    # to compare. Exercise both ends against the same page.
    _mock(vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert vm.run_validator(leader_result=_facts()) is True


def test_validator_rejects_a_leader_that_lies_about_the_date(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_result=_facts(latest="2026-10-12")) is False


def test_validator_rejects_a_leader_that_claims_the_statement_is_missing(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_result=_facts(found=False, latest="")) is False


def test_validator_rejects_a_leader_that_claims_the_page_is_gone(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_result=_facts(kind="gone", found=False, latest="")) is False


def test_validator_rejects_a_leader_that_hides_a_live_page_as_unreachable(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_result=_facts(kind="unreachable", found=False, latest="")) is False


def test_validator_checks_each_field_on_its_own(direct_vm, direct_deploy, direct_alice):
    """A leader can be wrong in just one field; each must be caught alone."""
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_result=_facts()) is True
    assert direct_vm.run_validator(leader_result=_facts(kind="gone")) is False  # only the kind differs
    assert direct_vm.run_validator(leader_result=_facts(found=False)) is False  # only found differs
    assert direct_vm.run_validator(leader_result=_facts(latest="2026-09-30")) is False  # only the date differs


@pytest.mark.parametrize(
    "leader",
    [
        {},
        {"kind": "ok"},
        {"kind": "bogus", "found": True, "latest": "2026-10-01"},
        {"kind": "ok", "found": "yes", "latest": "2026-10-01"},
        {"kind": "ok", "found": True, "latest": 20261001},
        {"kind": "ok", "found": 1, "latest": "2026-10-01"},
        "ok",
        None,
        [],
    ],
)
def test_validator_rejects_malformed_leader_results(direct_vm, direct_deploy, direct_alice, leader):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_result=leader) is False


def test_validator_rejects_a_leader_error(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _mock(direct_vm, body=_page("2026-10-01"))
    contract.check(cid)
    assert direct_vm.run_validator(leader_error=Exception("boom")) is False


# ---------------------------------------------------------------------------
# hostile pages
# ---------------------------------------------------------------------------


def test_hostile_markup_cannot_stall_a_check(direct_vm, direct_deploy, direct_alice):
    """Thousands of unclosed tags would make a backtracking regex quadratic."""
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    hostile = "<script " * 40000 + "<!-- " * 40000 + PHRASE
    t = time.time()
    _check(contract, direct_vm, cid, body=hostile)
    assert time.time() - t < 5
    assert contract.status_of(cid) == "changed"


def test_page_text_survives_binary_and_huge_input(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    pt = _mod(contract)._page_text
    assert isinstance(pt(bytes(range(256)) * 100), str)
    big = (b"a" * 10_000_000)
    assert len(pt(big)) <= _mod(contract).MAX_HTML_BYTES


def test_a_comment_containing_a_tag_end_cannot_smuggle_a_date(direct_vm, direct_deploy, direct_alice):
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    body = f"<!-- a > b {PHRASE} 2026-10-12 --><p>ExampleVPN {PHRASE}. Updated 2026-03-01</p>"
    _check(contract, direct_vm, cid, body=body)
    assert contract.get_canary(cid)["last_date"] == "2026-03-01"
    assert contract.get_canary(cid)["status"] == "stale"


def test_a_canary_page_can_be_plain_text(direct_vm, direct_deploy, direct_alice):
    """Raw files (a GitHub raw URL, a text/plain canary) have no markup at all."""
    contract, cid = _setup(direct_vm, direct_deploy, direct_alice)
    _check(contract, direct_vm, cid, body=f"ExampleVPN {PHRASE}.\nSigned: 2026-10-10\n")
    assert contract.get_canary(cid)["status"] == "alive"
    assert contract.get_canary(cid)["last_date"] == "2026-10-10"
