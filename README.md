# Canary

An on-chain monitor for warrant canaries and dead-man's switches, built on GenLayer validator consensus. No LLM.

## The problem

A warrant canary is a public statement ("we have not received any gag orders") that a publisher keeps re-dating. If it disappears, is reworded, or stops being updated, that silence is the warning. In practice nobody watches reliably, and no smart contract can react to it, so the whole mechanism rests on someone noticing.

Canary makes the silence checkable. Anyone registers a page, the exact statement to look for, and how old its date may be. Anyone can then call `check()`. Other contracts gate on `is_alive()`.

## How it works

1. **`register(url, phrase, max_age_days, window)`** records what to watch. The id is derived from all four settings, so nobody can squat the id of someone else's canary with a different rule, and the same canary can't be registered twice. `canary_id(...)` computes it. The fields are joined with `|`, which a URL may not contain, so every id decodes to exactly one tuple.
2. **`check(id)`** is permissionless. Each validator fetches the page itself and extracts two facts, with no LLM:
   - is the statement on the page (case, spacing and typographic quotes ignored)?
   - what is the newest non-future date within `window` characters of the statement?
3. Validators must agree on those facts. The contract then derives the status from its own clock:

| Status | Meaning |
|---|---|
| `alive` | statement present, dated, and the date is at most `max_age_days` old |
| `stale` | statement present and dated, but too old |
| `undated` | statement present, but no usable date next to it |
| `changed` | page reachable, but the statement is no longer on it |
| `removed` | the page is gone (HTTP 404 or 410) |

4. **`is_alive(id, max_check_age_seconds)`** is true only if the last check found the canary `alive`, that check is recent enough, **and the statement's date is still within `max_age_days` as of right now**. It never reverts. `status_of` and `get_canary` report the state as of the last check and do not age by themselves, so consumers should gate on `is_alive`.

## Security model

- **An error is never absence.** A failed connection, a timeout, a 5xx, a 403, a 429 or a blank page reverts `check()` and records nothing. Only a real 404/410 counts as `removed`, and only a reachable page without the statement counts as `changed`. Otherwise anyone able to make a validator's request fail could forge a "removed" canary. Same rule as [Deed](https://github.com/2TheMoom/deed).
- **Only dates beside the statement count.** A news sidebar or footer dated today must not rescue a statement last dated months ago, so only dates within `window` characters of the statement are read. A registrant who wants a wider net chooses it explicitly, and it is part of the canary's id.
- **Future dates never count.** A "next update" date or a pre-dated statement is ignored (one day of clock skew is allowed), so a canary can't look fresh by being signed ahead of time.
- **Freshness comes from the contract's clock, after consensus.** Validators agree only on facts (found? newest date?). Whether that date is fresh is decided afterwards from the transaction time, so a validator whose clock is a few seconds off can't split the vote.
- **Strict dates.** Real calendar dates only, in three formats (`2026-09-30`, `September 30, 2026`, `30 September 2026`), years 2000 to 2100. `10/13/2026` is deliberately unsupported because it is ambiguous. `Dismay 5, 2026` is not a date.
- **Validators can't be aimed inward.** URLs must be `https`, a real domain name (no IP address, port, credentials or single-label host), and not an internal suffix (`.local`, `.internal`, `.lan`, `.localhost` and similar).
- **Hostile pages are bounded.** The page reader is a single forward pass over at most 2 MB, with scripts, styles and comments removed. Statement matching stops after 20 occurrences. A page full of unclosed tags or thousands of repeated statements cannot time out validators.
- **A malicious leader is caught field by field.** Validators re-read the page and each compare the kind of result, whether the statement was found, and the date. A leader that lies about any one of them, or returns a malformed result, is rejected.
- **Checks are rate limited** to one per canary per five minutes, and a failed check doesn't start the clock.
- **Listings are bounded.** Anyone can register, so the list of ids is unbounded and `get_ids(offset, limit)` returns at most 50 at a time.

### What Canary does not do

- It cannot tell whether a published statement is true, only whether it is present, dated and fresh.
- It reads page text, not what a browser renders. A statement hidden with CSS still counts as present, so Canary catches a canary that is forgotten, reworded or deleted, not a publisher who deliberately hides it.
- It reads server-rendered pages and plain text. A page that needs JavaScript to show the statement, or that blocks validators (403/429), reports an error rather than a status.
- Someone has to call `check()`. Consumers should require a recent check through `is_alive`'s second argument.
- Hostnames are filtered by name, so a public name that resolves to a private address (wildcard DNS such as `nip.io`) is not caught. Redirects are followed by the platform's fetcher and are not inspected.
- If the statement or the dates near it change between validators' fetches, validators may fail to agree and the check will not be recorded. That fails closed.

### Bugs found in review, and fixed

A steward-style review before submission found three real bugs, each now covered by tests:

1. **Id collision.** The id is `url|phrase|age|window` and a URL could contain `|`, so an attacker could register a different page whose id equalled someone else's canary, blocking them and pointing consumers at the attacker's page. `|` is now refused in URLs, and a test checks that every id reads back as exactly one tuple.
2. **Unbounded listing.** `get_all_ids()` returned every canary ever registered, which spam registrations could make too large to call. It is replaced by `get_count()` and the capped `get_ids(offset, limit)`.
3. **`is_alive` froze freshness at check time.** A statement dated exactly 35 days ago (the limit) was `alive` when checked, and a consumer tolerating week-old checks kept being told it was fresh for up to a week after it had aged out. `is_alive` now evaluates the date against the current time as well.

All of the above is covered by 122 direct-mode tests, and every rule was mutation-checked: breaking it on purpose makes a test fail (61 of 62 mutations are caught; the survivor is a redundant status check in `is_alive`, since its date check already rejects every non-alive state).

## Using Canary from another contract

```python
from genlayer.py.public_abi import StorageType

MAX_CHECK_AGE_SECONDS = 24 * 3600

def _canary_alive(self, canary_id: str) -> bool:
    try:
        return (
            gl.get_contract_at(self.canary)
            .view(state=StorageType.LATEST_FINAL)   # not just accepted: final
            .is_alive(canary_id, MAX_CHECK_AGE_SECONDS)
        ) is True
    except Exception:
        return False
```

Fail closed: anything other than a literal `True` means "not alive". Compute the id yourself with `canary_id(...)` from the settings you trust rather than accepting one from a caller. The same two Bradbury caveats that apply to any cross-contract consumer apply here: finalized state lags, and calls abort the caller until the target's own deployment is final (see [Deed](https://github.com/2TheMoom/deed#using-deed-from-another-contract)).

## Interface

| Method | Kind | Purpose |
|---|---|---|
| `canary_id(url, phrase, max_age_days, window)` | view | the id these settings have |
| `register(url, phrase, max_age_days, window)` | write | start watching a page |
| `check(id)` | write | read the page and record its status |
| `is_alive(id, max_check_age_seconds)` | view | alive **and** recently checked; never reverts |
| `status_of(id)` | view | the status as of the last check, or `unknown` |
| `get_canary(id)` | view | settings, status, newest date, check counts |
| `get_history(id)` | view | the last 12 status changes, oldest first |
| `get_count()` | view | how many canaries are registered |
| `get_ids(offset, limit)` | view | a page of ids, oldest first, at most 50 |

Limits: phrase 8 to 200 characters, `max_age_days` 1 to 400, `window` 100 to 2000 characters, URL at most 300 characters.

## Live deployment

GenLayer Bradbury Testnet (chain 4221):

- **Canary:** [`0x5e0E239E12B82d8376C9D4D3Bd5af8ab7E805e85`](https://explorer-bradbury.genlayer.com/address/0x5e0E239E12B82d8376C9D4D3Bd5af8ab7E805e85)

**Real canaries**, registered and checked on this deployment, all with validators in agreement:

| Page | Settings | Result |
|---|---|---|
| anon.li warrant canary | 40 days, window 400 | `alive`, newest date 2026-10-01 |
| TunnelSats transparency page | 120 days, window 400 | `alive`, newest date 2026-09-30 (the page's older and "next" dates were not mistaken for it) |
| VeePN warrant canary | 400 days, window 400 | `undated`: the statement is there, no date is |
| Riseup canary | 120 days, window 1000 | `undated`: the statement is there, no date beside it |

**A canary this repo controls** ([`demo/CANARY.txt`](demo/CANARY.txt)), driven through every state by `scripts/demo-lifecycle.sh`:

| Step | Page | `check` result |
|---|---|---|
| fresh statement, signed 2026-10-13 | `demo/CANARY.txt` | `alive`, newest date 2026-10-13 |
| statement reworded to "can no longer comment on legal requests" | page still there, statement gone | `changed` (tx `0x4740a2d1...`) |
| page deleted | HTTP 404 | `removed` (tx `0x90bc0569...`) |
| statement restored with a fresh date | page back | `alive` again (tx `0xab6df777...`) |

`get_history` then returns exactly those four transitions, oldest first, and `is_alive(id, 3600)` is `true`. One check along the way ended in a `LEADER_TIMEOUT` (the leader validator ran out of time), which records nothing; repeating it succeeded.

**Error handling**, live:

| Check | Result |
|---|---|
| A canary whose host does not exist | `check` refused: "The page could not be read cleanly (timeout, server error or blocked), so nothing was recorded." (tx `0x749af819...`); the canary stays `unchecked` with 0 checks and 0 events |
| A deliberately old statement ([`demo/OLD.txt`](demo/OLD.txt), signed 2026-10-05, `max_age_days` 3) | `stale`, newest date 2026-10-05 |
| `register` with a `|` in the URL (the id-collision attempt) | Refused: "url contains a forbidden character" (tx `0x635ef580...`) |
| `get_count` and `get_ids(0, 3)` | 7 canaries registered; the first three ids, no unbounded listing |

## Development

```bash
pip install -r requirements.txt
genvm-lint check contracts/canary.py
python -m pytest tests/direct/ -v
```

`scripts/live.mjs` registers, checks and reads canaries on Bradbury. It signs with a testnet wallet kept outside the repo.

## License

MIT
