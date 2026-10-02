"""Tests for the relay-fetched, cached, monotonic pinned trust set (P3).

Everything is offline: the relay client is an injected callable, so these tests
never touch the network and never import electrum.
"""

from __future__ import annotations

import pytest

from trust_vendor.lsag import generate_key_pair
from trust_vendor.trustset import pin_trust_set, trust_set_content_hash
from trust_vendor.trustset_relay import (
    TrustSetEventError,
    cache_path,
    load_cache,
    load_or_fetch,
    parse_trust_set_event,
    save_cache,
)

SET_ID = "burger-vendors-berlin"


def member_keys(n: int = 5) -> list[bytes]:
    return [generate_key_pair()[1] for _ in range(n)]


def event_for(keys, *, set_id: str = SET_ID, created_at: int = 1790925000, kind: int = 30000) -> dict:
    """A kind-30000 event whose 'p' tags carry X-ONLY keys (64 hex) on purpose."""
    tags = [["d", set_id], ["title", "Berlin vendors vetted in person"]]
    for i, pk in enumerate(keys):
        # pk is already 33-byte compressed; the event carries the X-ONLY half on purpose
        tags.append(["p", pk[1:33].hex(), "", f"vendor-{i}", "met-in-person", "silver", "2030-01-01T00:00:00Z"])
    return {"kind": kind, "created_at": created_at, "content": "", "tags": tags, "id": "ab" * 32}


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def test_parses_members_and_lifts_xonly_keys_to_even_y_compressed():
    keys = member_keys()
    ts = parse_trust_set_event(event_for(keys))
    assert ts.set_id == SET_ID
    assert ts.description == "Berlin vendors vetted in person"
    assert len(ts.members) == len(keys)
    for member, pk in zip(ts.members, keys):
        assert len(member.public_key) == 33
        assert member.public_key == b"\x02" + pk[1:33]  # x-only key lifted to the even-y point
        assert member.basis == "met-in-person"
        assert member.tier == "silver"
        assert member.label.startswith("vendor-")
        assert member.expires_at == "2030-01-01T00:00:00Z"
    assert ts.published_at == "2026-10-02T07:10:00Z"


def test_content_hash_is_stable_across_parses():
    keys = member_keys()
    a = parse_trust_set_event(event_for(keys))
    b = parse_trust_set_event(event_for(keys))
    assert trust_set_content_hash(a) == trust_set_content_hash(b)
    assert pin_trust_set(a) == pin_trust_set(b)


def test_compressed_keys_are_accepted_as_is():
    keys = member_keys(2)
    ev = event_for(keys)
    ev["tags"] = [["d", SET_ID]] + [["p", pk.hex()] for pk in keys]
    ts = parse_trust_set_event(ev)
    assert [m.public_key for m in ts.members] == keys


@pytest.mark.parametrize("mutate, needle", [
    (lambda ev: ev.update(kind=1), "expected kind 30000"),
    (lambda ev: ev.update(tags=[["d", SET_ID]]), "no 'p' member tags"),
    (lambda ev: ev.update(tags=[["title", "x"], ["p", "aa" * 32]]), "no 'd' tag"),
    (lambda ev: ev.update(tags=[["d", SET_ID], ["p", "zz" * 32]]), "not hex"),
    (lambda ev: ev.update(tags=[["d", SET_ID], ["p", "00" * 32]]), "not a valid point"),
    (lambda ev: ev.pop("created_at"), "no created_at"),
    (lambda ev: ev.update(tags=[["d", SET_ID], ["p"]]), "without a pubkey"),
])
def test_malformed_events_are_rejected(mutate, needle):
    ev = event_for(member_keys(2))
    mutate(ev)
    with pytest.raises(TrustSetEventError) as e:
        parse_trust_set_event(ev)
    assert needle in str(e.value)


def test_wrong_set_id_from_relay_is_rejected(tmp_path):
    keys = member_keys()
    with pytest.raises(TrustSetEventError):
        load_or_fetch(fetch=lambda _sid: event_for(keys, set_id="someone-elses-set"),
                      set_id=SET_ID, cache_dir=str(tmp_path), now="2026-10-02T12:00:00Z")


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

def test_cache_round_trip(tmp_path):
    ts = parse_trust_set_event(event_for(member_keys()))
    path = cache_path(str(tmp_path), SET_ID)
    save_cache(path, ts)
    back = load_cache(path)
    assert back is not None
    assert trust_set_content_hash(back) == trust_set_content_hash(ts)
    import json
    assert json.loads(open(path).read())["content_hash"] == pin_trust_set(ts).content_hash


def test_load_cache_missing_file_is_none(tmp_path):
    assert load_cache(cache_path(str(tmp_path), "nope")) is None


# ---------------------------------------------------------------------------
# load_or_fetch — the monotonic-version rules
# ---------------------------------------------------------------------------

NOW = "2026-10-02T12:00:00Z"


def test_relay_newer_than_cache_wins_and_updates_the_cache(tmp_path):
    keys = member_keys()
    old = parse_trust_set_event(event_for(keys[:3], created_at=1790900000))
    save_cache(cache_path(str(tmp_path), SET_ID), old)

    new_event = event_for(keys, created_at=1790925000)
    res = load_or_fetch(fetch=lambda _sid: new_event, set_id=SET_ID, cache_dir=str(tmp_path), now=NOW)
    assert res.source == "relay" and res.warning is None
    assert len(res.trust_set.members) == len(keys)
    cached = load_cache(cache_path(str(tmp_path), SET_ID))
    assert cached is not None and len(cached.members) == len(keys)


def test_relay_older_than_cache_is_rejected_and_cache_kept(tmp_path):
    keys = member_keys()
    new = parse_trust_set_event(event_for(keys, created_at=1790925000))
    save_cache(cache_path(str(tmp_path), SET_ID), new)

    stale = event_for(keys[:2], created_at=1790900000)
    res = load_or_fetch(fetch=lambda _sid: stale, set_id=SET_ID, cache_dir=str(tmp_path), now=NOW)
    assert res.source == "cache"
    assert "older" in (res.warning or "")
    assert len(res.trust_set.members) == len(keys)          # pin did NOT move back


def test_future_dated_relay_event_is_rejected(tmp_path):
    keys = member_keys()
    cached = parse_trust_set_event(event_for(keys[:3], created_at=1790900000))
    save_cache(cache_path(str(tmp_path), SET_ID), cached)

    future = event_for(keys, created_at=2000000000)
    res = load_or_fetch(fetch=lambda _sid: future, set_id=SET_ID, cache_dir=str(tmp_path), now=NOW)
    assert res.source == "cache"
    assert "future" in (res.warning or "")


def test_relay_unavailable_falls_back_to_cache(tmp_path):
    keys = member_keys()
    cached = parse_trust_set_event(event_for(keys, created_at=1790900000))
    save_cache(cache_path(str(tmp_path), SET_ID), cached)

    res = load_or_fetch(fetch=lambda _sid: None, set_id=SET_ID, cache_dir=str(tmp_path), now=NOW)
    assert res.source == "cache"
    assert "unavailable" in (res.warning or "")


def test_no_cache_and_no_relay_is_an_error(tmp_path):
    with pytest.raises(TrustSetEventError):
        load_or_fetch(fetch=lambda _sid: None, set_id=SET_ID, cache_dir=str(tmp_path), now=NOW)


def test_no_cache_but_relay_works(tmp_path):
    res = load_or_fetch(fetch=lambda _sid: event_for(member_keys(4)),
                        set_id=SET_ID, cache_dir=str(tmp_path), now=NOW)
    assert res.source == "relay"
    assert len(res.trust_set.members) == 4
