from __future__ import annotations

import time

from vscommon.signing import sign, verify


def test_roundtrip() -> None:
    ts, sig = sign("secret", b'{"a":1}')
    assert verify("secret", b'{"a":1}', ts, sig)


def test_wrong_secret_rejected() -> None:
    ts, sig = sign("secret", b"body")
    assert not verify("other", b"body", ts, sig)


def test_tampered_body_rejected() -> None:
    ts, sig = sign("secret", b"body")
    assert not verify("secret", b"body-modified", ts, sig)


def test_replay_outside_window_rejected() -> None:
    old = int(time.time()) - 3600
    ts, sig = sign("secret", b"body", old)
    assert not verify("secret", b"body", ts, sig)
