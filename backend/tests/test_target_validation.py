from security.target_validation import validate_repo_target, validate_target


def test_validate_target_blocks_private_ranges():
    ok, reason = validate_target("127.0.0.1")
    assert not ok
    assert "blocked" in reason.lower() or "private" in reason.lower()


def test_validate_target_accepts_public_hostname():
    ok, reason = validate_target("example.com")
    assert ok
    assert reason == "ok"


def test_validate_target_rejects_bad_hostname():
    ok, reason = validate_target("bad host name")
    assert not ok
    assert "invalid" in reason.lower()


def test_validate_repo_target_rejects_invalid_scheme():
    ok, reason = validate_repo_target("/tmp/project")
    assert not ok
    assert "repo:" in reason.lower() or "file://" in reason.lower()
