from trustpatch.versions import classify_bump, is_major_change, version_key


def test_version_key_orders_numerically_not_lexically():
    assert version_key("2.9.0") < version_key("2.10.0")


def test_version_key_handles_wildcard_as_lowest():
    assert version_key("*") < version_key("0.0.1")


def test_is_major_change():
    assert is_major_change("1.2.3", "2.0.0") is True
    assert is_major_change("1.2.3", "1.9.0") is False


def test_classify_bump():
    assert classify_bump("1.2.3", "2.0.0") == "major"
    assert classify_bump("1.2.3", "1.3.0") == "minor"
    assert classify_bump("1.2.3", "1.2.4") == "patch"
    assert classify_bump("1.2.3", "1.2.3") == "equal"
    assert classify_bump("*", "1.2.3") == "unknown"
