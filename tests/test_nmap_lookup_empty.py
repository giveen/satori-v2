from satori.nmap_lookup import lookup_os_from_nmap


def test_empty_fingerprint():
    # missing or empty fingerprint returns empty list
    assert lookup_os_from_nmap({}, db_path="tests/data/nmap_test_db.json") == []
    assert lookup_os_from_nmap(None, db_path="tests/data/nmap_test_db.json") == []
