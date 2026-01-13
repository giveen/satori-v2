from satori.nmap_lookup import parse_nmap_os_db_text


def test_parse_minimal():
    sample = """
# sample db
class os family vendor name
ttl 64
window 64240
"""
    out = parse_nmap_os_db_text(sample)
    assert isinstance(out, list)
    assert len(out) >= 1
    assert 'signature' in out[0]
