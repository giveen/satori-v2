import builtins
from satori.nmap_lookup import download_nmap_os_db


def test_download_fallback(monkeypatch, tmp_path):
    # Simulate network failure by patching urlopen to raise
    def bad_open(*a, **k):
        raise Exception('network down')

    monkeypatch.setattr('urllib.request.urlopen', bad_open, raising=False)

    dest = tmp_path / 'nmap-os-db'
    res = download_nmap_os_db(str(dest))
    assert res is None
