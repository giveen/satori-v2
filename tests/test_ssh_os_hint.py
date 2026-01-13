import copy

from satori.host import Host
from satori.ssh_fingerprint import SSHFingerprint
from satori.ssh_os_hint import build_ssh_os_hint


def _make_host_with_ssh(ssh_fp: SSHFingerprint, ambiguity: dict | None = None) -> Host:
    h = Host(host_id="host:test", ips=set(["10.0.0.1"]), macs=set(), first_seen=None, last_seen=None, evidence=[], flows=set(["flow1"]), ambiguity=ambiguity or {})
    h.ssh_fingerprint = ssh_fp
    return h


def test_basic_mapping_openssh():
    prov = {"software_family": ["flowA"], "banner": ["flowA"]}
    sf = SSHFingerprint(
        ssh_banner=["OpenSSH_8.2p1"],
        ssh_software_family=["openssh"],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance=prov,
        confidence=0.8,
    )

    h = _make_host_with_ssh(sf)
    hints = build_ssh_os_hint(h)
    assert isinstance(hints, list)
    assert len(hints) == 1
    hint = hints[0]
    assert hint.os_family == "Linux"
    # base_conf 0.8 -> conf = 0.4 -> capped to 0.3
    assert hint.confidence == 0.3
    assert hint.provenance == ["flowA"]


def test_multiple_families_and_provenance():
    prov = {"software_family": ["f2"], "banner": ["f2"]}
    sf = SSHFingerprint(
        ssh_banner=["OpenSSH_7.9", "Dropbear_2018"],
        ssh_software_family=["openssh", "dropbear"],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance=prov,
        confidence=0.6,
    )

    h = _make_host_with_ssh(sf)
    hints = build_ssh_os_hint(h)
    assert len(hints) == 2
    families = [x.os_family for x in hints]
    assert set(families) == {"Linux", "Embedded-Linux"}
    # confidence: base 0.6 -> conf 0.3 (cap)
    assert all(x.confidence == 0.3 for x in hints)
    # provenance should include flow id from prov values
    for x in hints:
        assert "f2" in x.provenance


def test_ambiguity_penalty_applied():
    prov = {"software_family": ["flowX"], "banner": ["flowX"]}
    sf = SSHFingerprint(
        ssh_banner=["OpenSSH_8.0"],
        ssh_software_family=["openssh"],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance=prov,
        confidence=0.8,
    )

    h = _make_host_with_ssh(sf, ambiguity={"nat_suspected": True})
    hints = build_ssh_os_hint(h)
    assert len(hints) == 1
    # base_conf 0.8 -> conf 0.4 *0.6 = 0.24
    assert hints[0].confidence == 0.24


def test_empty_ssh_fingerprint_returns_empty_list():
    h = Host(host_id="host:none", ips=set(), macs=set(), first_seen=None, last_seen=None, evidence=[], flows=set(), ambiguity={})
    h.ssh_fingerprint = None
    hints = build_ssh_os_hint(h)
    assert hints == []


def test_unknown_banner_results_empty_hint_list():
    # Unknown banner with no detected family currently yields no hints
    prov = {"banner": ["flowZ"]}
    sf = SSHFingerprint(
        ssh_banner=["MySuperSSH_1.0"],
        ssh_software_family=[],
        kex_algorithms=[],
        hostkey_algorithms=[],
        encryption_algorithms_c2s=[],
        encryption_algorithms_s2c=[],
        mac_algorithms_c2s=[],
        mac_algorithms_s2c=[],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance=prov,
        confidence=0.5,
    )

    h = _make_host_with_ssh(sf)
    hints = build_ssh_os_hint(h)
    assert hints == []


def test_determinism_of_output():
    prov = {"software_family": ["fD"], "banner": ["fD"]}
    sf = SSHFingerprint(
        ssh_banner=["OpenSSH_9.0"],
        ssh_software_family=["openssh"],
        kex_algorithms=["kex1", "kex2"],
        hostkey_algorithms=["rsa"],
        encryption_algorithms_c2s=["aes128"],
        encryption_algorithms_s2c=["aes128"],
        mac_algorithms_c2s=["hmac-sha2-256"],
        mac_algorithms_s2c=["hmac-sha2-256"],
        compression_algorithms_c2s=[],
        compression_algorithms_s2c=[],
        first_kex_packet_follows_present=False,
        provenance=prov,
        confidence=0.9,
    )

    h = _make_host_with_ssh(sf)
    a = build_ssh_os_hint(h)
    b = build_ssh_os_hint(copy.deepcopy(h))
    assert len(a) == len(b)
    for x, y in zip(a, b):
        assert x.os_family == y.os_family
        assert x.confidence == y.confidence
        assert x.provenance == y.provenance
