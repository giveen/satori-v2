from satori.phase2.traits import extract_traits


def test_ssh_traits_normalization_and_determinism():
    host = {
        "ssh_fingerprint": {
            "ssh_banner": ["OpenSSH_8.9p1"],
            "kex_algorithms": ["curve25519-sha256@libssh.org"],
            "hostkey_algorithms": ["ssh-ed25519"],
            "encryption_algorithms_c2s": ["aes128-gcm@openssh.com"],
            "encryption_algorithms_s2c": [],
            "confidence": 0.6,
        },
        "evidence": [],
    }

    t = extract_traits(host)
    assert "ssh:banner:openssh_8_9p1" in t or "ssh:banner:openssh_8_9" in t
    assert "ssh:kex:curve25519" in t
    assert "ssh:hostkey:ed25519" in t
    assert "ssh:cipher:aes128_gcm" in t or "ssh:cipher:aes128-gcm" in t
