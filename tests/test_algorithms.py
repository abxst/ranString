import hashlib
import hmac
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms import REGISTRY, catalog, generate  # noqa: E402


def run(algo, text="abc", **kw):
    return generate(algo, text=text, **kw)


def test_known_vectors():
    assert run("hash:sha256")["output"] == hashlib.sha256(b"abc").hexdigest()
    assert run("hash:md5")["output"] == "900150983cd24fb0d6963f7d28e17f72"
    assert run("sum:crc32")["output"] == f"{zlib.crc32(b'abc'):08x}"
    assert run("enc:base64")["output"] == "YWJj"


def test_hash_iterations():
    once = hashlib.sha256(hashlib.sha256(b"abc").digest()).hexdigest()
    assert run("hash:sha256", rounds=2)["output"] == once


def test_variable_digest_size():
    assert len(run("hash:shake_128", digest_size=10)["output"]) == 20
    assert len(run("hash:blake2b", digest_size=16)["output"]) == 32


def test_hmac_roundtrip():
    r = run("hmac:sha256")
    key = bytes.fromhex(r["extra"]["key"])
    assert r["output"] == hmac.new(key, b"abc", "sha256").hexdigest()


def test_pbkdf2_roundtrip():
    r = run("kdf:pbkdf2-sha256", rounds=1000, digest_size=24)
    salt = bytes.fromhex(r["extra"]["salt"])
    assert r["output"] == hashlib.pbkdf2_hmac("sha256", b"abc", salt, 1000, 24).hex()


def test_aes_gcm_roundtrip():
    from Crypto.Cipher import AES
    r = run("cipher:aes256-gcm")
    e = r["extra"]
    c = AES.new(bytes.fromhex(e["key"]), AES.MODE_GCM, nonce=bytes.fromhex(e["nonce"]))
    assert c.decrypt_and_verify(bytes.fromhex(r["output"]), bytes.fromhex(e["tag"])) == b"abc"


def test_random_input_length():
    assert len(generate("hash:sha1", length=40)["input"]) == 40


def test_validation_errors():
    with pytest.raises(ValueError):
        generate("nope")
    with pytest.raises(ValueError):
        generate("hash:sha1", length=0)
    with pytest.raises(ValueError):
        generate("hash:sha1", length=5000)
    with pytest.raises(ValueError):
        generate("hash:sha1", length="abc")
    with pytest.raises(ValueError):
        generate("hash:sha256", rounds=10**9)
    with pytest.raises(ValueError):
        generate("hash:shake_128", digest_size=0)


def test_every_algorithm_runs_with_defaults():
    failures = []
    for algo in REGISTRY.values():
        try:
            generate(algo.id, length=12)
        except Exception as exc:
            failures.append(f"{algo.id}: {exc}")
    assert not failures, "\n".join(failures)


def test_catalog_shape():
    cat = catalog()
    assert cat and all(g["items"] for g in cat)
    assert sum(len(g["items"]) for g in cat) == len(REGISTRY)


def test_complexity_scores():
    assert all(1 <= a.complexity <= 10 for a in REGISTRY.values())
    c = {a.id: a.complexity for a in REGISTRY.values()}
    order = ["enc:base64", "sum:crc32", "hash:md5", "hash:sha256", "hash:sha3_256",
             "kdf:pbkdf2-sha256", "kdf:bcrypt", "kdf:scrypt", "kdf:argon2id"]
    scores = [c[i] for i in order if i in c]
    assert scores == sorted(scores) and scores[0] < scores[-1]
    assert all("complexity" in i for g in catalog() for i in g["items"])


def test_api():
    from app import app
    c = app.test_client()
    assert c.get("/").status_code == 200
    assert c.get("/api/algorithms").json
    ok = c.post("/api/generate", json={"algorithm": "hash:sha256", "text": "abc"})
    assert ok.json["output"] == hashlib.sha256(b"abc").hexdigest()
    bad = c.post("/api/generate", json={"algorithm": "hash:sha256", "rounds": 10**9})
    assert bad.status_code == 400 and "error" in bad.json
    assert c.post("/api/generate", data="x").status_code == 400
