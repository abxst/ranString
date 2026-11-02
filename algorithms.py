"""Registry of hash / checksum / KDF / cipher algorithms for ranString.

Every entry is an `Algo`: metadata for the UI plus a `run(data, rounds, size)`
callable returning `(output, extra)`. Optional libraries are imported lazily;
a missing library just drops its group instead of breaking the app.
"""
import base64
import hashlib
import hmac
import secrets
import string
import time
import zlib
from dataclasses import dataclass, replace
from typing import Callable, Optional

MAX_LENGTH = 4096
MAX_TEXT_BYTES = 65536
_ALPHABET = string.ascii_letters + string.digits

GROUPS = [
    "Hash",
    "Hash (extended)",
    "Checksum",
    "HMAC",
    "KDF / password hash",
    "Crypt schemes",
    "Cipher",
    "Encoding",
]


@dataclass(frozen=True)
class Param:
    min: int
    max: int
    default: int
    label: str

    def to_dict(self):
        return {"min": self.min, "max": self.max, "default": self.default, "label": self.label}


@dataclass(frozen=True)
class Algo:
    id: str
    group: str
    label: str
    run: Callable[[bytes, int, int], tuple]
    rounds: Optional[Param] = None
    digest_size: Optional[Param] = None
    complexity: int = 0

    def to_dict(self):
        return {
            "id": self.id,
            "label": self.label,
            "complexity": self.complexity,
            "rounds": self.rounds.to_dict() if self.rounds else None,
            "digest_size": self.digest_size.to_dict() if self.digest_size else None,
        }


REGISTRY: dict = {}


def _add(id, group, label, run, rounds=None, size=None):
    REGISTRY[id] = Algo(id, group, label, run, rounds, size)


# --------------------------------------------------------------------------
# Hash (hashlib, discovered at runtime)
# --------------------------------------------------------------------------
HASH_ITER = Param(1, 100_000, 1, "Số lần hash lặp lại")
_VAR_SIZE = {
    "shake_128": Param(1, 1024, 32, "Độ dài output (byte)"),
    "shake_256": Param(1, 1024, 64, "Độ dài output (byte)"),
    "blake2b": Param(1, 64, 64, "Độ dài output (byte)"),
    "blake2s": Param(1, 32, 32, "Độ dài output (byte)"),
}
_ALIAS_SKIP = {"blake2b512", "blake2s256"}


def _digest(name, data, size=None):
    if name in ("blake2b", "blake2s"):
        return getattr(hashlib, name)(data, digest_size=size).digest()
    h = hashlib.new(name, data)
    if name.startswith("shake_"):
        return h.digest(size)
    return h.digest()


def _hashlib_names():
    names = []
    for n in sorted({n.lower() for n in hashlib.algorithms_available}):
        if n in _ALIAS_SKIP or ("-" in n and n != "md5-sha1"):
            continue
        try:
            _digest(n, b"", _VAR_SIZE[n].default if n in _VAR_SIZE else None)
        except Exception:
            continue
        names.append(n)
    return names


def _register_hashlib():
    for name in _hashlib_names():
        def run(data, rounds, size, name=name):
            d = data
            for _ in range(rounds):
                d = _digest(name, d, size)
            return d.hex(), {}
        _add(f"hash:{name}", "Hash", name, run, HASH_ITER, _VAR_SIZE.get(name))
        if name.startswith("shake_"):
            continue

        def hmac_run(data, rounds, size, name=name):
            key = secrets.token_bytes(32)
            return hmac.digest(key, data, name).hex(), {"key": key.hex()}
        _add(f"hmac:{name}", "HMAC", f"HMAC-{name}", hmac_run)


# --------------------------------------------------------------------------
# Hash (extended): pycryptodome / xxhash / blake3
# --------------------------------------------------------------------------
def _register_extended():
    try:
        from Crypto.Hash import MD2, MD4, RIPEMD160, keccak
    except ImportError:
        keccak = None
    else:
        def simple(mod):
            return lambda data, rounds, size: (mod.new(data).hexdigest(), {})
        _add("ext:md2", "Hash (extended)", "md2", simple(MD2))
        if "hash:md4" not in REGISTRY:
            _add("ext:md4", "Hash (extended)", "md4", simple(MD4))
        if "hash:ripemd160" not in REGISTRY:
            _add("ext:ripemd160", "Hash (extended)", "ripemd160", simple(RIPEMD160))
        for bits in (224, 256, 384, 512):
            _add(f"ext:keccak{bits}", "Hash (extended)", f"keccak-{bits}",
                 lambda data, rounds, size, b=bits: (keccak.new(digest_bits=b, data=data).hexdigest(), {}))
    try:
        from Crypto.Hash import KangarooTwelve
    except ImportError:
        pass
    else:
        _add("ext:k12", "Hash (extended)", "KangarooTwelve",
             lambda data, rounds, size: (KangarooTwelve.new(data=data).read(size).hex(), {}),
             size=Param(1, 1024, 32, "Độ dài output (byte)"))
    try:
        import xxhash
    except ImportError:
        pass
    else:
        for n in ("xxh32", "xxh64", "xxh3_64", "xxh3_128"):
            _add(f"ext:{n}", "Hash (extended)", n,
                 lambda data, rounds, size, n=n: (getattr(xxhash, n)(data).hexdigest(), {}))
    try:
        import blake3
    except ImportError:
        pass
    else:
        _add("ext:blake3", "Hash (extended)", "blake3",
             lambda data, rounds, size: (blake3.blake3(data).hexdigest(length=size), {}),
             size=Param(1, 1024, 32, "Độ dài output (byte)"))


# --------------------------------------------------------------------------
# Checksum
# --------------------------------------------------------------------------
def _register_checksums():
    _add("sum:crc32", "Checksum", "crc32",
         lambda data, rounds, size: (f"{zlib.crc32(data):08x}", {}))
    _add("sum:adler32", "Checksum", "adler32",
         lambda data, rounds, size: (f"{zlib.adler32(data):08x}", {}))


# --------------------------------------------------------------------------
# KDF / password hash
# --------------------------------------------------------------------------
_DKLEN = Param(1, 128, 32, "Độ dài output (byte)")


def _register_kdfs():
    for name in ("sha1", "sha256", "sha384", "sha512", "sha3_256", "blake2b"):
        if f"hash:{name}" not in REGISTRY:
            continue

        def pbkdf2(data, rounds, size, name=name):
            salt = secrets.token_bytes(16)
            out = hashlib.pbkdf2_hmac(name, data, salt, rounds, dklen=size)
            return out.hex(), {"salt": salt.hex()}
        _add(f"kdf:pbkdf2-{name}", "KDF / password hash", f"PBKDF2-HMAC-{name}", pbkdf2,
             Param(1, 2_000_000, 100_000, "Số vòng (iterations)"), _DKLEN)

    if hasattr(hashlib, "scrypt"):
        def scrypt(data, rounds, size):
            salt = secrets.token_bytes(16)
            out = hashlib.scrypt(data, salt=salt, n=1 << rounds, r=8, p=1,
                                 maxmem=128 * 1024 * 1024, dklen=size)
            return out.hex(), {"salt": salt.hex(), "n": 1 << rounds, "r": 8, "p": 1}
        _add("kdf:scrypt", "KDF / password hash", "scrypt", scrypt,
             Param(4, 15, 14, "log2(N)"), _DKLEN)

    try:
        import argon2
    except ImportError:
        pass
    else:
        for label, typ in (("argon2id", argon2.Type.ID), ("argon2i", argon2.Type.I), ("argon2d", argon2.Type.D)):
            def a2(data, rounds, size, typ=typ):
                ph = argon2.PasswordHasher(time_cost=rounds, memory_cost=19456, parallelism=1, type=typ)
                return ph.hash(data), {}
            _add(f"kdf:{label}", "KDF / password hash", label, a2,
                 Param(1, 10, 3, "Time cost"))

    try:
        import bcrypt
    except ImportError:
        pass
    else:
        def bc(data, rounds, size):
            extra = {"note": "bcrypt chỉ dùng 72 byte đầu"} if len(data) > 72 else {}
            return bcrypt.hashpw(data[:72], bcrypt.gensalt(rounds)).decode(), extra
        _add("kdf:bcrypt", "KDF / password hash", "bcrypt", bc, Param(4, 15, 12, "Cost (log2 rounds)"))


# --------------------------------------------------------------------------
# Crypt schemes (passlib / libpass)
# --------------------------------------------------------------------------
_PASSLIB = [
    ("sha256_crypt", "SHA-256 crypt", Param(1000, 500_000, 5000, "Số vòng (rounds)")),
    ("sha512_crypt", "SHA-512 crypt", Param(1000, 500_000, 5000, "Số vòng (rounds)")),
    ("sha1_crypt", "SHA-1 crypt", Param(1000, 500_000, 100_000, "Số vòng (rounds)")),
    ("md5_crypt", "MD5 crypt", None),
    ("apr_md5_crypt", "Apache APR1 MD5", None),
    ("des_crypt", "DES crypt", None),
    ("phpass", "phpass (WordPress)", Param(7, 16, 9, "log2(rounds)")),
    ("nthash", "NTLM (NT hash)", None),
    ("lmhash", "LM hash", None),
    ("mysql41", "MySQL 4.1+", None),
    ("msdcc2", "MS Domain Cached Creds 2", None),
]


def _register_passlib():
    try:
        from passlib import hash as ph
    except ImportError:
        return
    for name, label, rounds in _PASSLIB:
        handler = getattr(ph, name, None)
        if handler is None:
            continue

        def run(data, rounds_, size, handler=handler, name=name, has_rounds=rounds is not None):
            h = handler.using(rounds=rounds_) if has_rounds else handler
            if name == "msdcc2":
                return h.hash(data, user="user"), {"user": "user"}
            return h.hash(data), {}
        _add(f"crypt:{name}", "Crypt schemes", label, run, rounds)


# --------------------------------------------------------------------------
# Symmetric ciphers (pycryptodome); key / iv are random and returned
# --------------------------------------------------------------------------
def _register_ciphers():
    try:
        from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20, ChaCha20_Poly1305, Salsa20
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad
    except ImportError:
        return

    def cbc(module, klen, block, key_fn=None):
        def run(data, rounds, size):
            key = key_fn() if key_fn else get_random_bytes(klen)
            iv = get_random_bytes(block)
            ct = module.new(key, module.MODE_CBC, iv).encrypt(pad(data, block))
            return ct.hex(), {"key": key.hex(), "iv": iv.hex()}
        return run

    def gcm(klen):
        def run(data, rounds, size):
            key = get_random_bytes(klen)
            c = AES.new(key, AES.MODE_GCM)
            ct, tag = c.encrypt_and_digest(data)
            return ct.hex(), {"key": key.hex(), "nonce": c.nonce.hex(), "tag": tag.hex()}
        return run

    def ctr(klen):
        def run(data, rounds, size):
            key = get_random_bytes(klen)
            c = AES.new(key, AES.MODE_CTR)
            return c.encrypt(data).hex(), {"key": key.hex(), "nonce": c.nonce.hex()}
        return run

    def stream(module, klen, nlen):
        def run(data, rounds, size):
            key, nonce = get_random_bytes(klen), get_random_bytes(nlen)
            ct = module.new(key=key, nonce=nonce).encrypt(data)
            return ct.hex(), {"key": key.hex(), "nonce": nonce.hex()}
        return run

    def chacha_poly(data, rounds, size):
        key = get_random_bytes(32)
        c = ChaCha20_Poly1305.new(key=key)
        ct, tag = c.encrypt_and_digest(data)
        return ct.hex(), {"key": key.hex(), "nonce": c.nonce.hex(), "tag": tag.hex()}

    for bits in (128, 192, 256):
        k = bits // 8
        _add(f"cipher:aes{bits}-cbc", "Cipher", f"AES-{bits}-CBC", cbc(AES, k, 16))
        _add(f"cipher:aes{bits}-gcm", "Cipher", f"AES-{bits}-GCM", gcm(k))
        _add(f"cipher:aes{bits}-ctr", "Cipher", f"AES-{bits}-CTR", ctr(k))
    _add("cipher:3des-cbc", "Cipher", "3DES-CBC",
         cbc(DES3, 24, 8, lambda: DES3.adjust_key_parity(get_random_bytes(24))))
    _add("cipher:blowfish-cbc", "Cipher", "Blowfish-CBC", cbc(Blowfish, 16, 8))
    _add("cipher:chacha20", "Cipher", "ChaCha20", stream(ChaCha20, 32, 12))
    _add("cipher:xchacha20", "Cipher", "XChaCha20", stream(ChaCha20, 32, 24))
    _add("cipher:salsa20", "Cipher", "Salsa20", stream(Salsa20, 32, 8))
    _add("cipher:chacha20-poly1305", "Cipher", "ChaCha20-Poly1305", chacha_poly)


# --------------------------------------------------------------------------
# Encodings (not encryption, kept in their own group)
# --------------------------------------------------------------------------
def _register_encodings():
    for id_, label, fn in (
        ("base64", "Base64", base64.b64encode),
        ("base64url", "Base64 URL-safe", base64.urlsafe_b64encode),
        ("base32", "Base32", base64.b32encode),
        ("base16", "Hex (Base16)", base64.b16encode),
        ("base85", "Base85", base64.b85encode),
        ("ascii85", "Ascii85", base64.a85encode),
    ):
        _add(f"enc:{id_}", "Encoding", label,
             lambda data, rounds, size, fn=fn: (fn(data).decode("ascii"), {}))


_register_hashlib()
_register_extended()
_register_checksums()
_register_kdfs()
_register_passlib()
_register_ciphers()
_register_encodings()


# --------------------------------------------------------------------------
# Complexity: a static 1-10 estimate of computational cost / strength.
# 1 = plain encoding, 10 = memory-hard password hashing (argon2).
# --------------------------------------------------------------------------
_COMPLEXITY_GROUP = {
    "Encoding": 1, "Checksum": 2, "Hash": 4, "Hash (extended)": 4,
    "HMAC": 5, "Cipher": 5, "Crypt schemes": 6, "KDF / password hash": 8,
}
_COMPLEXITY_ID = {
    "crypt:des_crypt": 3, "crypt:nthash": 3, "crypt:lmhash": 3, "crypt:mysql41": 3,
    "crypt:md5_crypt": 5, "crypt:apr_md5_crypt": 5,
    "crypt:sha256_crypt": 7, "crypt:sha512_crypt": 7,
    "cipher:3des-cbc": 6, "cipher:aes128-gcm": 6, "cipher:aes192-gcm": 6,
    "cipher:aes256-gcm": 6, "cipher:chacha20-poly1305": 6,
    "kdf:bcrypt": 8, "kdf:scrypt": 9,
    "kdf:argon2i": 10, "kdf:argon2d": 10, "kdf:argon2id": 10,
}
_WEAK_HASHES = {"md2", "md4", "md5", "sha1", "md5-sha1"}


def _hash_score(name):
    if name in _WEAK_HASHES:
        return 3
    if name.startswith(("sha3_", "shake_", "keccak")):
        return 5
    return 4


def _complexity(algo):
    if algo.id in _COMPLEXITY_ID:
        return _COMPLEXITY_ID[algo.id]
    kind, _, name = algo.id.partition(":")
    if kind == "hash":
        return _hash_score(name)
    if kind == "hmac":
        return _hash_score(name) + 1
    if kind == "ext":
        return 2 if name.startswith("xxh") else _hash_score(name)
    if kind == "kdf" and name.startswith("pbkdf2"):
        return 7
    return _COMPLEXITY_GROUP[algo.group]


for _id, _a in list(REGISTRY.items()):
    REGISTRY[_id] = replace(_a, complexity=_complexity(_a))


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def catalog():
    """Algorithms grouped for the UI, in GROUPS order."""
    out = []
    for group in GROUPS:
        items = sorted((a for a in REGISTRY.values() if a.group == group), key=lambda a: a.label)
        if items:
            out.append({"group": group, "items": [a.to_dict() for a in items]})
    return out


def _to_int(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{name} phải là số nguyên")
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} phải là số nguyên") from None


def _check(value, param, name):
    if value is None:
        return param.default
    value = _to_int(value, name)
    if not param.min <= value <= param.max:
        raise ValueError(f"{name} phải nằm trong khoảng {param.min}–{param.max}")
    return value


def generate(algorithm, length=16, rounds=None, digest_size=None, text=None):
    """Run one algorithm. Raises ValueError with a user-facing message on bad input."""
    algo = REGISTRY.get(algorithm)
    if algo is None:
        raise ValueError("Thuật toán không tồn tại")

    if text:
        if not isinstance(text, str):
            raise ValueError("text phải là chuỗi")
        data_str = text
        if len(data_str.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValueError(f"text tối đa {MAX_TEXT_BYTES} byte")
    else:
        n = 16 if length is None else _to_int(length, "length")
        if not 1 <= n <= MAX_LENGTH:
            raise ValueError(f"length phải nằm trong khoảng 1–{MAX_LENGTH}")
        data_str = "".join(secrets.choice(_ALPHABET) for _ in range(n))

    r = _check(rounds, algo.rounds, "rounds") if algo.rounds else None
    s = _check(digest_size, algo.digest_size, "digest_size") if algo.digest_size else None

    start = time.perf_counter()
    try:
        output, extra = algo.run(data_str.encode("utf-8"), r, s)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Không chạy được {algo.label}: {exc}") from exc
    elapsed = (time.perf_counter() - start) * 1000
    return {
        "input": data_str,
        "output": output,
        "extra": extra,
        "params": {"algorithm": algo.id, "rounds": r, "digest_size": s},
        "elapsed_ms": round(elapsed, 2),
    }
