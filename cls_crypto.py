"""
cls_crypto.py
=============
CLSEngine — Certificateless Signature (CLS) module for anonymous
authentication in the Healthcare IoT blockchain framework.

Mathematical foundation: NIST P-256 (secp256r1) elliptic curve.
No external dependencies beyond Python stdlib.

Scheme: Adapted from
  Qiao et al., "A Provably Secure Certificateless Signature Scheme With
  Anonymity for Healthcare IIoT", IEEE IoT Journal, Jul 2025.
  Wang et al., "Blockchain-Based Certificateless Conditional Anonymous
  Authentication for IIoT", IEEE Systems Journal, Mar 2024.

Key relationships
─────────────────
  PKG master:   s ∈ Zₙ (secret),  Ppub = s·G (public)
  User secret:  x ∈ Zₙ,  X = x·G
  PKG partial:  r ∈ Zₙ,  R = r·G,  d = r + s·H₁(ID,R,X) mod n
  User SK = (x, d),  PK = (X, R)
  Pseudo-ID:    pid = H₀(ID ‖ r·Ppub)  — only PKG can invert

Sign(m, SK, pid):
  t ∈ Zₙ random,  T = t·G
  h₁ = H("h1" ‖ m ‖ T ‖ pid) mod n
  h₂ = H("h2" ‖ m ‖ X ‖ pid) mod n
  σ  = (t + h₁·d + h₂·x) mod n
  signature = { T, σ, pid }

Verify(m, sig, PK, pid, h1_val, Ppub):
  h₁ = H("h1" ‖ m ‖ T ‖ pid) mod n
  h₂ = H("h2" ‖ m ‖ X ‖ pid) mod n
  Check:  σ·G  ==  T + h₁·(R + h1_val·Ppub) + h₂·X

BatchVerify([items]) — Wang et al. BCCA:
  Random λᵢ per item (prevents rogue-key attack):
  (Σ λᵢσᵢ)·G  ==  Σ λᵢ·[Tᵢ + h₁ᵢ·(Rᵢ + h1_valᵢ·Ppub) + h₂ᵢ·Xᵢ]
"""

import hashlib
import secrets
import threading
from typing import Optional, List, Dict, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# NIST P-256 (secp256r1) curve parameters
# ─────────────────────────────────────────────────────────────────────────────
_P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_G  = (_GX, _GY)
_INF = None   # Represents the point at infinity


# ─────────────────────────────────────────────────────────────────────────────
# Low-level P-256 arithmetic
# ─────────────────────────────────────────────────────────────────────────────

def _modinv(a: int, m: int) -> int:
    """Modular inverse via Extended Euclidean Algorithm."""
    a = a % m
    if a == 0:
        raise ZeroDivisionError("modular inverse of 0")
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        ratio = high // low
        lm, low, hm, high = hm - lm * ratio, high - low * ratio, lm, low
    return lm % m


def _point_add(P1, P2):
    """Add two affine points on P-256.  Returns _INF for the identity."""
    if P1 is _INF:
        return P2
    if P2 is _INF:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return _INF          # P + (-P) = O
        # Point doubling
        m = (3 * x1 * x1 + _A) * _modinv(2 * y1, _P) % _P
    else:
        m = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k: int, P) -> object:
    """Scalar multiplication k·P using left-to-right double-and-add."""
    if P is _INF or k == 0:
        return _INF
    k = k % _N
    if k == 0:
        return _INF
    result = _INF
    addend = P
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _pt_encode(P) -> str:
    """Encode a point as a 128-char hex string (uncompressed, no prefix)."""
    if P is _INF:
        return "inf"
    x, y = P
    return f"{x:064x}{y:064x}"


def _pt_decode(s: str):
    """Decode a point from its hex encoding."""
    if s == "inf":
        return _INF
    if len(s) != 128:
        raise ValueError(f"Invalid point encoding length {len(s)}")
    return (int(s[:64], 16), int(s[64:], 16))


def _hash_scalar(*parts) -> int:
    """SHA-256 hash of concatenated parts → integer in Zₙ."""
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, int):
            h.update(part.to_bytes(32, "big"))
        elif isinstance(part, str):
            h.update(part.encode("utf-8"))
        elif isinstance(part, bytes):
            h.update(part)
        elif isinstance(part, tuple) and len(part) == 2:
            h.update(_pt_encode(part).encode())
        else:
            h.update(str(part).encode("utf-8"))
    return int(h.hexdigest(), 16) % _N


# ─────────────────────────────────────────────────────────────────────────────
# CLSEngine
# ─────────────────────────────────────────────────────────────────────────────

class CLSEngine:
    """
    Certificateless Signature engine — PKG + client combined.

    Thread-safe, in-memory.  Integrates with app.py alongside KACUREngine.
    """

    def __init__(self):
        """Setup(1^λ) — PKG generates master key pair."""
        self._lock = threading.Lock()
        self._s    = secrets.randbelow(_N - 1) + 1   # master secret key
        self._Ppub = _point_mul(self._s, _G)          # Ppub = s·G

        # { identity -> { pk, pseudo_id, h1_val } }
        self._registry: Dict[str, dict] = {}

        # { identity -> { sk, pk, pseudo_id, h1_val } }  (session, post-login)
        self._session:  Dict[str, dict] = {}

        # Conditional anonymity: { pseudo_id -> real_id }  (PKG/Admin only)
        self._pseudo_to_real: Dict[str, str] = {}

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def Ppub_hex(self) -> str:
        """Serialised PKG public key (for embedding in blockchain records)."""
        return _pt_encode(self._Ppub)

    # ── PKG: Partial Key Extraction ───────────────────────────────────────

    def _partial_key_extract(self, identity: str, X) -> dict:
        """
        PartialKeyExtract(ID, X) — PKG issues partial key.
        Internal; called from user_key_gen.
        Returns { R_hex, d, pseudo_id, h1_val }.
        """
        r  = secrets.randbelow(_N - 1) + 1
        R  = _point_mul(r, _G)
        h1 = _hash_scalar("H1", identity, R, X)
        d  = (r + self._s * h1) % _N

        # Pseudo-identity: H₀(ID ‖ r·Ppub) — non-invertible without PKG
        rPpub      = _point_mul(r, self._Ppub)
        pseudo_id  = hashlib.sha256(
            (identity + _pt_encode(rPpub)).encode()
        ).hexdigest()[:32]

        with self._lock:
            self._pseudo_to_real[pseudo_id] = identity

        return {
            "R_hex":    _pt_encode(R),
            "d":        d,
            "pseudo_id": pseudo_id,
            "h1_val":   h1,
        }

    # ── User: Full Key Generation ─────────────────────────────────────────

    def user_key_gen(self, identity: str) -> dict:
        """
        UserKeyGen() — Generate a full key pair for a user.
        Idempotent: returns existing keys if already generated.
        Returns { sk, pk, pseudo_id, h1_val }.
        """
        with self._lock:
            if identity in self._session:
                return self._session[identity]

        x = secrets.randbelow(_N - 1) + 1
        X = _point_mul(x, _G)

        partial  = self._partial_key_extract(identity, X)
        d        = partial["d"]
        pseudo_id = partial["pseudo_id"]
        h1_val   = partial["h1_val"]

        key_data = {
            "sk":        {"x": x, "d": d},
            "pk":        {"X_hex": _pt_encode(X), "R_hex": partial["R_hex"]},
            "pseudo_id": pseudo_id,
            "h1_val":    h1_val,
        }
        with self._lock:
            self._session[identity]  = key_data
            self._registry[identity] = {
                "pk":        key_data["pk"],
                "pseudo_id": pseudo_id,
                "h1_val":    h1_val,
            }
        return key_data

    def get_or_create_keys(self, identity: str) -> dict:
        """Return existing session keys or generate new ones (convenience)."""
        existing = self._session.get(identity)
        if existing:
            return existing
        return self.user_key_gen(identity)

    # ── Signing ───────────────────────────────────────────────────────────

    def sign(self, message: str, identity: str) -> Optional[dict]:
        """
        Sign(m, SK, pid) — Produce a CLS signature.
        Returns { T_hex, sigma, pseudo_id } or None on error.
        """
        try:
            key_data  = self.get_or_create_keys(identity)
            sk        = key_data["sk"]
            pk        = key_data["pk"]
            pseudo_id = key_data["pseudo_id"]
            x, d      = sk["x"], sk["d"]
            X         = _pt_decode(pk["X_hex"])

            t  = secrets.randbelow(_N - 1) + 1
            T  = _point_mul(t, _G)
            h1 = _hash_scalar("h1_sign", message, T, pseudo_id)
            h2 = _hash_scalar("h2_sign", message, X, pseudo_id)
            sigma = (t + h1 * d + h2 * x) % _N

            return {
                "T_hex":    _pt_encode(T),
                "sigma":    sigma,
                "pseudo_id": pseudo_id,
            }
        except Exception as e:
            print(f"[CLS] sign() error for '{identity}': {e}")
            return None

    # ── Verification ──────────────────────────────────────────────────────

    def verify(self, message: str, signature: dict, identity: str) -> bool:
        """
        Verify(m, sig, ID, PK) — Single signature verification.
        Returns True iff signature is valid.
        """
        try:
            key_data = (self._session.get(identity)
                        or self._registry.get(identity))
            if key_data is None:
                print(f"[CLS] verify(): unknown identity '{identity}'")
                return False

            pk        = key_data["pk"]
            pseudo_id = key_data["pseudo_id"]
            h1_val    = key_data["h1_val"]
            X         = _pt_decode(pk["X_hex"])
            R         = _pt_decode(pk["R_hex"])
            T         = _pt_decode(signature["T_hex"])
            sigma     = int(signature["sigma"])

            h1 = _hash_scalar("h1_sign", message, T, pseudo_id)
            h2 = _hash_scalar("h2_sign", message, X, pseudo_id)

            lhs = _point_mul(sigma, _G)

            h1_Ppub  = _point_mul(h1_val, self._Ppub)
            R_plus   = _point_add(R, h1_Ppub)
            term1    = _point_mul(h1, R_plus)
            term2    = _point_mul(h2, X)
            rhs      = _point_add(T, _point_add(term1, term2))

            return lhs == rhs
        except Exception as e:
            print(f"[CLS] verify() error: {e}")
            return False

    # ── Batch Verification ────────────────────────────────────────────────

    def batch_verify(self, items: List[dict]) -> Tuple[bool, int, int]:
        """
        BatchVerify([{message, signature, identity}]) — Wang et al. BCCA.

        Uses per-item random coefficient λᵢ to prevent cancellation attacks.
        Checks:  (Σ λᵢσᵢ)·G  ==  Σ λᵢ·[Tᵢ + h₁ᵢ·(Rᵢ+h1_valᵢ·Ppub) + h₂ᵢ·Xᵢ]

        Returns (all_valid: bool, passed: int, failed: int).
        """
        if not items:
            return True, 0, 0

        passed = 0
        failed = 0
        lhs_acc = _INF
        rhs_acc = _INF

        try:
            for item in items:
                message   = item.get("message", "")
                signature = item.get("signature", {})
                identity  = item.get("identity", "")

                key_data = (self._session.get(identity)
                            or self._registry.get(identity))
                if key_data is None:
                    # Auto-initialise for demo — in production reject unknown ID
                    key_data = self.get_or_create_keys(identity)

                pk        = key_data["pk"]
                pseudo_id = key_data["pseudo_id"]
                h1_val    = key_data["h1_val"]
                X         = _pt_decode(pk["X_hex"])
                R         = _pt_decode(pk["R_hex"])
                T         = _pt_decode(signature.get("T_hex", _pt_encode(_G)))
                sigma     = int(signature.get("sigma", 0))

                h1 = _hash_scalar("h1_sign", message, T, pseudo_id)
                h2 = _hash_scalar("h2_sign", message, X, pseudo_id)
                lam = secrets.randbelow(_N - 1) + 1

                # LHS accumulate: Σ λᵢσᵢ·G
                lhs_term = _point_mul((lam * sigma) % _N, _G)
                lhs_acc  = _point_add(lhs_acc, lhs_term)

                # RHS accumulate: Σ λᵢ·[Tᵢ + h₁ᵢ·(Rᵢ+h1·Ppub) + h₂ᵢ·Xᵢ]
                h1_Ppub = _point_mul(h1_val, self._Ppub)
                R_plus  = _point_add(R, h1_Ppub)
                inner   = _point_add(T, _point_add(
                    _point_mul(h1, R_plus),
                    _point_mul(h2, X)
                ))
                rhs_acc = _point_add(rhs_acc, _point_mul(lam, inner))

            all_ok = (lhs_acc == rhs_acc)
            if all_ok:
                passed = len(items)
            else:
                # Identify individual failures (slower path, for reporting)
                for item in items:
                    ok = self.verify(item.get("message", ""),
                                     item.get("signature", {}),
                                     item.get("identity", ""))
                    if ok:
                        passed += 1
                    else:
                        failed += 1
            return all_ok, passed, failed
        except Exception as e:
            print(f"[CLS] batch_verify() error: {e}")
            return False, passed, len(items) - passed

    # ── Conditional Anonymity ─────────────────────────────────────────────

    def trace_identity(self, pseudo_id: str) -> Optional[str]:
        """
        Admin/PKG only: reveal the real identity behind a pseudo-ID.
        Returns the real_id string, or None if not found.
        """
        return self._pseudo_to_real.get(pseudo_id)

    def get_pseudo_id(self, identity: str) -> Optional[str]:
        """Return the pseudo-ID for a registered identity."""
        kd = self._session.get(identity) or self._registry.get(identity)
        return kd.get("pseudo_id") if kd else None

    def get_public_key_record(self, identity: str) -> Optional[dict]:
        """Return serialisable PK record for blockchain storage."""
        kd = self._session.get(identity)
        if not kd:
            return None
        return {
            "X_hex":    kd["pk"]["X_hex"],
            "R_hex":    kd["pk"]["R_hex"],
            "pseudo_id": kd["pseudo_id"],
        }

    def is_registered(self, identity: str) -> bool:
        """True if CLS keys have been generated for this identity."""
        return identity in self._session or identity in self._registry
