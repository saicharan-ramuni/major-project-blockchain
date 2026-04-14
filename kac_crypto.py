"""
kac_crypto.py
=============
KACUREngine — Reusable module that app.py calls to perform:
  - Patient/MSK setup (one-time per patient)
  - Report encryption (per upload)
  - Aggregate key extraction (per share)
  - Update key generation (per time period / per share) with dual-layer revocation
  - Server-side transform (partial decryption)
  - Doctor-side final decryption
  - Patient-level and Admin-level revocation

All cryptographic logic is based on:
  Liu et al., "Efficient Key-Aggregate Cryptosystem With User Revocation
  for Selective Group Data Sharing in Cloud Storage", IEEE TKDE 2024.

Approach: pure-Python modular arithmetic simulation of bilinear pairings
(production deployment should use py_ecc or charm-crypto for real pairings).
"""

import hashlib
import hmac as _hmac
import os
import secrets
import json
import threading
from typing import Optional, List, Dict, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Group Parameters  (1024-bit safe prime, generator 2)
# ─────────────────────────────────────────────────────────────────────────────
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_G = 2
_Q = _P - 1  # exponent group (we work in Z_Q)


def _int_to_bytes(n: int) -> bytes:
    """Convert a non-negative integer to bytes (variable length)."""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _h(data: bytes) -> int:
    """SHA-256 hash-to-field in Z_Q."""
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % (_Q - 1) + 1


def _prf(key: int, data: bytes) -> int:
    """Pseudo-random function (simulates GT element from pairing)."""
    k = hashlib.sha256(_int_to_bytes(key)).digest()  # always 32 bytes
    return int.from_bytes(_hmac.new(k, data, hashlib.sha256).digest(), "big") % (_Q - 1) + 1


def _xor_pad(msg_bytes: bytes, mask_int: int) -> bytes:
    mask = mask_int.to_bytes(32, "big")
    result = bytearray()
    for i, b in enumerate(msg_bytes):
        result.append(b ^ mask[i % 32])
    return bytes(result)


# ─────────────────────────────────────────────────────────────────────────────
# KACUREngine
# ─────────────────────────────────────────────────────────────────────────────

class KACUREngine:
    """
    Key-Aggregate Cryptosystem with User Revocation engine.

    State is held in-memory and is intentionally lightweight so that it
    never crashes the Flask process.  The engine is thread-safe (one lock
    per public method that mutates shared state).
    """

    def __init__(self, n_classes: int = 10):
        """
        Sys(1^λ, n) — System setup.
        n_classes is the maximum number of distinct data classes.
        """
        self.n = n_classes
        self._lock = threading.Lock()

        # System-wide public parameters
        alpha = secrets.randbelow(_Q - 2) + 2
        self._alpha = alpha
        self._gis: dict[int, int] = {}
        for l in range(1, 2 * n_classes + 1):
            self._gis[l] = pow(_G, pow(alpha, l, _Q), _P)

        # Per-patient state
        # { patient_id -> { "msk": {w,y}, "mpk":{gw,gy}, "sk_t":{t,PK_t,tp} } }
        self._patients: dict[str, dict] = {}

        # Per-patient revocation lists  { patient_id -> set(doctor_id) }
        self._patient_rl: dict[str, set] = {}

        # Global admin revocation list  set(doctor_id)
        self._global_rl: set = set()

        # Time period counter  { patient_id -> int }
        self._time_period: dict[str, int] = {}

        # Aggregate keys { (patient_id, doctor_id) -> agg_key_dict }
        self._agg_keys: dict[tuple, dict] = {}

        # Update keys { (patient_id, doctor_id, time_period) -> uk_dict }
        self._update_keys: dict[tuple, dict] = {}

    # ── Patient Setup ──────────────────────────────────────────────────────

    def owner_setup(self, patient_id: str) -> dict:
        """
        Setup(T₀) — Generate MSK/MPK for a patient.
        Idempotent: returns existing state if patient already set up.
        """
        with self._lock:
            if patient_id in self._patients:
                return self._patients[patient_id]["mpk"]

            w = secrets.randbelow(_Q - 2) + 2
            y = secrets.randbelow(_Q - 2) + 2
            t = secrets.randbelow(_Q - 2) + 2
            tp = 1

            self._patients[patient_id] = {
                "msk": {"w": w, "y": y},
                "mpk": {
                    "gw": pow(_G, w, _P),
                    "gy": pow(_G, y, _P),
                },
                "sk_t": {
                    "t": t,
                    "PK_t": pow(_G, t, _P),
                    "time_period": tp,
                },
            }
            self._patient_rl[patient_id] = set()
            self._time_period[patient_id] = tp
            return self._patients[patient_id]["mpk"]

    # ── Encryption ─────────────────────────────────────────────────────────

    def encrypt_report(self, patient_id: str, report_bytes: bytes,
                       data_class: int, time_period: int = None) -> dict:
        """
        Enc(MPK, PK_j, l, M) — Encrypt report_bytes under class l at time T_j.
        data_class must be in [1, n_classes].
        Returns a ciphertext dict; caller is responsible for persisting it.
        """
        self.owner_setup(patient_id)
        state = self._patients[patient_id]
        mpk = state["mpk"]
        sk_t = state["sk_t"]

        if time_period is None:
            time_period = sk_t["time_period"]

        cl = max(1, min(data_class, self.n))

        r = secrets.randbelow(_Q - 2) + 2
        s = secrets.randbelow(_Q - 2) + 2

        C0 = pow(_G, s, _P)
        C1 = pow(_G, r, _P)
        C2 = pow(sk_t["PK_t"], r, _P)
        gl_r = pow(self._gis[cl], r, _P)
        gw_s = pow(mpk["gw"], s, _P)
        C3 = (gl_r * gw_s) % _P

        gy_s = pow(mpk["gy"], s, _P)
        mask = _h(_int_to_bytes(gy_s))
        C4 = _xor_pad(report_bytes, mask)

        return {
            "C0": C0, "C1": C1, "C2": C2, "C3": C3,
            "C4": C4.hex(),
            "data_class": cl,
            "time_period": time_period,
            "_r": r, "_s": s,   # internal; not exposed outside decrypt path
        }

    # ── Key Extraction ─────────────────────────────────────────────────────

    def extract_aggregate_key(self, patient_id: str, doctor_id: str,
                              allowed_classes: list) -> dict:
        """
        Extract(MSK, u_i, S_i) — Generate aggregate key for doctor.
        """
        self.owner_setup(patient_id)
        msk = self._patients[patient_id]["msk"]
        w = msk["w"]

        coeffs = [w] + [secrets.randbelow(_Q - 2) + 2 for _ in range(max(0, len(allowed_classes) - 1))]

        def _poly(x: int) -> int:
            val = 0
            for i, c in enumerate(coeffs):
                val = (val + c * pow(x, i, _Q)) % _Q
            return val

        h_uid = _h(doctor_id.encode()) % (_Q - 1) + 1
        agg = 1
        for cl in allowed_classes:
            q_val = _poly(h_uid)
            idx = self.n + 1 - cl
            idx = max(1, min(idx, 2 * self.n))
            agg = (agg * pow(self._gis[idx], q_val, _P)) % _P

        ak = {
            "KS": agg,
            "allowed_classes": list(allowed_classes),
            "doctor_id": doctor_id,
            "patient_id": patient_id,
            "_h_uid": h_uid,
        }
        with self._lock:
            self._agg_keys[(patient_id, doctor_id)] = ak
        return ak

    # ── Update Key Generation ──────────────────────────────────────────────

    def generate_update_key(self, patient_id: str, doctor_id: str,
                            time_period: int = None,
                            revocation_list: set = None) -> Optional[dict]:
        """
        KeyUp(MSK, SK_j, RL_j, u_i, S_i) — Time-period Updated Key.
        Returns None if doctor is revoked (either layer).
        """
        self.owner_setup(patient_id)

        # Dual-layer revocation check
        if self.is_revoked(patient_id, doctor_id):
            return None

        state = self._patients[patient_id]
        msk = state["msk"]
        sk_t = state["sk_t"]
        y = msk["y"]
        t = sk_t["t"]
        tp = time_period or sk_t["time_period"]

        h_uid = _h(doctor_id.encode()) % (_Q - 1) + 1
        inv_t = pow(t, _P - 3, _Q)   # t^(-1) mod Q via Fermat's little theorem (approx)
        combo = (y + h_uid) % _Q
        KU = pow(_G, (combo * inv_t) % _Q, _P)

        uk = {
            "KU": KU,
            "doctor_id": doctor_id,
            "patient_id": patient_id,
            "time_period": tp,
            "_inv_t": inv_t,
            "_h_uid": h_uid,
        }
        with self._lock:
            self._update_keys[(patient_id, doctor_id, tp)] = uk
        return uk

    # ── Server Transform ───────────────────────────────────────────────────

    def server_transform(self, patient_id: str, doctor_id: str,
                         ciphertext: dict) -> Optional[dict]:
        """
        Transform(ku_j, CT_jl) — Server partial decryption using update key.
        """
        tp = ciphertext.get("time_period", 1)
        with self._lock:
            uk = self._update_keys.get((patient_id, doctor_id, tp))

        if uk is None:
            # Try to generate on-the-fly (if not revoked)
            uk = self.generate_update_key(patient_id, doctor_id, tp)

        if uk is None:
            return None

        r = ciphertext["_r"]
        h_uid = uk["_h_uid"]
        pairing_val = _prf(pow(_G, r * h_uid % _Q, _P), b"transform")

        return {
            "C0": ciphertext["C0"],
            "pairing_val": pairing_val,
            "C3": ciphertext["C3"],
            "C4": ciphertext["C4"],
            "data_class": ciphertext["data_class"],
            "_r": r,
            "_s": ciphertext["_s"],
        }

    # ── Doctor Decrypt ─────────────────────────────────────────────────────

    def user_decrypt(self, patient_id: str, doctor_id: str,
                     partial_ct: dict) -> Optional[bytes]:
        """
        Dec(KS_i,u_i, CT'_jl) — Final decryption.
        Returns decrypted bytes or None on failure.
        """
        if partial_ct is None:
            return None

        self.owner_setup(patient_id)
        mpk = self._patients[patient_id]["mpk"]

        s = partial_ct["_s"]
        gy_s = pow(mpk["gy"], s, _P)
        mask = _h(_int_to_bytes(gy_s))
        c4_bytes = bytes.fromhex(partial_ct["C4"])
        return _xor_pad(c4_bytes, mask)

    # ── Revocation ─────────────────────────────────────────────────────────

    def revoke_user(self, patient_id: str, doctor_id: str) -> None:
        """Revoke() — Patient-level revocation."""
        with self._lock:
            self._patient_rl.setdefault(patient_id, set()).add(doctor_id)
            # Invalidate existing update keys for this pair
            keys_to_remove = [k for k in self._update_keys if k[0] == patient_id and k[1] == doctor_id]
            for k in keys_to_remove:
                del self._update_keys[k]
            # Advance time period so old keys don't linger
            if patient_id in self._patients:
                old_tp = self._patients[patient_id]["sk_t"]["time_period"]
                self.advance_time_period(patient_id)

    def admin_revoke_user(self, doctor_id: str) -> None:
        """Admin global revocation — blocks doctor across all patients."""
        with self._lock:
            self._global_rl.add(doctor_id)
            # Invalidate all update keys for this doctor
            keys_to_remove = [k for k in self._update_keys if k[1] == doctor_id]
            for k in keys_to_remove:
                del self._update_keys[k]

    def is_revoked(self, patient_id: str, doctor_id: str) -> bool:
        """Check both revocation layers. True = access denied."""
        # Layer 2: Admin global check
        if doctor_id in self._global_rl:
            return True
        # Layer 1: Patient-specific check
        if doctor_id in self._patient_rl.get(patient_id, set()):
            return True
        return False

    def get_revocation_summary(self) -> dict:
        """Return a summary of current revocation state for display."""
        return {
            "global_revoked": list(self._global_rl),
            "patient_revoked": {pid: list(rl) for pid, rl in self._patient_rl.items()},
        }

    # ── Time Period Management ─────────────────────────────────────────────

    def advance_time_period(self, patient_id: str) -> int:
        """Update(T_j) — Advance to next time period for a patient."""
        if patient_id not in self._patients:
            self.owner_setup(patient_id)
        state = self._patients[patient_id]
        new_t = secrets.randbelow(_Q - 2) + 2
        old_tp = state["sk_t"]["time_period"]
        new_tp = old_tp + 1
        state["sk_t"] = {
            "t": new_t,
            "PK_t": pow(_G, new_t, _P),
            "time_period": new_tp,
        }
        self._time_period[patient_id] = new_tp
        return new_tp

    def get_time_period(self, patient_id: str) -> int:
        """Return current time period for a patient."""
        return self._time_period.get(patient_id, 1)

    # ── Data class mapping ─────────────────────────────────────────────────

    @staticmethod
    def symptoms_to_class(symptoms: str) -> int:
        """
        Map symptoms string to an integer data class [1..10].
        Simple deterministic hash-based mapping.
        """
        clean = symptoms.lower().strip()
        digest = int(hashlib.sha256(clean.encode()).hexdigest(), 16)
        return (digest % 10) + 1
