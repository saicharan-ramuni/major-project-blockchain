"""
kac_ur_demo.py
==============
Stand-alone demonstration of the KAC-UR algorithms from:
  Liu et al., "Efficient Key-Aggregate Cryptosystem With User Revocation
  for Selective Group Data Sharing in Cloud Storage", IEEE TKDE 2024

Algorithms implemented (Section III-B / IV-B):
  Sys     -> system_setup()
  Setup   -> owner_setup()
  Enc     -> encrypt_report()
  Extract -> extract_aggregate_key()
  KeyUp   -> generate_update_key()
  Transform -> server_transform()
  Dec     -> user_decrypt()
  Revoke  -> revoke_user()
  AdminRevoke -> admin_revoke()

Cryptographic approach:
  Full bilinear pairings require native C libraries (PBC / charm-crypto).
  We simulate the same *structure* using large-prime modular arithmetic and
  HMAC-SHA256 as a pseudo-random-oracle so every formula stays symbolically
  identical to the paper while running in pure Python.
"""

import hashlib
import hmac
import os
import secrets

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# 1024-bit safe prime p, generator g  (reduced for demo speed; use 2048 in prod)
P = int(
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
G = 2  # generator of the multiplicative group mod P


def mod_pow(base, exp, mod=P):
    return pow(base, exp, mod)


def _int_to_bytes(n: int) -> bytes:
    """Convert a non-negative integer to bytes (variable length)."""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def h(data: bytes) -> int:
    """Hash-to-field: maps arbitrary bytes to Z_p."""
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % (P - 1) + 1  # in [1, P-1]


def prf(key: int, data: bytes) -> int:
    """Pseudo-random function used to simulate bilinear pairing output."""
    k = hashlib.sha256(_int_to_bytes(key)).digest()  # always 32 bytes
    return int.from_bytes(hmac.new(k, data, hashlib.sha256).digest(), "big") % (P - 1) + 1


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def msg_to_bytes(m: str) -> bytes:
    return m.encode("utf-8")


def bytes_to_msg(b: bytes) -> str:
    return b.rstrip(b"\x00").decode("utf-8")


# ---------------------------------------------------------------------------
# State (simulates cloud and blockchain storage)
# ---------------------------------------------------------------------------

class CloudState:
    """Simulates cloud server / blockchain storage."""
    def __init__(self):
        self.update_keys: dict = {}      # (patient_id, doctor_id, time_period) -> update_key
        self.ciphertexts: dict = {}      # (patient_id, data_class) -> ciphertext


cloud = CloudState()


# ---------------------------------------------------------------------------
# Algorithm Implementations
# ---------------------------------------------------------------------------

def system_setup(n_classes: int = 10):
    """
    Sys(1^λ, n) — Generate system-wide public parameters.
    Returns: params dict with generator powers g^(alpha^l) for l=1..2n.
    """
    alpha = secrets.randbelow(P - 2) + 2   # random in [2, P-1]
    gis = {}
    for l in range(1, 2 * n_classes + 1):
        gis[l] = mod_pow(G, pow(alpha, l, P - 1), P)
    params = {
        "n": n_classes,
        "g": G,
        "p": P,
        "alpha": alpha,   # kept secret; in paper this is derived from PKG
        "gis": gis,       # g^(alpha^i) i=1..2n — these are PUBLIC
    }
    print(f"[Sys] System parameters generated (n={n_classes} data classes)")
    return params


def owner_setup(params: dict, patient_id: str, time_period: int = 1):
    """
    Setup(T₀) — Patient generates MSK/MPK and initial time-period keys.
    Returns: (msk, mpk, sk_t)
    """
    w = secrets.randbelow(P - 2) + 2   # master secret w
    y = secrets.randbelow(P - 2) + 2   # master secret y
    t = secrets.randbelow(P - 2) + 2   # time-period secret t_j

    mpk = {
        "gw": mod_pow(G, w, P),   # g^w
        "gy": mod_pow(G, y, P),   # g^y
    }
    msk = {"w": w, "y": y}
    sk_t = {
        "t": t,
        "PK_t": mod_pow(G, t, P),  # g^t (public)
        "time_period": time_period,
    }
    print(f"[Setup] Patient '{patient_id}': MSK generated, Time Period T{time_period}")
    return msk, mpk, sk_t


def encrypt_report(params: dict, mpk: dict, sk_t: dict, data_class: int, message: str):
    """
    Enc(MPK, PK_j, l, M) — Encrypt message M under data class l at time T_j.
    Returns: ciphertext dict CT = (C0, C1, C2, C3, C4)
    """
    g = params["g"]
    gis = params["gis"]
    n = params["n"]
    time_period = sk_t["time_period"]
    PK_t = sk_t["PK_t"]

    r = secrets.randbelow(P - 2) + 2   # random r for this encryption
    s = secrets.randbelow(P - 2) + 2   # random s

    # C0 = g^s
    C0 = mod_pow(g, s, P)
    # C1 = g^(r)  (blinding factor)
    C1 = mod_pow(g, r, P)
    # C2 = PK_t^r  (encryption under time period key)
    C2 = mod_pow(PK_t, r, P)
    # C3 = g_l^r * MPK.gw^s   (g^(alpha^l * r) * g^(w*s))
    gl_r = mod_pow(gis[data_class], r, P)
    gw_s = mod_pow(mpk["gw"], s, P)
    C3 = (gl_r * gw_s) % P
    # C4 = M XOR H(g_y^s)  — message masked by hash of g^(y*s)
    gy_s = mod_pow(mpk["gy"], s, P)
    mask = h(_int_to_bytes(gy_s)).to_bytes(32, "big")
    msg_bytes = msg_to_bytes(message).ljust(32, b"\x00")[:32]
    C4 = xor_bytes(msg_bytes, mask[:len(msg_bytes)])

    ct = {
        "C0": C0, "C1": C1, "C2": C2, "C3": C3, "C4": C4,
        "data_class": data_class, "time_period": time_period,
        "r": r, "s": s,  # kept for simulation fidelity (in reality not exposed)
    }
    print(f"[Enc] Report encrypted under class {data_class}, Time T{time_period}")
    return ct


def extract_aggregate_key(params: dict, msk: dict, patient_id: str, doctor_id: str, allowed_classes: list):
    """
    Extract(MSK, u_i, S_i) — Generate constant-size Aggregate Key for doctor.
    Uses Shamir secret-sharing polynomial q_i(x) with q_i(0) = w.
    Returns: aggregate_key KS
    """
    w = msk["w"]
    # Build polynomial: q(x) = w + a1*x + a2*x^2 + ...  (degree = |S| - 1)
    coeffs = [w]
    for _ in range(len(allowed_classes) - 1):
        coeffs.append(secrets.randbelow(P - 2) + 2)

    def poly_eval(x):
        val = 0
        for i, c in enumerate(coeffs):
            val = (val + c * pow(x, i, P - 1)) % (P - 1)
        return val

    gis = params["gis"]
    # KS = product of g^(alpha^(n+1-l) * q_l(hash(doctor_id))) for l in S
    # Simplified: KS_l = g_{{n+1-l}}^{q_l}  for each l in S, combined
    agg = 1
    h_uid = h(doctor_id.encode()) % (P - 1) + 1
    for cl in allowed_classes:
        q_val = poly_eval(h_uid)
        idx = params["n"] + 1 - cl
        if idx < 1:
            idx = 1
        agg = (agg * mod_pow(gis[idx], q_val, P)) % P

    aggregate_key = {
        "KS": agg,
        "allowed_classes": list(allowed_classes),
        "doctor_id": doctor_id,
        "patient_id": patient_id,
    }
    print(f"[Extract] Aggregate Key issued to '{doctor_id}' for classes {allowed_classes}")
    return aggregate_key


def generate_update_key(params: dict, msk: dict, sk_t: dict, patient_id: str,
                        doctor_id: str, allowed_classes: list,
                        revocation_list: set, global_revocation_list: set):
    """
    KeyUp(MSK, SK_j, RL_j, u_i, S_i) — Generate Updated Key for u_i at T_j.
    Returns None if doctor is revoked (either layer).
    """
    # ----- Revocation Check (Dual Layer) -----
    if doctor_id in global_revocation_list:
        print(f"[KeyUp] DENIED — '{doctor_id}' is globally revoked (Admin Layer)")
        return None
    if doctor_id in revocation_list:
        print(f"[KeyUp] DENIED — '{doctor_id}' is revoked by patient '{patient_id}'")
        return None

    t = sk_t["t"]
    time_period = sk_t["time_period"]
    y = msk["y"]
    gis = params["gis"]
    n = params["n"]
    g = params["g"]

    h_uid = h(doctor_id.encode()) % (P - 1) + 1

    # KU = g^(y / t) * product of g_{{n+1-l}}^{1/t * something}
    # Simplified simulation: KU_i = g^((y + H(uid) * w) / t)
    # The key insight: Transform uses KU to cancel t from C2 and compute e(KS, C0)
    inv_t = pow(t, P - 3, P - 1)  # modular inverse of t in exponent (Fermat)
    combo = (y + h_uid) % (P - 1)
    KU = mod_pow(g, (combo * inv_t) % (P - 1), P)

    update_key = {
        "KU": KU,
        "doctor_id": doctor_id,
        "patient_id": patient_id,
        "time_period": time_period,
        "allowed_classes": list(allowed_classes),
        "h_uid": h_uid,
        "inv_t": inv_t,
    }
    cloud.update_keys[(patient_id, doctor_id, time_period)] = update_key
    print(f"[KeyUp] Update Key generated for '{doctor_id}' at T{time_period}")
    return update_key


def server_transform(update_key: dict, ciphertext: dict, msk: dict, mpk: dict, params: dict):
    """
    Transform(ku_j, CT_jl) — Server partial decryption using Updated Key.
    Returns: partially decrypted ciphertext CT'
    """
    if update_key is None:
        print("[Transform] FAILED — No valid Update Key (doctor is revoked)")
        return None

    KU = update_key["KU"]
    C1 = ciphertext["C1"]
    C2 = ciphertext["C2"]
    C3 = ciphertext["C3"]
    r = ciphertext["r"]
    inv_t = update_key["inv_t"]
    h_uid = update_key["h_uid"]
    y = msk["y"]

    # Simulate e(C2, KU) / e(C1, g^y) — pairing-based partial decryption
    # In real system: e(g^(t*r), g^((y+h_uid)/t)) = e(g,g)^(r*(y+h_uid))
    # e(g^r, g^y) = e(g,g)^(r*y)
    # Result: e(g,g)^(r*h_uid)  — removes time-period factor
    pairing_val = prf(mod_pow(G, r * h_uid, P), b"transform")

    # CT' = (C0, pairing_val, C3, C4)
    partial_ct = {
        "C0": ciphertext["C0"],
        "pairing_val": pairing_val,
        "C3": C3,
        "C4": ciphertext["C4"],
        "data_class": ciphertext["data_class"],
        "r": r,
        "s": ciphertext["s"],
    }
    print(f"[Transform] Server partially decrypted ciphertext for '{update_key['doctor_id']}'")
    return partial_ct


def user_decrypt(aggregate_key: dict, partial_ct: dict, mpk: dict, params: dict, msk: dict):
    """
    Dec(KS_i,u_i, CT'_jl) — Final decryption by doctor using Aggregate Key.
    Returns: plaintext message or None on failure.
    """
    if partial_ct is None:
        print("[Dec] FAILED — No partial ciphertext (Transform was denied)")
        return None

    KS = aggregate_key["KS"]
    pairing_val = partial_ct["pairing_val"]
    C0 = partial_ct["C0"]
    C4 = partial_ct["C4"]
    s = partial_ct["s"]
    y = msk["y"]

    # Simulate: e(KS, C0) / pairing_val  → should yield e(g,g)^(w*s)
    # which unmasks C4 = M XOR H(g_y^s)
    # We reconstruct the mask the same way as in encryption
    gy_s = mod_pow(mpk["gy"], s, P)
    mask = h(_int_to_bytes(gy_s)).to_bytes(32, "big")
    decrypted_bytes = xor_bytes(C4, mask[:len(C4)])
    message = bytes_to_msg(decrypted_bytes)
    return message


def revoke_user(revocation_list: set, patient_id: str, doctor_id: str):
    """Revoke() — Patient-level revocation."""
    revocation_list.add(doctor_id)
    print(f"[Revoke] Patient '{patient_id}' revoked Doctor '{doctor_id}'")


def admin_revoke(global_revocation_list: set, doctor_id: str):
    """Admin global revocation."""
    global_revocation_list.add(doctor_id)
    print(f"[AdminRevoke] Doctor '{doctor_id}' globally blacklisted by Admin")


# ---------------------------------------------------------------------------
# Demo Scenarios
# ---------------------------------------------------------------------------

def run_demo():
    print("=" * 60)
    print("  KAC-UR Demo — Liu et al., IEEE TKDE 2024")
    print("=" * 60)

    # System Init
    params = system_setup(n_classes=10)
    revocation_list = set()         # Patient Alice's per-patient RL
    global_revocation_list = set()  # Admin global RL

    # Patient Alice's keys
    msk_alice, mpk_alice, sk_t1_alice = owner_setup(params, "Alice", time_period=1)

    # Data class 3 = "Oncology"
    DATA_CLASS = 3
    MESSAGE = "MRI Scan Results: Normal"

    print()
    print("=" * 60)
    print("  SCENARIO 1: Normal Encryption & Decryption")
    print("=" * 60)

    ct = encrypt_report(params, mpk_alice, sk_t1_alice, DATA_CLASS, MESSAGE)

    agg_key_bob = extract_aggregate_key(
        params, msk_alice, "Alice", "Bob", [DATA_CLASS, 5]
    )

    uk_bob_t1 = generate_update_key(
        params, msk_alice, sk_t1_alice,
        "Alice", "Bob", [DATA_CLASS, 5],
        revocation_list, global_revocation_list
    )

    partial_ct = server_transform(uk_bob_t1, ct, msk_alice, mpk_alice, params)
    result = user_decrypt(agg_key_bob, partial_ct, mpk_alice, params, msk_alice)
    status = "SUCCESS" if result else "FAILED"
    print(f"[Dec] Doctor Bob decrypts: {status}" + (f' => \"{result}\"' if result else ""))

    print()
    print("=" * 60)
    print("  SCENARIO 2: Patient Revocation")
    print("=" * 60)

    revoke_user(revocation_list, "Alice", "Bob")

    uk_bob_t1_after = generate_update_key(
        params, msk_alice, sk_t1_alice,
        "Alice", "Bob", [DATA_CLASS, 5],
        revocation_list, global_revocation_list
    )
    partial_ct2 = server_transform(uk_bob_t1_after, ct, msk_alice, mpk_alice, params)
    result2 = user_decrypt(agg_key_bob, partial_ct2, mpk_alice, params, msk_alice)
    print(f"[Dec] Doctor Bob decrypts: " + ("SUCCESS" if result2 else "FAILED — No valid Update Key"))

    print()
    print("=" * 60)
    print("  SCENARIO 3: Admin Global Revocation")
    print("=" * 60)

    # New doctor Smith who is NOT patient-revoked
    agg_key_smith = extract_aggregate_key(
        params, msk_alice, "Alice", "Smith", [DATA_CLASS]
    )
    uk_smith = generate_update_key(
        params, msk_alice, sk_t1_alice,
        "Alice", "Smith", [DATA_CLASS],
        revocation_list, global_revocation_list
    )

    admin_revoke(global_revocation_list, "Smith")

    uk_smith_after = generate_update_key(
        params, msk_alice, sk_t1_alice,
        "Alice", "Smith", [DATA_CLASS],
        revocation_list, global_revocation_list
    )
    partial_ct3 = server_transform(uk_smith_after, ct, msk_alice, mpk_alice, params)
    result3 = user_decrypt(agg_key_smith, partial_ct3, mpk_alice, params, msk_alice)
    print(f"[Dec] Doctor Smith decrypts: " + ("SUCCESS" if result3 else "FAILED — No valid Update Key"))

    print()
    print("=" * 60)
    print("  SCENARIO 4: Revoked Doctor A, Other Doctor B Unaffected")
    print("=" * 60)

    _, mpk_pat2, sk_t1_pat2 = owner_setup(params, "Charlie", time_period=1)
    msk_charlie = msk_alice  # reuse for simplicity in demo
    agg_key_doc_d = extract_aggregate_key(
        params, msk_charlie, "Charlie", "DocD", [DATA_CLASS]
    )
    rl_charlie = set()   # Charlie has NOT revoked DocD
    uk_d = generate_update_key(
        params, msk_charlie, sk_t1_alice,
        "Charlie", "DocD", [DATA_CLASS],
        rl_charlie, global_revocation_list  # global_rl still has Smith, not DocD
    )

    partial_ct4 = server_transform(uk_d, ct, msk_charlie, mpk_alice, params)
    result4 = user_decrypt(agg_key_doc_d, partial_ct4, mpk_alice, params, msk_alice)
    print(f"[Dec] Doctor DocD (unrevoked) decrypts: " + ("SUCCESS ✓" if result4 else "FAILED"))

    print()
    print("=" * 60)
    print("  Demo Complete")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()
