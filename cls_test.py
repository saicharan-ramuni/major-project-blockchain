"""
cls_test.py — Run this to verify the CLS module works correctly.
Usage:  python cls_test.py
"""
from cls_crypto import CLSEngine

e = CLSEngine()

print("=" * 55)
print("  CLS (Certificateless Signature) Module Test")
print("=" * 55)

# ── Registration ──────────────────────────────────────────
print("\n[1] Registration")
kd = e.user_key_gen('alice')
print("    pseudo-ID :", kd['pseudo_id'])
print("    Keys ready:", 'sk' in kd and 'pk' in kd)

# ── Sign & Verify ─────────────────────────────────────────
print("\n[2] Single Sign & Verify")
sig = e.sign('hello patient record', 'alice')
ok  = e.verify('hello patient record', sig, 'alice')
print("    Sign result  :", sig is not None)
print("    Verify (OK)  :", ok)           # Expected: True

# ── Tampered message should FAIL ──────────────────────────
print("\n[3] Tamper Detection")
bad = e.verify('tampered message', sig, 'alice')
print("    Tampered verify:", bad)        # Expected: False

# ── Batch Verify 5 users ──────────────────────────────────
print("\n[4] Batch Verify (5 doctors)")
items = []
for i in range(5):
    uid = f'doctor_{i}'
    e.user_key_gen(uid)
    msg = f'patient_X:class_{i}:2026-04-14'
    items.append({
        'identity':  uid,
        'message':   msg,
        'signature': e.sign(msg, uid)
    })

all_ok, passed, failed = e.batch_verify(items)
print(f"    all_valid : {all_ok}")
print(f"    passed    : {passed}")
print(f"    failed    : {failed}")

# ── Conditional Anonymity ─────────────────────────────────
print("\n[5] Conditional Anonymity (PKG Trace)")
pid  = e.get_pseudo_id('alice')
real = e.trace_identity(pid)
print(f"    pseudo-ID : {pid[:16]}...")
print(f"    real ID   : {real}")          # Expected: alice

# ── Summary ───────────────────────────────────────────────
print("\n" + "=" * 55)
all_passed = ok and not bad and all_ok and real == 'alice'
if all_passed:
    print("  ALL TESTS PASSED")
else:
    print("  SOME TESTS FAILED — check output above")
print("=" * 55)
