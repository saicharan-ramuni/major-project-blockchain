"""
batch_verify_test.py — Test the Batch Verify Telemetry API endpoint.
Make sure Flask app is running before executing this.
Usage:  python batch_verify_test.py

Why keys come from Flask:
  Each CLSEngine() generates a random master key (Ppub).
  Signatures must be created using keys tied to Flask's Ppub,
  otherwise Flask's verify() will reject them (different PKG).
  So: test registers with Flask's PKG → signs locally → Flask verifies.
"""
import json
import requests
from cls_crypto import CLSEngine

FLASK_URL = "http://127.0.0.1:5000"

# Local engine used ONLY for signing — keys come from Flask's PKG
local_engine = CLSEngine()

print("=" * 60)
print("  Batch Verify Telemetry API Test")
print("=" * 60)

# ── Step 1: Register each doctor with Flask's PKG ────────────
print("\n[1] Registering doctors with Flask PKG...")
records = []

try:
    for i in range(5):
        uid = f'doctor_{i}'

        # Get key material from Flask's PKG (server-side registration)
        reg_r = requests.get(f"{FLASK_URL}/api/cls_register/{uid}", timeout=10)
        if reg_r.status_code != 200:
            print(f"    ERROR registering {uid}: {reg_r.text}")
            raise SystemExit

        key_data = reg_r.json()

        # Import those keys into the local engine so we can sign
        local_engine.import_key_data(uid, key_data)

        print(f"    {uid} registered — pseudo-ID: {key_data['pseudo_id'][:16]}...")

except requests.exceptions.ConnectionError:
    print("\n  ERROR: Could not connect to Flask app.")
    print("  Make sure 'python app.py' is running first, then retry.")
    raise SystemExit

# ── Step 2: Sign telemetry records locally ────────────────────
print("\n[2] Signing telemetry records locally...")
for i in range(5):
    uid = f'doctor_{i}'
    msg = f'patient_A:class_{i}:2026-04-14:bp=120'
    sig = local_engine.sign(msg, uid)
    records.append({
        'identity':  uid,
        'message':   msg,
        'signature': sig,
    })
    print(f"    {uid} signed: {msg}")

# ── Step 3: Send to Flask for batch verification ──────────────
print(f"\n[3] Sending {len(records)} records to /api/batch_verify_telemetry ...")
r = requests.post(
    f"{FLASK_URL}/api/batch_verify_telemetry",
    json={'records': records},
    timeout=30
)
result = r.json()

print("\n[4] API Response:")
print(json.dumps(result, indent=4))

print("\n" + "=" * 60)
if result.get("all_valid"):
    print(f"  ALL {result['passed']} SIGNATURES VALID  (method: {result['method']})")
else:
    print(f"  BATCH FAILED — passed: {result['passed']}, failed: {result['failed']}")
print("=" * 60)

# ── Step 4: Tamper test ───────────────────────────────────────
print("\n[5] Tamper Test — injecting a bad record (wrong message)...")
tampered = []
for i, rec in enumerate(records):
    if i == 2:
        # Use original signature but swap the message
        tampered.append({
            'identity':  rec['identity'],
            'message':   'TAMPERED:malicious_data',
            'signature': rec['signature'],
        })
    else:
        tampered.append(rec)

r2 = requests.post(
    f"{FLASK_URL}/api/batch_verify_telemetry",
    json={'records': tampered},
    timeout=30
)
result2 = r2.json()

print("    Response:")
print(json.dumps(result2, indent=4))

print("\n" + "=" * 60)
if not result2.get("all_valid"):
    print("  TAMPER CORRECTLY DETECTED")
else:
    print("  WARNING: tamper was NOT detected")
print("=" * 60)
