# KAC-UR Implementation Plan — Dual-Layer Revocation
### Reference: Liu et al., "Efficient Key-Aggregate Cryptosystem With User Revocation for Selective Group Data Sharing in Cloud Storage", IEEE TKDE, Vol. 36, No. 11, Nov 2024

---

## Background & Problem Statement

Your current project encrypts patient reports using **AES-256-GCM** with a single shared key (`ENCRYPTION_KEY_B64` in `app.py`). When a patient shares a file with hospitals, the file is encrypted, stored on disk, and the sharing record is appended to the blockchain as a string. **There are two fundamental problems:**

1. **No Key Aggregation**: If a patient shares 10 files across 3 hospitals, there is no way to issue one compact key per hospital that selectively unlocks only the relevant files while keeping the rest secret. Currently every authorized party uses the same AES key.
2. **No Revocation**: Once a hospital is listed in a patient's sharing record, there is no mechanism to revoke their access. The hospital name stays in the blockchain string forever and the single AES key never changes.

The **KAC-UR** paper solves both problems. Below we map the paper's algorithms to your project and detail how each phase integrates.

---

## How the Paper Maps to Your Project

The paper defines **three entities**. Here is how they map:

| Paper Entity | Your Project Entity | Role |
|---|---|---|
| **Data Owner (DO)** | **Patient** | Encrypts and uploads medical reports. Controls who gets access. |
| **Data User (DU)** | **Doctor / Hospital** | Receives an aggregate key and decrypts shared reports. |
| **Cloud Server (CS)** | **Blockchain + Flask Server** | Stores ciphertexts and Updated Keys. Performs partial decryption (Transform). |

The paper defines **9 algorithms** (Section III-B, Definition 3). Here is how each one maps:

| Paper Algorithm | What It Does | Where It Will Live |
|---|---|---|
| `Sys(1λ, n)` | Generates system-wide public parameters (bilinear pairing group, generator) | `kac_crypto.py` → `system_setup()` |
| `Setup(T₀)` | Generates Master Public/Secret Key pair, initial time period key, empty revocation list | `kac_crypto.py` → `owner_setup()` |
| `Extract(MSK, uᵢ, Sᵢ)` | Patient generates a constant-size Aggregate Key for a specific doctor covering data classes Sᵢ | `kac_crypto.py` → `extract_aggregate_key()` |
| `Update(Tⱼ)` | Advances to new time period, generates new time-period secret | `kac_crypto.py` → `advance_time_period()` |
| `Enc(MPK, PKⱼ, l, M)` | Encrypts data M under class l and time period Tⱼ | `kac_crypto.py` → `encrypt_report()` |
| `Revoke(RLⱼ₋₁, Tⱼ, RIⱼ)` | Adds users to revocation list, deletes their updated keys | `kac_crypto.py` → `revoke_user()` + Smart Contract |
| `KeyUp(MSK, SKⱼ, RLⱼ, uᵢ, Sᵢ)` | Generates time-period Updated Key for unrevoked user uᵢ | `kac_crypto.py` → `generate_update_key()` |
| `Transform(kuⱼ, CTⱼₗ)` | Server partially decrypts ciphertext using the Updated Key | `kac_crypto.py` → `server_transform()` |
| `Dec(KSᵢ,uᵢ, CT'ⱼₗ)` | Doctor combines Aggregate Key + partially decrypted ciphertext to recover data | `kac_crypto.py` → `user_decrypt()` |

---

## Dual-Layer Revocation Design

The paper describes a single revocation list `RL` managed by the Data Owner. We extend this to **two layers**:

### Layer 1 — Patient Revocation (Granular)
- **Who triggers it**: The Patient (Data Owner)
- **What happens**: Patient stops generating `UpdateKey` for a specific doctor for *their own files only*
- **Example**: Patient Alice revokes Doctor Bob → Doctor Bob can no longer decrypt Alice's files, but can still access Patient Charlie's files (if Charlie hasn't revoked him)
- **Paper reference**: This is the standard `Revoke()` algorithm (Section IV-B), applied per-patient

### Layer 2 — Admin Revocation (Global)
- **Who triggers it**: The System Administrator
- **What happens**: Admin marks a doctor as globally revoked in the smart contract. The system stops generating `UpdateKey` for that doctor across *all patients*
- **Example**: Admin blacklists Doctor Bob → No patient's files are accessible to Doctor Bob anymore, regardless of individual patient settings
- **Implementation**: A `mapping(string => bool) isRevokedGlobal` in the smart contract

### Revocation Check Logic (Pseudocode)
```python
def can_access(patient_id, doctor_id):
    # Layer 2: Admin global check
    if smart_contract.isRevokedGlobal(doctor_id):
        return False
    # Layer 1: Patient-specific check  
    if smart_contract.isRevokedByPatient(patient_id, doctor_id):
        return False
    return True
```

---

## Phase 1: Standalone Cryptographic Demo

> **Goal**: Build a self-contained Python script that implements the KAC-UR algorithms from the paper so you can verify correctness in the terminal before touching the main app.

#### [NEW] `kac_ur_demo.py`

This script will simulate the full lifecycle described in the paper's Section IV-B:

**Step 1 — System Parameter Generation** (`Sys`)
- Generate a prime `p`, a cyclic group generator `g`, and compute `gₗ = g^(αˡ)` for l = 1..2n
- For practical Python implementation: we use modular arithmetic over a large prime field instead of full bilinear pairings (the logic is identical, the math is simulated)

**Step 2 — Owner Setup** (`Setup`)
- Patient generates Master Secret Key `MSK = (w, y)` and Master Public Key `MPK = (g^w, g^y)`
- Initialize time period T₀ with random secret `t₀`, public key `PK₀ = g^t₀`
- Initialize empty Revocation List `RL₀ = {}`

**Step 3 — Encrypt a Report** (`Enc`)
- Patient encrypts a medical report M under data class `l` (e.g., "Oncology") and current time period `Tⱼ`
- Output: Ciphertext `CTⱼₗ = (C₀, C₁, C₂, C₃, C₄)` as described in paper Section IV-B

**Step 4 — Extract Aggregate Key** (`Extract`)
- Patient generates a single Aggregate Key `K_{S,u}` for Doctor Bob covering classes S = {"Oncology", "Cardiology"}
- Uses random first-order polynomial `qᵢ(x)` where `qᵢ(0) = w` (Shamir secret sharing as per paper)

**Step 5 — Generate Update Key** (`KeyUp`)
- System generates Updated Key `kuⱼ_{S,u}` for Doctor Bob at time period Tⱼ
- This key is stored on the "Cloud Server" (blockchain in our case) — NOT sent privately to the doctor

**Step 6 — Server Transform** (`Transform`)
- Server uses Doctor Bob's Updated Key to partially decrypt the ciphertext
- Output: Partially decrypted ciphertext `CT'ⱼₗ`

**Step 7 — Doctor Decrypts** (`Dec`)
- Doctor Bob combines his Aggregate Key with the partially decrypted ciphertext to recover data M

**Step 8 — Revocation Demo**
- **Patient Revocation**: Patient Alice calls `Revoke()` for Doctor Bob → system stops generating UpdateKey for Bob → Bob's subsequent `Dec()` calls fail with "Access Denied"
- **Admin Revocation**: Admin calls `adminRevoke()` for Doctor Smith → all patients' files become inaccessible to Smith

**Console Output (Expected)**:
```
=== SCENARIO 1: Normal Encryption & Decryption ===
[Setup] System parameters generated (n=10 data classes)
[Setup] Patient Alice: MSK generated, Time Period T1
[Encrypt] Report encrypted under class "Oncology", Time T1
[Extract] Aggregate Key issued to Doctor Bob for classes: [Oncology, Cardiology]
[KeyUp] Update Key generated for Doctor Bob at T1
[Transform] Server partially decrypted ciphertext for Doctor Bob
[Dec] Doctor Bob decrypts: SUCCESS → "MRI Scan Results: Normal"

=== SCENARIO 2: Patient Revocation ===
[Revoke] Patient Alice revoked Doctor Bob
[KeyUp] DENIED — Doctor Bob is revoked by Patient Alice
[Dec] Doctor Bob decrypts: FAILED — No valid Update Key

=== SCENARIO 3: Admin Global Revocation ===
[AdminRevoke] Doctor Smith globally blacklisted
[KeyUp] DENIED — Doctor Smith is globally revoked
[Dec] Doctor Smith decrypts: FAILED — No valid Update Key
```

---

## Phase 2: Smart Contract Upgrade

> **Goal**: Modify `Report.sol` to track revocation state and time periods on-chain.

#### [MODIFY] [Report.sol](file:///c:/Users/kalya/Downloads/blockchain-based-anonymous-authentication-framework-for-healthcare/contracts/Report.sol)

**Current state** (41 lines): Stores `hospital_details`, `patient_details`, `prescription` as simple strings.

**Changes**:
```diff
 contract Report {
     string public hospital_details;
     string public patient_details;
     string public prescription;
+    string public revocation_details;    // Stores revocation records
+    uint256 public currentTimePeriod;    // Tracks the global time period (Tⱼ)
     
+    // Advance to next time period (called by admin or on schedule)
+    function advanceTimePeriod() public {
+        currentTimePeriod += 1;
+    }
+
+    // Get current time period
+    function getTimePeriod() public view returns (uint256) {
+        return currentTimePeriod;
+    }
+
+    // Store revocation records (admin_revoke#doctor or patient_revoke#patient#doctor)
+    function setRevocation(string memory rd) public {
+        revocation_details = rd;
+    }
+
+    function getRevocation() public view returns (string memory) {
+        return revocation_details;
+    }
```

> [!NOTE]
> We keep the existing string-append architecture (matching your current `setHospital`/`setPatient` pattern) for backward compatibility. Revocation records are stored as encrypted strings like: `admin_revoke#doctorname#date` or `patient_revoke#patientname#doctorname#date`.

#### [MODIFY] [2_deploy_contracts.js](file:///c:/Users/kalya/Downloads/blockchain-based-anonymous-authentication-framework-for-healthcare/migrations/2_deploy_contracts.js)
- No structural changes needed since we're adding functions to the same `Report` contract
- Will need to recompile and redeploy: `truffle compile && truffle migrate --reset`

---

## Phase 3: Crypto Module for Flask

> **Goal**: Port the verified `kac_ur_demo.py` logic into a reusable Python module.

#### [NEW] `kac_crypto.py`

This module exposes clean functions that `app.py` will call:

```python
# Core functions exposed by kac_crypto.py:

class KACUREngine:
    def __init__(self, n_classes=10):
        """Sys(1λ, n) — Generate system parameters"""
    
    def owner_setup(self, patient_id):
        """Setup(T₀) — Generate MSK/MPK for a patient"""
    
    def encrypt_report(self, patient_id, report_bytes, data_class, time_period):
        """Enc(MPK, PKⱼ, l, M) — Encrypt report under class and time"""
    
    def extract_aggregate_key(self, patient_id, doctor_id, allowed_classes):
        """Extract(MSK, uᵢ, Sᵢ) — Generate aggregate key for doctor"""
    
    def generate_update_key(self, patient_id, doctor_id, time_period, revocation_list):
        """KeyUp(MSK, SKⱼ, RLⱼ, uᵢ, Sᵢ) — Time-period key (None if revoked)"""
    
    def server_transform(self, update_key, ciphertext):
        """Transform(kuⱼ, CTⱼₗ) — Server partial decryption"""
    
    def user_decrypt(self, aggregate_key, partial_ciphertext):
        """Dec(KSᵢ,uᵢ, CT'ⱼₗ) — Final decryption by doctor"""
    
    def revoke_user(self, patient_id, doctor_id):
        """Revoke() — Patient-level revocation"""
    
    def admin_revoke_user(self, doctor_id):
        """Admin global revocation"""
    
    def is_revoked(self, patient_id, doctor_id):
        """Check both revocation layers"""
```

---

## Phase 4: Flask Application Integration

> **Goal**: Wire the KAC-UR crypto module into the existing Flask routes.

#### [MODIFY] [app.py](file:///c:/Users/kalya/Downloads/blockchain-based-anonymous-authentication-framework-for-healthcare/app.py)

**4a. Imports and Initialization**
```diff
+from kac_crypto import KACUREngine
+kac_engine = KACUREngine(n_classes=10)
```

**4b. Patient Report Upload** — [AddHealthAction](file:///c:/Users/kalya/Downloads/blockchain-based-anonymous-authentication-framework-for-healthcare/app.py#L297-L325) (line 297)
- **Current**: Encrypts file with shared AES key, saves as `.enc`
- **New**: Additionally encrypts a KAC-UR ciphertext envelope that ties the file to a `data_class` (derived from symptoms) and the `currentTimePeriod` from the smart contract
- Generates Aggregate Keys for each selected hospital
- Generates Update Keys for each unrevoked hospital at the current time period
- Stores Update Keys on the blockchain (public channel, as per paper Section IV-B)

**4c. Doctor View Reports** — [ViewPatientReport](file:///c:/Users/kalya/Downloads/blockchain-based-anonymous-authentication-framework-for-healthcare/app.py#L217-L248) (line 217)
- **Current**: Checks if hospital name is in the patient's sharing string
- **New**: Additionally checks `is_revoked(patient_id, doctor_id)`. If not revoked, fetches the Update Key from the blockchain, calls `server_transform()`, and then the doctor's browser-side logic calls `user_decrypt()` with their Aggregate Key

**4d. Patient Revocation Endpoint** — NEW
```python
@app.route('/PatientRevokeDoctorAction', methods=['POST'])
def PatientRevokeDoctorAction():
    doctor_to_revoke = request.form['doctor_name']
    # 1. Add revocation record to blockchain
    data = f"patient_revoke#{userid}#{doctor_to_revoke}#{date.today()}\n"
    saveDataBlockChain(data, "revocation")
    # 2. Update KAC engine revocation list
    kac_engine.revoke_user(userid, doctor_to_revoke)
    # 3. Advance time period so old Update Keys become invalid
    # (calls smart contract advanceTimePeriod())
    context = f'Access revoked for {doctor_to_revoke}'
    return render_template('PatientScreen.html', data=context)
```

**4e. Admin Revocation Endpoint** — NEW
```python
@app.route('/AdminRevokeDoctorAction', methods=['POST'])
def AdminRevokeDoctorAction():
    doctor_to_revoke = request.form['doctor_name']
    # 1. Add global revocation record to blockchain
    data = f"admin_revoke#{doctor_to_revoke}#{date.today()}\n"
    saveDataBlockChain(data, "revocation")
    # 2. Update KAC engine global revocation
    kac_engine.admin_revoke_user(doctor_to_revoke)
    # 3. Advance time period
    context = f'{doctor_to_revoke} has been globally revoked'
    return render_template('AdminScreen.html', data=context)
```

**4f. Revocation Check in Download** — [download_report](file:///c:/Users/kalya/Downloads/blockchain-based-anonymous-authentication-framework-for-healthcare/app.py#L576-L596) (line 576)
- Before decrypting and serving the file, check `kac_engine.is_revoked(patient_id, requesting_doctor_id)`
- If revoked → return `"Access Revoked", 403`

---

## Phase 5: End-to-End Verification

> **Goal**: Prove the full system works by running through all scenarios.

### Test Plan

| # | Scenario | Steps | Expected Result |
|---|---|---|---|
| 1 | Normal sharing | Patient uploads report → Doctor views & downloads | ✅ Doctor sees decrypted report |
| 2 | Patient revokes doctor | Patient clicks "Revoke" on Doctor Bob → Doctor Bob tries to view | ❌ "Access Revoked" error |
| 3 | Admin revokes doctor | Admin blacklists Doctor Smith → Doctor Smith tries to view any patient | ❌ "Access Revoked" for ALL patients |
| 4 | Revoked doctor, other doctor unaffected | Patient revokes Doctor A, Doctor B still has access | ✅ Doctor B can still decrypt |
| 5 | Time period advancement | New time period → old Update Keys invalid for revoked users | ❌ Revoked user cannot use old keys |
| 6 | Backward compatibility | Existing records (without KAC-UR) still display correctly | ✅ Old records unaffected |

### Verification Commands
```bash
# Phase 1: Run standalone demo
python kac_ur_demo.py

# Phase 2: Recompile and deploy smart contract
truffle compile
truffle migrate --reset

# Phase 3-4: Run the Flask app and test manually
python app.py
# Then test scenarios 1-6 via browser at http://127.0.0.1:5000
```

---

## Open Questions

> [!IMPORTANT]
> **Cryptographic Implementation Choice**: The paper uses Bilinear Pairings from the PBC library (C++). In Python, we have two options:
> 1. **Full Bilinear Pairing** via `py_ecc` or `charm-crypto` — mathematically identical to paper, but slower
> 2. **Practical Simulation** using modular arithmetic + Shamir Secret Sharing + AES — same aggregate-key and revocation logic, much faster, production-ready
> 
> Which do you prefer?

> [!NOTE]
> **Frontend Changes**: You mentioned to skip frontend changes. However, the Patient Revocation and Admin Revocation features will need at minimum a button/form in the existing HTML templates. Should I add minimal HTML for those buttons, or will you handle the frontend yourself?
