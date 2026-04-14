// SPDX-License-Identifier: MIT
pragma solidity >= 0.4.0 <= 0.9.0;

// ═══════════════════════════════════════════════════════════════════════════
// Dual-Blockchain EHR Smart Contract
// ═══════════════════════════════════════════════════════════════════════════
// Chain 1 – Historical Verification Chain
//   • hospital_details, patient_details, prescription  (existing)
//   • audit_log       — immutable access trail (who accessed what, when)
//   • pkg_registry    — CLS pseudo-ID → serialised public key (PKG store)
//
// Chain 2 – Revocation Evidence Chain
//   • revocation_details — patient + admin revocation records (KAC-UR)
//   • currentTimePeriod  — monotonic counter for KAC-UR time periods
// ═══════════════════════════════════════════════════════════════════════════

contract Report {

    // ── Chain 1: Historical Verification ─────────────────────────────────
    string public hospital_details;
    string public patient_details;
    string public prescription;

    // Immutable access-audit log.
    // Each newline-delimited record (after Python decryption):
    //   "access_log#<patient>#<doctor>#<data_class>#<timestamp>#<cls_sig>"
    string public audit_log;

    // CLS PKG Registry: pseudo_id → JSON-serialised public key record.
    // Stored as a mapping so lookups are O(1) instead of scanning a string.
    // Record format (Python dict serialised as JSON):
    //   { "X_hex": "<128-char hex>", "R_hex": "<128-char hex>",
    //     "pseudo_id": "<32-char hex>" }
    mapping(string => string) private pkg_registry;

    // ── Chain 2: Revocation Evidence ──────────────────────────────────────
    // Newline-delimited encrypted revocation records.
    //   Patient layer : "patient_revoke#<patient>#<doctor>#<date>"
    //   Admin layer   : "admin_revoke#<doctor>#<date>"
    string public revocation_details;

    // Global time-period counter (KAC-UR — incremented on each revocation)
    uint256 public currentTimePeriod;


    // ── Chain 1: Hospital / Patient / Prescription (existing) ─────────────
    function setHospital(string memory hd) public {
        hospital_details = hd;
    }
    function getHospital() public view returns (string memory) {
        return hospital_details;
    }

    function setPatient(string memory pd) public {
        patient_details = pd;
    }
    function getPatient() public view returns (string memory) {
        return patient_details;
    }

    function setPrescription(string memory p) public {
        prescription = p;
    }
    function getPrescription() public view returns (string memory) {
        return prescription;
    }

    // ── Chain 1: Audit Log ────────────────────────────────────────────────
    // Append-style from Python; full string is replaced on each write.
    function setAuditLog(string memory al) public {
        audit_log = al;
    }
    function getAuditLog() public view returns (string memory) {
        return audit_log;
    }

    // ── Chain 1: PKG / CLS Registry ───────────────────────────────────────
    // Register a user's CLS public key under their pseudo-ID.
    function setPKGKey(string memory pseudoId, string memory pubkeyJson) public {
        pkg_registry[pseudoId] = pubkeyJson;
    }
    // Retrieve a user's CLS public key by pseudo-ID (returns "" if absent).
    function getPKGKey(string memory pseudoId) public view returns (string memory) {
        return pkg_registry[pseudoId];
    }

    // ── Chain 2: Revocation Evidence ──────────────────────────────────────
    function setRevocation(string memory rd) public {
        revocation_details = rd;
    }
    function getRevocation() public view returns (string memory) {
        return revocation_details;
    }

    // ── Chain 2: Time Period ───────────────────────────────────────────────
    function advanceTimePeriod() public {
        currentTimePeriod += 1;
    }
    function getTimePeriod() public view returns (uint256) {
        return currentTimePeriod;
    }

    // ── Constructor ───────────────────────────────────────────────────────
    constructor() public {
        hospital_details   = "";
        prescription       = "";
        patient_details    = "";
        revocation_details = "";
        audit_log          = "";
        currentTimePeriod  = 1;
    }
}