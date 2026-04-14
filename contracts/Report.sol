// SPDX-License-Identifier: MIT
pragma solidity >= 0.4.0 <= 0.9.0;

contract Report {
    string public hospital_details;
    string public patient_details;
    string public prescription;

    // ── KAC-UR additions ─────────────────────────────────────────────
    // Stores revocation records as newline-delimited encrypted strings.
    // Format per record (after decryption in Python):
    //   Patient layer : "patient_revoke#<patient>#<doctor>#<date>"
    //   Admin layer   : "admin_revoke#<doctor>#<date>"
    string public revocation_details;

    // Global time-period counter (incremented on each revocation or advance)
    uint256 public currentTimePeriod;
    // ─────────────────────────────────────────────────────────────────

    // ── Existing hospital functions ───────────────────────────────────
    function setHospital(string memory hd) public {
       hospital_details = hd;
    }
    function getHospital() public view returns (string memory) {
        return hospital_details;
    }

    // ── Existing patient functions ────────────────────────────────────
    function setPatient(string memory pd) public {
       patient_details = pd;
    }
    function getPatient() public view returns (string memory) {
        return patient_details;
    }

    // ── Existing prescription functions ───────────────────────────────
    function setPrescription(string memory p) public {
       prescription = p;
    }
    function getPrescription() public view returns (string memory) {
        return prescription;
    }

    // ── KAC-UR: Revocation functions ──────────────────────────────────
    // Store revocation records (append-style, managed from Python layer)
    function setRevocation(string memory rd) public {
        revocation_details = rd;
    }

    function getRevocation() public view returns (string memory) {
        return revocation_details;
    }

    // ── KAC-UR: Time period functions ─────────────────────────────────
    // Advance to next time period (called on revocation or scheduled)
    function advanceTimePeriod() public {
        currentTimePeriod += 1;
    }

    function getTimePeriod() public view returns (uint256) {
        return currentTimePeriod;
    }

    constructor() public {
        hospital_details   = "";
        prescription       = "";
        patient_details    = "";
        revocation_details = "";
        currentTimePeriod  = 1;
    }
}