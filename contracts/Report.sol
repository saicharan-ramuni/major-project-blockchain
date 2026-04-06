// SPDX-License-Identifier: MIT
pragma solidity >= 0.4.0 <= 0.9.0;

contract Report {
    string public hospital_details;
    string public patient_details;
    string public prescription;
       
    //call this function to save hospital data to Blockchain
    function setHospital(string memory hd) public {
       hospital_details = hd;	
    }
   //get hospital details
    function getHospital() public view returns (string memory) {
        return hospital_details;
    }

    //call this function to save patient data to Blockchain
    function setPatient(string memory pd) public {
       patient_details = pd;	
    }
   //get hospital details
    function getPatient() public view returns (string memory) {
        return patient_details;
    }

    //call this function to save prescription data to Blockchain
    function setPrescription(string memory p) public {
       prescription = p;	
    }
   //get hospital details
    function getPrescription() public view returns (string memory) {
        return prescription;
    }

    constructor() public {
        hospital_details="";
	prescription = "";
	patient_details="";
    }
}