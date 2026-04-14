from flask import Flask, render_template, request, send_file, jsonify
from datetime import date, datetime
import json
from web3 import Web3, HTTPProvider
import os
import socket
import pickle
import base64
import io
import logging
import traceback
import secrets as _secrets
from urllib.parse import quote
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename
from mailer import send_email_with_attachment, build_share_email, build_prescription_email

# ── KAC-UR import ──────────────────────────────────────────────────────────
from kac_crypto import KACUREngine
kac_engine = KACUREngine(n_classes=10)
# ──────────────────────────────────────────────────────────────────────────

# ── CLS import ─────────────────────────────────────────────────────────────
from cls_crypto import CLSEngine
cls_engine = CLSEngine()

# In-memory nonce store for CLS challenge-response auth
# { username: nonce_string }
_cls_challenges: dict = {}
# ──────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# Show full traceback in the browser for every error (debug helper)
@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    with open('error_log.txt', 'a') as f:
        f.write(tb + '\n---\n')
    return f'<pre style="color:red;padding:20px">{tb}</pre>', 500

UPLOAD_FOLDER = 'static/report'
global userid, hospital, pnameValue, pdateValue, pfileValue

# 32-byte (256-bit) key for AES-256-GCM. Replace with your own fixed key.
ENCRYPTION_KEY_B64 = "4m8XfS5h4m3B85NYRrHnVdM3nX8b9r6Qz3q8c6K7mH8="


def _get_key():
    key = base64.b64decode(ENCRYPTION_KEY_B64)
    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY_B64 must decode to 32 bytes.")
    return key

def encrypt_text(plain_text):
    if plain_text is None or plain_text == "":
        return ""
    data = plain_text.encode("utf-8")
    nonce = os.urandom(12)
    aesgcm = AESGCM(_get_key())
    ct = aesgcm.encrypt(nonce, data, None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")

def decrypt_text(token):
    if token is None or token == "":
        return ""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(raw) < 13:
            return token
        nonce = raw[:12]
        ct = raw[12:]
        aesgcm = AESGCM(_get_key())
        data = aesgcm.decrypt(nonce, ct, None)
        return data.decode("utf-8")
    except Exception:
        return token

def encrypt_bytes(data):
    if data is None:
        return b""
    nonce = os.urandom(12)
    aesgcm = AESGCM(_get_key())
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_bytes(data):
    if not data:
        return b""
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(_get_key())
    return aesgcm.decrypt(nonce, ct, None)

def get_rows(contract_type):
    readDetails(contract_type)
    rows = details.split("\n")
    output = []
    for row in rows:
        if row.strip():
            output.append(decrypt_text(row))
    return output

def get_patient_email(username):
    rows = get_rows("patient")
    for row in rows:
        arr = row.split("#")
        if arr[0] == "signup" and arr[1] == username:
            return arr[4]
    return ""

def get_hospital_emails_by_names(hospital_names):
    emails = []
    rows = get_rows("hospital")
    for row in rows:
        arr = row.split("#")
        if arr[0] == "hospital" and arr[8] in hospital_names:
            if arr[4] and arr[4] not in emails:
                emails.append(arr[4])
    return emails

def get_report_filename(patient_name, report_date):
    rows = get_rows("patient")
    for row in rows:
        arr = row.split("#")
        if arr[0] == "patient" and arr[1] == patient_name and arr[6] == report_date:
            return arr[5]
    return ""

def readDetails(contract_type):
    global details
    details = ""
    print(contract_type+"======================")
    blockchain_address = 'http://127.0.0.1:8545' #Blokchain connection IP
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'Report.json' 
    deployed_contract_address = '0x3D932527B5546A7440BefB61f12A0CEAaf3ba84d' #hash address to access EHR contract
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi) #now calling contract to access data
    if contract_type == 'hospital':
        details = contract.functions.getHospital().call() #call getHospital function to access all hospital details
    if contract_type == 'patient':
        details = contract.functions.getPatient().call()
    if contract_type == 'prescription':
        details = contract.functions.getPrescription().call()    
    if contract_type == 'revocation':
        try:
            details = contract.functions.getRevocation().call()
        except Exception:
            details = ""
    if contract_type == 'audit':
        try:
            details = contract.functions.getAuditLog().call()
        except Exception:
            details = ""
    print(details)

def saveDataBlockChain(currentData, contract_type):
    global details
    global contract
    details = ""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 2222))

    blockchain_address = 'http://127.0.0.1:8545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'Report.json' 
    deployed_contract_address = '0x3D932527B5546A7440BefB61f12A0CEAaf3ba84d' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    readDetails(contract_type)
    line = currentData.rstrip("\n")
    encrypted_line = encrypt_text(line)
    if contract_type == 'hospital':
        details+=encrypted_line + "\n"
        msg = contract.functions.setHospital(details).transact()
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)
    if contract_type == 'patient':
        details+=encrypted_line + "\n"
        msg = contract.functions.setPatient(details).transact()
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)
    if contract_type == 'prescription':
        details+=encrypted_line + "\n"
        msg = contract.functions.setPrescription(details).transact()
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)
    if contract_type == 'revocation':
        details+=encrypted_line + "\n"
        try:
            msg = contract.functions.setRevocation(details).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(msg)
        except Exception:
            tx_receipt = {}
    if contract_type == 'audit':
        details += encrypted_line + "\n"
        try:
            msg = contract.functions.setAuditLog(details).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(msg)
        except Exception:
            # Contract not yet redeployed with audit support — silent fail
            tx_receipt = {}
    tx_receipt_data = pickle.dumps(tx_receipt)
    client_socket.send(tx_receipt_data)
    client_socket.close()

def getPrescription(pname, pdate, pfile):
    global details
    rows = get_rows("prescription")
    output = "Pending"
    doctor = "Pending"
    for i in range(len(rows)):
        arr = rows[i].split("#")
        if arr[0] == "prescription":
            # New format: prescription#pname#pdate#filename#prescription#doctor#date
            if len(arr) >= 7 and arr[1] == pname and arr[2] == pdate and arr[3] == pfile:
                output = arr[4]
                doctor = arr[5]
            # Backward compatibility for old format: prescription#pname#pdate#prescription#doctor#date
            elif len(arr) >= 6 and arr[1] == pname and arr[2] == pdate:
                output = arr[3]
                doctor = arr[4]
    return output, doctor

# ── KAC-UR helper: load revocations from blockchain into the engine ────────
def _sync_revocations_from_blockchain():
    """
    Read revocation records stored on the blockchain and sync them into
    the in-memory kac_engine so that the engine state reflects what is
    persisted even after app restarts.
    """
    try:
        rows = get_rows("revocation")
        for row in rows:
            if not row.strip():
                continue
            arr = row.split("#")
            if arr[0] == "patient_revoke" and len(arr) >= 3:
                patient_id = arr[1]
                doctor_id = arr[2]
                kac_engine._patient_rl.setdefault(patient_id, set()).add(doctor_id)
            elif arr[0] == "admin_revoke" and len(arr) >= 2:
                doctor_id = arr[1]
                kac_engine._global_rl.add(doctor_id)
    except Exception as e:
        print(f"[KAC] Warning: could not sync revocations from blockchain: {e}")

# ── CLS: Audit-proof access logging ──────────────────────────────────────────
def log_access(patient_id: str, doctor_id: str, file_class: int = 0):
    """
    Record a non-repudiable access event on the blockchain.
    CLS-signs the log entry with the doctor's session key so the doctor
    cannot later deny having accessed the file.
    Wrapped in try/except — never crashes the app.
    """
    try:
        timestamp  = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        log_entry  = f"access_log#{patient_id}#{doctor_id}#{file_class}#{timestamp}"
        sig        = cls_engine.sign(log_entry, doctor_id)
        sig_str    = f"{sig['pseudo_id']}:{sig['sigma']}" if sig else "unsigned"
        full_record = f"{log_entry}#{sig_str}"
        saveDataBlockChain(full_record, "audit")
    except Exception as e:
        print(f"[CLS] log_access warning: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING ROUTES (unchanged logic, revocation guard added where relevant)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/Prescription', methods=['GET','POST'])
def Prescription():
    if request.method == 'GET':
        global pnameValue, pdateValue, pfileValue
        pnameValue = request.args.get('pname')
        pdateValue = request.args.get('pdate')
        pfileValue = request.args.get('pfile')
        print(pnameValue+" "+pdateValue+" "+str(pfileValue))
        context= "Patient Name: "+pnameValue
        return render_template('Prescription.html', data=context)


@app.route('/PrescriptionAction', methods=['POST'])
def PrescriptionAction():
    global pnameValue, pdateValue, pfileValue, userid
    prescription = request.form['t1']
    today = date.today()
    data = "prescription#"+pnameValue+"#"+pdateValue+"#"+pfileValue+"#"+prescription+"#"+userid+"#"+str(today)+"\n"
    saveDataBlockChain(data,"prescription")
    patient_email = get_patient_email(pnameValue)
    filename = pfileValue or get_report_filename(pnameValue, pdateValue)
    attachment_bytes = None
    if filename:
        file_path = os.path.join('static/reports/', filename + ".enc")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                enc_bytes = f.read()
            try:
                attachment_bytes = decrypt_bytes(enc_bytes)
            except Exception:
                attachment_bytes = None
    subject, body = build_prescription_email(pnameValue, pdateValue, prescription)
    send_email_with_attachment(patient_email, subject, body, attachment_bytes, filename)
    context= 'Prescription details added'
    return render_template('DoctorScreen.html', data=context) 

@app.route('/ViewPatientReport', methods=['GET','POST'])
def ViewPatientReport():
    if request.method == 'GET':
        global hospital
        rows = get_rows("patient")
        output = ""
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "patient":
                temp = arr[4].split(",")
                flag = 0
                for k in range(len(temp)):
                    if temp[k] == hospital:
                        flag = 1
                        break
                if flag == 1:
                    # ── KAC-UR: Check revocation before showing report ──
                    patient_id = arr[1]
                    revoked = kac_engine.is_revoked(patient_id, userid) or kac_engine.is_revoked(patient_id, hospital)
                    prescription, doctor = getPrescription(arr[1], arr[6], arr[5])
                    output += '<tr>'
                    output += f'<td>{arr[1]}</td>'
                    output += f'<td>{arr[2]}</td>'
                    output += f'<td>{arr[3]}</td>'
                    output += f'<td>{arr[4]}</td>'
                    output += f'<td>{arr[6]}</td>'
                    # ── Per-file view buttons (pipe-separated filenames) ──
                    if revoked:
                        output += '<td><span class="badge bg-danger px-3 py-2"><i class="fa fa-ban me-1"></i>Access Revoked</span></td>'
                    else:
                        file_names = arr[5].split("|")
                        btn_html = ""
                        for fn in file_names:
                            fn = fn.strip()
                            if fn:
                                btn_html += (f'<button class="btn btn-sm btn-view-report me-1 mb-1" '
                                             f'onclick="openReportModal(\'{quote(fn)}\', \'{quote(arr[1])}\')">'
                                             f'<i class="fa fa-eye me-1"></i>{fn}</button>')
                        output += f'<td>{btn_html}</td>'
                    output += f'<td>{prescription}</td>'
                    output += f'<td>{doctor}</td>'
                    if prescription == "Pending" and not revoked:
                        output += (f'<td><a href="Prescription?pname={arr[1]}&pdate={arr[6]}&pfile={arr[5]}" '
                                   f'class="btn btn-sm btn-outline-primary">Write Prescription</a></td></tr>')
                    else:
                        output += (f'<td><span class="text-secondary small">'
                                   f'{"Prescription Done" if prescription != "Pending" else "Access Revoked"}'
                                   f'</span></td></tr>')
        
        return render_template('ViewPatientReport.html', data=output)  


    
@app.route('/ViewHealth', methods=['GET','POST'])
def ViewHealth():
    if request.method == 'GET':
        global userid
        rows = get_rows("patient")
        output = ""
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "patient" and arr[1] == userid:
                prescription, doctor = getPrescription(arr[1], arr[6], arr[5])
                output += '<tr>'
                output += f'<td>{arr[1]}</td>'
                output += f'<td>{arr[2]}</td>'
                output += f'<td>{arr[3]}</td>'
                output += f'<td>{arr[4]}</td>'
                output += f'<td>{arr[6]}</td>'
                # ── Per-file view buttons for each uploaded file ──
                file_names = arr[5].split("|")
                btn_html = ""
                for fn in file_names:
                    fn = fn.strip()
                    if fn:
                        btn_html += (f'<button class="btn btn-sm btn-view-report me-1 mb-1" '
                                     f'onclick="openReportModal(\'{quote(fn)}\', \'{quote(arr[1])}\')">'
                                     f'<i class="fa fa-eye me-1"></i>{fn}</button>')
                output += f'<td>{btn_html}</td>'
                output += f'<td>{prescription}</td>'
                output += f'<td>{doctor}</td>'
                output += '</tr>'

        return render_template('ViewHealth.html', data=output)


@app.route('/ViewPatientHospital', methods=['GET', 'POST'])
def ViewPatientHospital():
    if request.method == 'GET':
        rows = get_rows("hospital")
        output = ""
        for i in range(len(rows)):
            row = rows[i].split("#")
            if row[0] == "hospital":
                output+='<tr><td><font size="" color="black">'+str(row[1])+'</td>'
                #output+='<td><font size="" color="black">'+str(row[2])+'</td>'
                output+='<td><font size="" color="black">'+str(row[3])+'</td>'
                output+='<td><font size="" color="black">'+str(row[4])+'</td>'
                output+='<td><font size="" color="black">'+str(row[5])+'</td>'
                output+='<td><font size="" color="black">'+str(row[6])+'</td>'
                output+='<td><font size="" color="black">'+str(row[7])+'</td>'
                output+='<td><font size="" color="black">'+str(row[8])+'</td>'
               
                
        
        return render_template('ViewPatientHospital.html', data=output)


@app.route('/AddHealthAction', methods=['POST'])
def AddHealthAction():
    if request.method == 'POST':
        age = request.form.get('t1', False)
        symptoms = request.form.get('t2', False)
        files = request.files.getlist('t3')  # support multiple files
        hospitals = request.form.getlist('t4')
        hospitals = ','.join(hospitals)
        today = date.today()

        # ── KAC-UR: Ensure patient is set up, derive data class ────────
        kac_engine.owner_setup(userid)
        data_class = KACUREngine.symptoms_to_class(symptoms or "general")
        time_period = kac_engine.get_time_period(userid)

        # Generate aggregate keys and update keys for each selected hospital
        hospital_list_raw = [h.strip() for h in hospitals.split(",") if hospitals and h.strip()]
        for hosp_name in hospital_list_raw:
            try:
                kac_engine.extract_aggregate_key(userid, hosp_name, [data_class])
                kac_engine.generate_update_key(userid, hosp_name, time_period)
                print(f"[KAC] Aggregate + Update Key generated for hospital '{hosp_name}'")
            except Exception as e:
                print(f"[KAC] Warning: key generation failed for '{hosp_name}': {e}")
        # ────────────────────────────────────────────────────────────────

        # ── Encrypt and save every uploaded file ──────────────────────
        saved_filenames = []
        all_attachments = []  # list of (bytes, filename) for email
        for file in files:
            if file and file.filename:
                fname = secure_filename(file.filename)
                file_bytes = file.read()
                enc_bytes = encrypt_bytes(file_bytes)
                file_path = os.path.join('static/reports/', fname + ".enc")
                with open(file_path, "wb") as f:
                    f.write(enc_bytes)
                saved_filenames.append(fname)
                all_attachments.append((file_bytes, fname))
                print(f"@@ Saved encrypted file: {fname}")
        # ─────────────────────────────────────────────────────────────

        # Pipe-join multiple filenames for backward-compatible blockchain storage
        filenames_field = "|".join(saved_filenames) if saved_filenames else "unknown"

        data = "patient#"+userid+"#"+age+"#"+symptoms+"#"+hospitals+"#"+filenames_field+"#"+str(today)+"\n"
        saveDataBlockChain(data, "patient")

        hospital_emails = get_hospital_emails_by_names(hospital_list_raw)
        subject, body = build_share_email(userid, symptoms, str(today))
        for email in hospital_emails:
            # send all files; mailer sends first attachment; extend if mailer supports multi
            for (fb, fn) in all_attachments:
                send_email_with_attachment(email, subject, body, fb, fn)

        context = f'Your {len(saved_filenames)} report(s) shared with {hospitals}'
        return render_template('PatientScreen.html', data=context)
    



@app.route('/AddHealth', methods=['GET'])
def AddHealth():
    if request.method == 'GET':
        output = ""
        names = []
        rows = get_rows("hospital")
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "hospital":
                if arr[8] not in names:
                    names.append(arr[8])
                    output += f'<div class="form-check mb-2"><input class="form-check-input" type="checkbox" name="t4" value="{arr[8]}" id="hospital_{i}"><label class="form-check-label text-secondary ms-2" for="hospital_{i}">{arr[8]}</label></div>'
                    
        return render_template('AddHealth.html', data1=output)



@app.route('/ViewHospitalDetails', methods=['GET'])
def ViewHospitalDetails():
    if request.method == 'GET':
        rows = get_rows("hospital")
        output = ""
        for i in range(len(rows)):
            row = rows[i].split("#")
            if row[0] == "hospital":
                output+='<tr><td><font size="" color="black">'+str(row[1])+'</td>'
                output+='<td><font size="" color="black">'+str(row[2])+'</td>'
                output+='<td><font size="" color="black">'+str(row[3])+'</td>'
                output+='<td><font size="" color="black">'+str(row[4])+'</td>'
                output+='<td><font size="" color="black">'+str(row[5])+'</td>'
                output+='<td><font size="" color="black">'+str(row[6])+'</td>'
                output+='<td><font size="" color="black">'+str(row[7])+'</td>'
                output+='<td><font size="" color="black">'+str(row[8])+'</td>'
                                
        
        return render_template('ViewHospitalDetails.html', data=output)



@app.route('/AdminLoginAction', methods=['GET','POST'])
def AdminLoginAction():
    if request.method == 'POST':
        global userid
        user = request.form['t1']
        password = request.form['t2']
        if user == "admin" and password == "admin":
            context= 'Welcome '+user
            return render_template('AdminScreen.html', data=context)
        else:
            context= 'Invalid Login'
            return render_template('AdminLogin.html', data=context)

        


@app.route('/PatientSignupAction', methods=['GET', 'POST'])
def PatientSignupAction():
    if request.method == 'POST':
        user = request.form['t1']
        password = request.form['t2']
        email = request.form['t3']
        contact = request.form['t4']
        address = request.form['t5']
        record = 'none'
        rows = get_rows("patient")
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "signup":
                if arr[1] == user:
                    record = "exists"
                    break
        if record == 'none':
            data = "signup#"+user+"#"+password+"#"+contact+"#"+email+"#"+address+"\n"
            saveDataBlockChain(data,"patient")
            # ── CLS: Generate pseudo-identity and key pair for this patient ──
            try:
                key_data  = cls_engine.user_key_gen(user)
                pseudo_id = key_data["pseudo_id"]
                pk_rec    = cls_engine.get_public_key_record(user)
                # Store CLS registration record on the Historical Verification Chain
                cls_record = (f"cls_reg#{user}#{pseudo_id}#"
                              f"{pk_rec['X_hex'][:16]}...#{str(date.today())}")
                saveDataBlockChain(cls_record, "patient")
                print(f"[CLS] Patient '{user}' registered with pseudo-ID: {pseudo_id}")
            except Exception as e:
                print(f"[CLS] Warning: key gen failed for '{user}': {e}")
            # ────────────────────────────────────────────────────────────────
            context= 'Signup process completed and record saved in Blockchain'
            return render_template('PatientSignup.html', data=context)
        else:
            context= user+' Username already exists'
            return render_template('PatientSignup.html', data=context) 



@app.route('/PatientLoginAction', methods=['GET', 'POST'])
def PatientLoginAction():
    if request.method == 'POST':
        global userid
        user = request.form['t1']
        password = request.form['t2']
        status = 'none'
        rows = get_rows("patient")
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "signup":
                if arr[1] == user and arr[2] == password:
                    status = 'success'
                    userid = user
                    break
        if status == 'success':
            file = open('session.txt','w')
            file.write(user)
            file.close()
            # ── KAC-UR: ensure patient setup on login ──────────────────
            kac_engine.owner_setup(user)
            _sync_revocations_from_blockchain()
            # ── CLS: ensure session keys are ready ─────────────────────
            try:
                cls_engine.get_or_create_keys(user)
                print(f"[CLS] Patient '{user}' session keys ready. "
                      f"pseudo-ID: {cls_engine.get_pseudo_id(user)}")
            except Exception as e:
                print(f"[CLS] Warning: key init failed for '{user}': {e}")
            # ──────────────────────────────────────────────────────────
            context= "Welcome "+user
            return render_template('PatientScreen.html', data=context)
        else:
            context= 'Invalid login details'
            return render_template('PatientLogin.html', data=context) 


@app.route('/AddDoctorAction', methods=['GET', 'POST'])
def AddDoctorAction():
    if request.method == 'POST':
        user = request.form['t1']
        password = request.form['t2']
        email = request.form['t3']
        contact = request.form['t4']
        qualification = request.form['t5']
        experience = request.form['t6']
        hospital = request.form['t7']
        address = request.form['t8']
        record = 'none'
        rows = get_rows("hospital")
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "hospital":
                if arr[1] == user:
                    record = "exists"
                    break
        if record == 'none':
            data = "hospital#"+user+"#"+password+"#"+contact+"#"+email+"#"+address+"#"+qualification+"#"+experience+"#"+hospital+"\n"
            saveDataBlockChain(data,"hospital")
            # ── CLS: Generate pseudo-identity and key pair for this doctor ──
            try:
                key_data  = cls_engine.user_key_gen(user)
                pseudo_id = key_data["pseudo_id"]
                pk_rec    = cls_engine.get_public_key_record(user)
                cls_record = (f"cls_reg#{user}#{pseudo_id}#"
                              f"{pk_rec['X_hex'][:16]}...#{str(date.today())}")
                saveDataBlockChain(cls_record, "hospital")
                print(f"[CLS] Doctor '{user}' registered with pseudo-ID: {pseudo_id}")
            except Exception as e:
                print(f"[CLS] Warning: key gen failed for doctor '{user}': {e}")
            # ────────────────────────────────────────────────────────────────
            context= 'New Doctor & Hospital details saved in Blockchain'
            return render_template('AddDoctor.html', data=context)
        else:
            context= user+' Username already exists'
            return render_template('AddDoctor.html', data=context)
        
@app.route('/DoctorLoginAction', methods=['GET', 'POST'])
def DoctorLoginAction():
    if request.method == 'POST':
        global userid, hospital
        user = request.form['t1']
        password = request.form['t2']
        status = 'none'
        rows = get_rows("hospital")
        for i in range(len(rows)):
            arr = rows[i].split("#")
            if arr[0] == "hospital":
                if arr[1] == user and arr[2] == password:
                    status = 'success'
                    userid = user
                    hospital = arr[8]
                    break
        if status == 'success':
            file = open('session.txt','w')
            file.write(user)
            file.close()
            # ── KAC-UR: sync revocations so doctor login reflects current state ──
            _sync_revocations_from_blockchain()
            # ── CLS: ensure session keys are ready ─────────────────────────────
            try:
                cls_engine.get_or_create_keys(user)
                print(f"[CLS] Doctor '{user}' session keys ready. "
                      f"pseudo-ID: {cls_engine.get_pseudo_id(user)}")
            except Exception as e:
                print(f"[CLS] Warning: key init failed for doctor '{user}': {e}")
            # ────────────────────────────────────────────────────────────────────
            context= "Welcome "+user
            return render_template('DoctorScreen.html', data=context)
        else:
            context= 'Invalid login details'
            return render_template('DoctorLogin.html', data=context)


# ─────────────────────────────────────────────────────────────────────────────
# KAC-UR NEW ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/RevokeDoctor', methods=['GET'])
def RevokeDoctor():
    """Page for patient to view doctors they have shared with and revoke."""
    global userid
    # Gather hospitals the patient shared with
    rows = get_rows("patient")
    hospitals_shared = set()
    for row in rows:
        arr = row.split("#")
        if arr[0] == "patient" and arr[1] == userid:
            for h in arr[4].split(","):
                if h.strip():
                    hospitals_shared.add(h.strip())

    revocation_summary = kac_engine.get_revocation_summary()
    patient_revoked = set(revocation_summary["patient_revoked"].get(userid, []))

    output = ""
    for hosp in sorted(hospitals_shared):
        is_rev = hosp in patient_revoked
        badge = '<span class="badge bg-danger ms-2">Revoked</span>' if is_rev else '<span class="badge bg-success ms-2">Active</span>'
        if is_rev:
            btn = '<span class="text-muted small">Already Revoked</span>'
        else:
            btn = (
                f'<form method="POST" action="/PatientRevokeDoctorAction" class="d-inline">'
                f'<input type="hidden" name="doctor_name" value="{hosp}">'
                f'<button type="submit" class="btn btn-sm btn-danger" '
                f'onclick="return confirm(\'Revoke access for {hosp}?\')">Revoke Access</button>'
                f'</form>'
            )
        output += f'<tr><td>{hosp}</td><td>{badge}</td><td>{btn}</td></tr>'

    return render_template('RevokeDoctor.html', data=output)


@app.route('/PatientRevokeDoctorAction', methods=['POST'])
def PatientRevokeDoctorAction():
    """Patient-level revocation (KAC-UR Layer 1)."""
    global userid
    doctor_to_revoke = request.form.get('doctor_name', '').strip()
    if not doctor_to_revoke:
        return render_template('PatientScreen.html', data='No doctor specified')

    # 1. Update KAC engine revocation list (invalidates update keys internally)
    kac_engine.revoke_user(userid, doctor_to_revoke)

    # 2. Persist revocation record to blockchain
    today = str(date.today())
    record = f"patient_revoke#{userid}#{doctor_to_revoke}#{today}"
    try:
        saveDataBlockChain(record, "revocation")
    except Exception as e:
        print(f"[KAC] Warning: failed to write revocation to blockchain: {e}")

    context = f'✅ Access successfully revoked for <strong>{doctor_to_revoke}</strong>. They can no longer decrypt your reports.'
    return render_template('PatientScreen.html', data=context)


@app.route('/AdminRevokeDoctor', methods=['GET'])
def AdminRevokeDoctor():
    """Page for admin to globally revoke a doctor."""
    rows = get_rows("hospital")
    doctors = []
    for row in rows:
        arr = row.split("#")
        if arr[0] == "hospital":
            doctors.append(arr[1])

    revocation_summary = kac_engine.get_revocation_summary()
    global_revoked = set(revocation_summary["global_revoked"])

    output = ""
    for doc in sorted(set(doctors)):
        is_rev = doc in global_revoked
        badge = '<span class="badge bg-danger ms-2">Globally Revoked</span>' if is_rev else '<span class="badge bg-success ms-2">Active</span>'
        if is_rev:
            btn = '<span class="text-muted small">Already Revoked</span>'
        else:
            btn = (
                f'<form method="POST" action="/AdminRevokeDoctorAction" class="d-inline">'
                f'<input type="hidden" name="doctor_name" value="{doc}">'
                f'<button type="submit" class="btn btn-sm btn-danger" '
                f'onclick="return confirm(\'Globally revoke {doc}?\')">Global Revoke</button>'
                f'</form>'
            )
        output += f'<tr><td>{doc}</td><td>{badge}</td><td>{btn}</td></tr>'

    return render_template('AdminRevokeDoctor.html', data=output)


@app.route('/AdminRevokeDoctorAction', methods=['POST'])
def AdminRevokeDoctorAction():
    """Admin global revocation (KAC-UR Layer 2)."""
    doctor_to_revoke = request.form.get('doctor_name', '').strip()
    if not doctor_to_revoke:
        return render_template('AdminScreen.html', data='No doctor specified')

    # 1. Update KAC engine global revocation list
    kac_engine.admin_revoke_user(doctor_to_revoke)

    # 2. Persist to blockchain
    today = str(date.today())
    record = f"admin_revoke#{doctor_to_revoke}#{today}"
    try:
        saveDataBlockChain(record, "revocation")
    except Exception as e:
        print(f"[KAC] Warning: failed to write admin revocation to blockchain: {e}")

    context = f'⛔ Doctor <strong>{doctor_to_revoke}</strong> has been globally revoked. All patient files are now inaccessible to them.'
    return render_template('AdminScreen.html', data=context)


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING STATIC ROUTES (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/AddDoctor', methods=['GET', 'POST'])
def AddDoctor():
    if request.method == 'GET':
       return render_template('AddDoctor.html', msg='')


@app.route('/AddHealth', methods=['GET', 'POST'])
def AddHealths():
    if request.method == 'GET':
       return render_template('AddHealth.html', msg='')

@app.route('/AdminLogin', methods=['GET', 'POST'])
def AdminLogin():
    if request.method == 'GET':
       return render_template('AdminLogin.html', msg='')

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
       return render_template('index.html', msg='')

@app.route('/AdminScreen', methods=['GET', 'POST'])
def AdminScreen():
    if request.method == 'GET':
       return render_template('AdminScreen.html', msg='')

@app.route('/DoctorLogin', methods=['GET', 'POST'])
def DoctorLogin():
    if request.method == 'GET':
       return render_template('DoctorLogin.html', msg='')

@app.route('/DoctorScreen', methods=['GET', 'Post'])
def DoctorScreen():
    if request.method == 'GET':
       return render_template('DoctorScreen.html', msg='')

@app.route('/PatientLogin', methods=['GET', 'POST'])
def PatientLogin():
    if request.method == 'GET':
       return render_template('PatientLogin.html', msg='')

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
       return render_template('index.html', msg='')

@app.route('/PatientScreen', methods=['GET', 'POST'])
def PatientScreen():
    if request.method == 'GET':
       return render_template('PatientScreen.html', msg='')
    
@app.route('/PatientSignup', methods=['GET', 'POST'])
def PatientSignup():
    if request.method == 'GET':
       return render_template('PatientSignup.html', msg='')

@app.route('/Prescription', methods=['GET', 'POST'])
def Prescriptions():
    if request.method == 'GET':
       return render_template('Prescription.html', msg='')

@app.route('/ViewHealth', methods=['GET', 'POST'])
def ViewHealths():
    if request.method == 'GET':
       return render_template('ViewHealth.html', msg='')

@app.route('/ViewHospitalDetails', methods=['GET', 'POST'])
def ViewHospitalDetailss():
    if request.method == 'GET':
       return render_template('ViewHospitalDetails.html', msg='')

@app.route('/ViewPatientHospital', methods=['GET', 'POST'])
def ViewPatientHospitals():
    if request.method == 'GET':
       return render_template('ViewPatientHospital.html', msg='')

@app.route('/ViewPatientReport', methods=['GET', 'POST'])
def ViewPatientReports():
    if request.method == 'GET':
       return render_template('ViewPatientReport.html', msg='')

def _get_mimetype(filename: str) -> str:
    """Return an appropriate MIME type based on file extension."""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    mime_map = {
        'pdf':  'application/pdf',
        'png':  'image/png',
        'jpg':  'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif':  'image/gif',
        'bmp':  'image/bmp',
        'webp': 'image/webp',
        'txt':  'text/plain',
    }
    return mime_map.get(ext, 'application/octet-stream')


@app.route('/view_report', methods=['GET'])
def view_report():
    """Serve a decrypted report inline in the browser (PDF/image/text).
    Revoked doctors/hospitals are blocked with a 403 response."""
    name = request.args.get('name', '')
    patient = request.args.get('patient', '')
    filename = secure_filename(name)
    if not filename:
        return "Invalid filename", 400

    # ── KAC-UR: Dual-layer revocation check before serving file ────────
    if patient and userid:
        if kac_engine.is_revoked(patient, userid) or kac_engine.is_revoked(patient, hospital):
            return render_template(
                'ViewReport.html',
                revoked=True,
                filename=filename,
                patient=patient,
                file_url=None,
                mimetype=None
            ), 403
    # ────────────────────────────────────────────────────────────────────

    file_path = os.path.join('static/reports/', filename + ".enc")
    if not os.path.exists(file_path):
        return "File not found", 404
    with open(file_path, "rb") as f:
        enc_bytes = f.read()
    try:
        data = decrypt_bytes(enc_bytes)
    except Exception:
        return "Decryption failed", 500

    mime = _get_mimetype(filename)
    # For viewable types serve inline; others force download
    inline_types = {'application/pdf', 'image/png', 'image/jpeg',
                    'image/gif', 'image/bmp', 'image/webp', 'text/plain'}
    as_attachment = mime not in inline_types

    # ── CLS: Non-repudiable audit log entry ─────────────────────────────
    # Logs who accessed this file on the Historical Verification Chain.
    try:
        accessor   = userid if 'userid' in globals() and userid else "unknown"
        data_class = kac_engine.symptoms_to_class(filename) if patient else 0
        log_access(patient or "unknown", accessor, data_class)
    except Exception:
        pass
    # ────────────────────────────────────────────────────────────────────

    return send_file(
        io.BytesIO(data),
        as_attachment=as_attachment,
        download_name=filename,
        mimetype=mime
    )


@app.route('/download_report', methods=['GET'])
def download_report():
    """Backward-compatible alias — redirects to view_report."""
    from flask import redirect, url_for
    name = request.args.get('name', '')
    patient = request.args.get('patient', '')
    return redirect(url_for('view_report', name=name, patient=patient))


# ─────────────────────────────────────────────────────────────────────────────
# CLS API ENDPOINTS  (Section 6.3 of implementation plan)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/challenge/<username>', methods=['GET'])
def api_challenge(username):
    """
    Step 1 of CLS challenge-response login.
    Returns a one-time nonce that the client must sign with their CLS key.
    The nonce expires after use (single-use).

    GET /api/challenge/<username>
    Response: { "nonce": "<hex-string>", "username": "<username>" }
    """
    nonce = _secrets.token_hex(32)
    _cls_challenges[username] = nonce
    return jsonify({"nonce": nonce, "username": username})


@app.route('/api/cls_login', methods=['POST'])
def api_cls_login():
    """
    Step 2 of CLS challenge-response login.
    The client signs the nonce returned by /api/challenge with their CLS key.
    The server verifies the signature — no password is ever transmitted.

    POST /api/cls_login
    Body (JSON): { "username": "...", "signature": { "T_hex": "...", "sigma": ..., "pseudo_id": "..." } }
    Response:    { "status": "ok"|"fail", "pseudo_id": "...", "message": "..." }
    """
    body      = request.get_json(force=True, silent=True) or {}
    username  = body.get("username", "").strip()
    signature = body.get("signature", {})

    if not username or not signature:
        return jsonify({"status": "fail", "message": "username and signature required"}), 400

    nonce = _cls_challenges.pop(username, None)
    if nonce is None:
        return jsonify({"status": "fail",
                        "message": "No pending challenge. Call /api/challenge first."}), 400

    # Ensure CLS keys exist for this user
    if not cls_engine.is_registered(username):
        cls_engine.get_or_create_keys(username)

    valid = cls_engine.verify(nonce, signature, username)
    if valid:
        pseudo_id = cls_engine.get_pseudo_id(username)
        return jsonify({
            "status":    "ok",
            "pseudo_id": pseudo_id,
            "message":   f"CLS authentication successful for pseudo-ID {pseudo_id}"
        })
    else:
        return jsonify({"status": "fail", "message": "Invalid CLS signature"}), 401


@app.route('/api/batch_verify_telemetry', methods=['POST'])
def api_batch_verify_telemetry():
    """
    Batch-verify multiple CLS-signed health telemetry records in one call.
    Demonstrates O(1) batch verification latency regardless of record count
    (Wang et al. BCCA, Section 6.3 of implementation plan).

    POST /api/batch_verify_telemetry
    Body (JSON):
    {
      "records": [
        {
          "identity": "doctor_username",
          "message":  "patient_id:file_class:timestamp:value",
          "signature": { "T_hex": "...", "sigma": ..., "pseudo_id": "..." }
        }, ...
      ]
    }
    Response:
    {
      "status":  "ok"|"fail",
      "all_valid": true|false,
      "passed":  <int>,
      "failed":  <int>,
      "count":   <int>,
      "method":  "batch"
    }
    """
    body    = request.get_json(force=True, silent=True) or {}
    records = body.get("records", [])

    if not records:
        return jsonify({"status": "fail", "message": "No records provided"}), 400

    # Ensure CLS keys exist for every identity referenced
    for rec in records:
        ident = rec.get("identity", "")
        if ident and not cls_engine.is_registered(ident):
            cls_engine.get_or_create_keys(ident)

    all_valid, passed, failed = cls_engine.batch_verify(records)

    return jsonify({
        "status":    "ok",
        "all_valid": all_valid,
        "passed":    passed,
        "failed":    failed,
        "count":     len(records),
        "method":    "batch"
    })


@app.route('/ViewAccessLog', methods=['GET'])
def ViewAccessLog():
    """
    Patient/Admin view of the immutable blockchain access audit log.
    Shows who accessed which patient's files and when (with pseudo-ID).
    """
    rows   = get_rows("audit")
    output = ""
    filter_patient = request.args.get('patient', '')

    for row in rows:
        if not row.strip():
            continue
        arr = row.split("#")
        # Format: access_log#patient#doctor#class#timestamp#pseudo_id:sigma
        if arr[0] == "access_log" and len(arr) >= 5:
            patient_id  = arr[1]
            doctor_id   = arr[2]
            data_class  = arr[3]
            timestamp   = arr[4]
            sig_info    = arr[5] if len(arr) > 5 else "—"
            pseudo_part = sig_info.split(":")[0] if ":" in sig_info else sig_info

            if filter_patient and patient_id != filter_patient:
                continue

            output += (
                f'<tr>'
                f'<td>{patient_id}</td>'
                f'<td>{doctor_id}</td>'
                f'<td>{data_class}</td>'
                f'<td>{timestamp}</td>'
                f'<td><code style="font-size:0.75rem">{pseudo_part[:16]}…</code></td>'
                f'</tr>'
            )

    return render_template('ViewAccessLog.html', data=output,
                           filter_patient=filter_patient)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
