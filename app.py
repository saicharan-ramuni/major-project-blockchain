from flask import Flask, render_template, request, send_file
from datetime import date
import json
from web3 import Web3, HTTPProvider
import os
import socket
import pickle
import base64
import io
from urllib.parse import quote
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename
from mailer import send_email_with_attachment, build_share_email, build_prescription_email

app = Flask(__name__)

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
    deployed_contract_address = '0xE7B80C052E9a6666d53448b3Bb6Cb4E5e1b60b20' #hash address to access EHR contract
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
    deployed_contract_address = '0xE7B80C052E9a6666d53448b3Bb6Cb4E5e1b60b20' #contract address
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
                    prescription, doctor = getPrescription(arr[1],arr[6],arr[5])
                    output+='<tr><td><font size="" color="black">'+str(arr[1])+'</td>'
                    output+='<td><font size="" color="black">'+str(arr[2])+'</td>'
                    output+='<td><font size="" color="black">'+str(arr[3])+'</td>'
                    output+='<td><font size="" color="black">'+str(arr[4])+'</td>'
                    output+='<td><font size="" color="black">'+str(arr[5])+'</td>'
                    output+='<td><font size="" color="black">'+str(arr[6])+'</td>'
                    output += '<td><a href="/download_report?name=' + quote(arr[5]) + '">Click here to download</a></td>'
                    output+='<td><font size="" color="black">'+prescription+'</td>'
                    output+='<td><font size="" color="black">'+doctor+'</td>'
                    if prescription == "Pending":
                        output+='<td><a href=\'Prescription?pname='+arr[1]+'&pdate='+arr[6]+'&pfile='+arr[5]+'\'><font size=3 color=black>Click Here</font></a></td></tr>'
                    else:
                        output+='<td><font size="" color="black">Prescription Already Generated</td></tr>'
        
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
                prescription, doctor = getPrescription(arr[1],arr[6],arr[5])
                output+='<tr><td><font size="" color="black">'+str(arr[1])+'</td>'
                output+='<td><font size="" color="black">'+str(arr[2])+'</td>'
                output+='<td><font size="" color="black">'+str(arr[3])+'</td>'
                output+='<td><font size="" color="black">'+str(arr[4])+'</td>'
                output+='<td><font size="" color="black">'+str(arr[5])+'</td>'
                output+='<td><font size="" color="black">'+str(arr[6])+'</td>'
                output += '<td><a href="/download_report?name=' + quote(arr[5]) + '">Click here to download</a></td>'
                output+='<td><font size="" color="black">'+prescription+'</td>'
                output+='<td><font size="" color="black">'+doctor+'</td>'
        
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
        file = request.files['t3']
        filename = secure_filename(file.filename)
        print("@@ Input posted = ", filename)
        file_bytes = file.read()
        enc_bytes = encrypt_bytes(file_bytes)
        file_path = os.path.join('static/reports/', filename + ".enc")
        with open(file_path, "wb") as f:
            f.write(enc_bytes)
        hospitals = request.form.getlist('t4')
        hospitals = ','.join(hospitals)
        today = date.today()

                
        data = "patient#"+userid+"#"+age+"#"+symptoms+"#"+hospitals+"#"+filename+"#"+str(today)+"\n"
        saveDataBlockChain(data, "patient")
        
        hospital_list = hospitals.split(",") if hospitals else []
        hospital_emails = get_hospital_emails_by_names(hospital_list)
        subject, body = build_share_email(userid, symptoms, str(today))
        for email in hospital_emails:
            send_email_with_attachment(email, subject, body, file_bytes, filename)
        
        context = 'Your report shared with ' + hospitals
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
            context= 'Signup process completd and record saved in Blockchain'
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
            context= 'New Doctor & Hospital details saved in Blockchain'
            return render_template('AddDoctor.html', data=context)
        else:
            context= username+' Username already exists'
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
            context= "Welcome "+user
            return render_template('DoctorScreen.html', data=context)
        else:
            context= 'Invalid login details'
            return render_template('DoctorLogin.html', data=context)




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

@app.route('/DoctorScreen', methods=['GET', 'POST'])
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

@app.route('/download_report', methods=['GET'])
def download_report():
    name = request.args.get('name', '')
    filename = secure_filename(name)
    if not filename:
        return "Invalid filename", 400
    file_path = os.path.join('static/reports/', filename + ".enc")
    if not os.path.exists(file_path):
        return "File not found", 404
    with open(file_path, "rb") as f:
        enc_bytes = f.read()
    try:
        data = decrypt_bytes(enc_bytes)
    except Exception:
        return "Decryption failed", 500
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )


      
if __name__ == '__main__':
    app.run()       
