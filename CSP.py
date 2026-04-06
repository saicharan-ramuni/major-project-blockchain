
from tkinter import *
import tkinter
import socket 
from threading import Thread 
from socketserver import ThreadingMixIn
from os import path
import pickle
import sys
import numpy as np
from hashlib import sha1
from web3 import Web3, HTTPProvider
import json

mainGUI = tkinter.Tk()
mainGUI.title("Cloud Service Provider ") #designing main screen
mainGUI.geometry("900x700")
running = True

global details
details = ''


def readDetails(): #calling to read data from blockchain
    global details
    blockchain_address = 'http://127.0.0.1:9545' #Blokchain connection IP
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'Report.json' #industrial contract code
    deployed_contract_address = '0x0a8fD03eF0c92cb3F82b2384cc9886Ea7B89d1b9' #hash address to access industrail contract
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi) #now calling contract to access data
    details = contract.functions.getMasterHash().call()
    if len(details) > 0:
        if 'empty' in details:
            details = details[5:len(details)]
    return details   



def startDistributedCore():
    class CoreThread(Thread): 
 
        def __init__(self,ip,port): 
            Thread.__init__(self) 
            self.ip = ip 
            self.port = port 
            text.insert(END,'Request received from Client IP : '+ip+' with port no : '+str(port)+"\n") 
 
        def run(self):
            text.delete('1.0', END)
            global details
            data = conn.recv(100000) 
            dataset = pickle.loads(data)
            print(dataset) 
            output_data = f'Transaction is successfully and Transaction Receipt is {dataset}'

            text.insert(END,output_data+"\n\n")                           
                
            



    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    server.bind(('localhost', 2222))
    threads = []
    text.insert(END,"CSP Cloud Server1 Started\n\n")
    while running:
        server.listen(4)
        (conn, (ip,port)) = server.accept()
        newthread = CoreThread(ip,port) 
        newthread.start() 
        threads.append(newthread) 
    for t in threads:
        t.join()

def startCore():
    Thread(target=startDistributedCore).start()


gfont = ('times', 16, 'bold')
gtitle = Label(mainGUI, text='Cloud Server')
gtitle.config(bg='LightGoldenrod1', fg='medium orchid')  
gtitle.config(font=gfont)           
gtitle.config(height=3, width=120)       
gtitle.place(x=0,y=5)

gfont1 = ('times', 12, 'bold')

text=Text(mainGUI,height=28,width=130)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=100)
text.config(font=gfont1)

startCore()

mainGUI.config(bg='OliveDrab2')
mainGUI.mainloop()



