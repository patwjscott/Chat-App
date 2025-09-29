#########################################################################
# We need to add a few extra libraries
#
#########################################################################
import os
import socket
import random
import json
import getpass
import time
from base64 import b64encode, b64decode
from threading import Thread
from datetime import datetime
from colorama import Fore, init, Back
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7


# init colors
init()

# set the available colors
colors = [Fore.BLUE, Fore.CYAN, Fore.GREEN, Fore.LIGHTBLACK_EX, 
    Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, 
    Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, 
    Fore.LIGHTYELLOW_EX, Fore.MAGENTA, Fore.RED, Fore.WHITE, Fore.YELLOW
]

# choose a random color for the client
client_color = random.choice(colors)

#########################################################################
# Encrypting Function
# Receives the key, data and initialisation vector
# Pads data to appropriate length for encryption protocol
# Initialises AES Encryption
# Encrypts data using AES
# returns base 64 encoded AES encrypted text
#########################################################################
def AESencrypt(key, data):
    iv = os.urandom(16)
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, iv

#########################################################################
# Decrypting Function
# Receives key, encrypted data and initialisation vector
# Initialises AES decrypter
# Decodes base 64 encoded data and decrypts message
# Removes padding from message
# If incorrectly decrypted and padding removed
#   return error and encrypted msg
# Else return decrypted plaintext
#########################################################################
def AESdecrypt(key, data, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
    print("could not decode the message")
    return plaintext.decode('utf-8')

#########################################################################
#
# HMAC hashing function
# This function has been replaced by signing the ecdh keys
#########################################################################

#def create_hmac(key, data):
#    h = hmac.HMAC(key, hashes.SHA256())
#    h.update(data.encode('utf-8'))
#    signature = h.finalize()
#    return signature

# used to sign some data
# currently only the ecdh keys
def RSA_Sign(data):
    signature = private_rsa_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
    return signature

# just runs the cryptography verify function and returns true to false
def RSA_Verify(data, signature):
    try:
        peer_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False



# server's IP address
# if the server is not on this machine, 
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002 # server's port
separator_token = "<SEP>" # we will use this to separate the client name & message

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.")
# request Username
username = input("Enter your name: ")
print("If you already have an RSA key on this system, this password decrypts the key for use")
print("If you don't already have an RSA key, One will be created for you")
print("This is a Something that you know used to unlock a Something that you have - Authentication")
password = getpass.getpass(prompt="Password: ").encode('utf-8')
# Offer Verbose mode
Sec_Theatre = input("Would you like some security theatre to go with actual encryption? y/n: ")
if Sec_Theatre == "y":
    verbose = True
else:
    verbose = False

# Try to load the private and public key files using the username as the file name and the password as the encryption password for the private key
try:
    with open(f"client_files/{username}.pem", "rb") as keyfile:
        try:
            private_rsa_key = serialization.load_pem_private_key(
                keyfile.read(),
                password=password,
            )
        except IncorrectPassword as error:
            print("Please restart the client and use the correct password.")

    with open(f"client_files/{username}.pub", "rb") as keyfile:
        public_rsa_key = serialization.load_pem_public_key(
            keyfile.read()
        )
# If Private and Public key files aren't available, we create new ones
except FileNotFoundError:
    #generate a new private key
    private_rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # get public key that matches the private key
    public_rsa_key = private_rsa_key.public_key()

    #serialize the private key and encrypt with password
    pem_private_key = private_rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
            )

    #serialize the public key
    pem_public_key = public_rsa_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    #Write encrypted private key and public key to files to use next time
    with open(f"client_files/{username}.pem", "wb") as f:
        f.write(pem_private_key)

    with open(f"client_files/{username}.pub", "wb") as f:
        f.write(pem_public_key)

# Send username and public key to server for distribution so that other clients can message with end to end encryption
new_msg = {'username':username, 'pub_key':b64encode(public_rsa_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode("utf-8")}
s.send(json.dumps(new_msg).encode())
# request chat partners name
print("Please ensure that the peer is connected to the server before pressing enter. ")
peer = input("Enter your peer's name: ")
# send peers name to server, server will respond with the peers public key
# the RSA private key is used to sign ecdh public keys - confirming the integrity of the message and the sender of the message
new_msg = {'peer_name' : peer}
s.send(json.dumps(new_msg).encode())
# receive peers public key
received_data = s.recv(1024)
# load into python dict
obj = json.loads(received_data.decode())
# print a nice message and wait - to give the impression of security
if verbose:
    time.sleep(3)
    print(f"***Received Peer RSA Key***")
# load the peers ecdh public key
peer_public_key = serialization.load_pem_public_key(b64decode(obj["peer_pub_key"].encode('utf-8')))

#########################################################################
# Add key generation
# This key generation was used in earlier versions to ensure confidentiality
# It has been replaced by ECDH, which generates a new key pair for every message
# increasing the difficulty of breaking and providing forward secrecy if it is brokem
#########################################################################
#***********************replaced by ecdh key********************************************************
#key = input("Please input a 32 character key if you have one, or press ENTER to create a new one: ")
#if key == "":
#    key = b64encode(os.urandom(32)).decode('utf-8')[:32]
#print(f"Your Key is: {key} \n only give this to chat partner")
#########################################################################
# Now a function
# can be used to generate keys as required, currently only used to derive a
# key from the ecdh shared key
#########################################################################
def derive_key(key, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # HKDF can be used without salt for key expansion
        info=info.encode(),
    )
    enc_key = hkdf.derive(key)
    return enc_key


def listen_for_messages():
    while True:
        #generate a new ecdh key pair for every message sent
        ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
        ecdh_public_key = ecdh_private_key.public_key()
        #receive an ecdh public key from a peer and load to a Python dict
        message = s.recv(1024).decode()
        obj = json.loads(message)

        # reject messages meant for other clients
        # this stops errors caused by unexpected message content
        if obj["name"] == username:
            continue
        # only keep messages sent to the username attached to this client
        elif "to" in obj and obj["to"] == username:
            # only run this section of code if the function key is in the current message,
            # this stops random behaviour caused by the server mostly just echoing messages around
            if "function" in obj:
                if obj["function"] == "key_exchange":
                    # presume signature is not verified until it is
                    signature_verification = False
                    #load signature into variable for verification
                    received_signature = b64decode(obj["signature"])
                    # load peers ecdh key
                    received_key = serialization.load_pem_public_key(b64decode(obj["key"]))
                    # Print a nice message, make them feel safe
                    if verbose:
                        print("***received ECDH key***  ")
                        time.sleep(0.5)
                    # Serialise the peer ecdh key for verification
                    key_to_verify = received_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    #serialiase this clients ecdh key for signing
                    key_to_sign = ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    #generate a signature for the new ecdh key
                    signature = RSA_Sign(key_to_sign)
                    # compse a return ecdh key and signature for confidential communication
                    key_return = {"function": "key_return", "name": username, "key": b64encode(key_to_sign).decode("utf-8"), "signature": b64encode(signature).decode("utf-8")}
                    #if the signature is valid, send the current public ecdh key from this client
                    if RSA_Verify(key_to_verify, received_signature):
                        if verbose:
                            print("***ECDH Key Verified***")
                            time.sleep(0.5)
                        s.send(json.dumps(key_return).encode())
                    # verify the received signature came from the correct peer
                    signature_verification = RSA_Verify(key_to_verify, received_signature)

                    # if signature is valid
                    if signature_verification:
                        # generate the shared key from this clients private key and the peers public key
                        # a derivative of This key is used to encrypt the final message, providing confidentiality and forward secrecy
                        shared_key = ecdh_private_key.exchange(ec.ECDH(), received_key)
                        #derive a new key from the shared key
                        derived_key = derive_key(shared_key, "encryption")
                        # receive the message and load into python diction
                        final_message = s.recv(1024).decode()
                        obj = json.loads(final_message)
                        # Print out our message and details
                        print(f"{obj["colour"]}")
                        print(f"User: {obj['name']}")
                        print(f"Date: {obj["date"]}")
                        print(f"Message: {AESdecrypt(derived_key, b64decode(obj['msg']), b64decode(obj["iv"]))}")
                        print(f"{Fore.RESET}")
                        # help everone sleep better knowing they are only sharing information with people they planned to share it with
                        time.sleep(1)
                        print("##########################################\n#          Signature verified            #\n##########################################")
                    else:
                        # Help everyone sleep better knowing they didn't share their message with the wrong people
                        time.sleep(1)
                        print("##########################################\n#   Signature could not be verified!!!   #\n##########################################")


# make a thread that listens for messages to this client & print them
t = Thread(target=listen_for_messages)
# make the thread daemon so it ends whenever the main thread ends
t.daemon = True
# start the thread
t.start()

while True:
    # input message we want to send to the server
    m = input()
    #generate new ecdh key pair for every message sent - this provides forward secrecy
    ecdh_private_key = ec.generate_private_key(ec.SECP384R1())
    ecdh_public_key = ecdh_private_key.public_key()

    # a way to exit the program safely
    if m.lower() == '/q':
        s.close()
        break
    elif m.lower() == '/help':
        print("")
        print("/q to exit")
        print("/help to show this message")
    else:
        to_send = m

    #########################################################################
    # Sign & Hash ECDH Key
    #########################################################################
        #sign and hash ecdh key with RSA Private Key
        key_to_sign = ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        signature = RSA_Sign(key_to_sign)
        #send key to peer
        key_exchange = {"function":"key_exchange","key" : b64encode(key_to_sign).decode("utf-8"),"name":username, "to":peer,"signature" : b64encode(signature).decode("utf-8")}
        s.send(json.dumps(key_exchange).encode())
        #receive peers public ecdh key
        key_received = s.recv(1024).decode()
        #load received data into python dictionary
        key_received_json = json.loads(key_received)
        #print a nice message then wait to pretend security!!
        if verbose:
            print("***received ECDH key***")
            time.sleep(0.5)
        #seperate received data into variables
        received_signature = b64decode(key_received_json["signature"])
        received_key = serialization.load_pem_public_key(b64decode(key_received_json["key"]))
        key_to_verify = received_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)

        #verify peers ecdh public key
        signature_verification = RSA_Verify(key_to_verify, received_signature)

        #if signature is verified
        if signature_verification:
            # print a nice message then wait to pretend security
            if verbose:
                print("***ECDH Key Verified**")
                time.sleep(0.5)
            # generate shared key from ecdh private key and peers public ecdh key
            shared_key = ecdh_private_key.exchange(ec.ECDH(), received_key)
            # derive a new key for encryption from the shared key
            derived_key = derive_key(shared_key,"encryption")
            # encrypt message to send
            to_send, iv = AESencrypt(derived_key, to_send.encode())
            # print a nice message then wait to pretend security
            if verbose:
                print(
                "##########################################\n#          response verified             #\n##########################################")
        # if signature is not verified
        else:
            to_send = ""
            iv = ""
            # print a nice message then wait to pretend security
            if verbose:
                print(
                "##########################################\n#   response could not be verified!!!   #\n##########################################")

        # add the datetime, name & the color of the sender
        date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


        # Compile the final message to send
        js = {"colour":client_color, "date":date_now, "to":peer, "name":username, "msg":b64encode(to_send).decode("utf-8"), "iv":b64encode(iv).decode("utf-8")}

        #Convert to a string
        y = json.dumps(js)
        # finally, send the message
        s.send(y.encode())

# close the socket
s.close()
