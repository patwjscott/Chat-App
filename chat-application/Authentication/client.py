#########################################################################
# We need to add a few extra libraries
# hmac,
# hashlib,
#########################################################################
import os
import socket
import random
import json
import getpass
from base64 import b64encode, b64decode
from threading import Thread
from datetime import datetime
from colorama import Fore, init, Back
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
def AESencrypt(key, data, iv):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return str(b64encode(ciphertext).decode('utf-8'))

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
    try:
        plaintext_padded = decryptor.update(b64decode(data)) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
    except Exception as e:
        print("could not decode the message")
        return data.decode('utf-8')
    else:
        return plaintext.decode('utf-8')

#########################################################################
#
# HMAC hashing function
#
#########################################################################
def create_hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data.encode('utf-8'))
    signature = h.finalize()
    return signature

######################################################
#Authorisation
######################################################
def register(username,password):

    #generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    ) 

    #get public key that matches private key
    public_key = private_key.public_key()

    #serialize the private key and encrypt with password
    pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
            )

    #serialize the public key
    pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    #Write encrypted private key and public key to files to use next time
    with open(f"client_files/{username}.pem", "wb") as f:
        f.write(pem_private_key)

    with open(f"client_files/{username}.pub", "wb") as f:
        f.write(pem_public_key)

    return username, public_key

def RSA_Sign(data):
    signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.sha256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            utils.Prehashed(hashes.SHA256())
            )
    return signature

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
#server_public_key = serialization.load_pem_public_key(b64decode(s.recv(4096).decode('utf-8')))
# prompt the client for a name
#print(f"[+] Server public key: {server_public_key}")
name = input("Enter your name: ")
password = getpass.getpass(prompt="Password: ").encode('utf-8')

try:
    username = name
    with open(f"client_files/{username}.pem", "rb") as keyfile:
        private_key = serialization.load_pem_private_key(
            keyfile.read(),
            password=password,
        )
    with open(f"client_files/{username}.pub", "rb") as keyfile:
        public_key = serialization.load_pem_public_key(
            keyfile.read()
        )

except FileNotFoundError:
    username, public_key = register(name, password)

print(f'{b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode("utf-8")} ')
new_msg = {'username':username, 'pub_key':b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode("utf-8")}
s.send(json.dumps(new_msg).encode())

peer = input("Enter your peer's name: ")
new_msg = {'peer_name' : peer}
s.send(json.dumps(new_msg).encode())
received_data = s.recv(1024)
obj = json.loads(received_data.decode())
print(f"{obj['peer_pub_key']}")

#########################################################################
# Add key generation
#########################################################################
key = input("Please input a 32 character key if you have one, or press ENTER to create a new one: ")
if key == "":
    key = b64encode(os.urandom(32)).decode('utf-8')[:32]
print(f"Your Key is: {key} \n only give this to chat partner")
#########################################################################
# derive 2 keys from the intitial key
# enc_key used for encryption
# hmac_key used for HMAC generation
#########################################################################
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # HKDF can be used without salt for key expansion
    info=b"encryption",
)
enc_key = hkdf.derive(key.encode('utf-8'))

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # HKDF can be used without salt for key expansion
    info=b"hmac",
)
hmac_key = hkdf.derive(key.encode('utf-8'))

def listen_for_messages():
    while True:
        message = s.recv(1024).decode()
        obj = json.loads(message)
        signature = create_hmac(hmac_key, obj["msg"])
        if obj["signature"] == b64encode(signature).decode("utf-8"):
            plaintext_message = AESdecrypt(enc_key, obj["msg"].encode('utf-8'), b64decode(obj["iv"]))
            print("#######################################\n#          message verified            #\n#######################################")
        else:
            print("#######################################\n#   message could not be verified!!!   #\n#######################################")
            plaintext_message = f"[!] {obj['msg']}\n{obj['signature']} : {b64encode(signature).decode("utf-8")}"
        print(f"{obj["colour"]}")
        print(f"User: {obj['name']}")
        print(f"Date: {obj["date"]}")
        print(f"Message: {plaintext_message}")
        print(f"{Fore.RESET}")

# make a thread that listens for messages to this client & print them
t = Thread(target=listen_for_messages)
# make the thread daemon so it ends whenever the main thread ends
t.daemon = True
# start the thread
t.start()

while True:
    # input message we want to send to the server
    m = input()
    # a way to exit the program
    if m.lower() == '/q':
        s.close()
        break
    elif m.lower() == '/help':
        print("")
        print("/q to exit")
        print("/help to show this message")
    else:
        to_send = m
    #else to_send.lower() == '/':
    #########################################################################
    # Encrypt the message
    #########################################################################
        iv = os.urandom(16)
        to_send = AESencrypt(enc_key, to_send, iv)
    #########################################################################
    # HMAC encrypted message
    #########################################################################
        signature = create_hmac(hmac_key, to_send)

    # add the datetime, name & the color of the sender
        date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    #########################################################################
    # Alter message sent to use JSON format
    #########################################################################
        js = {"colour":client_color, "date":date_now, "name":name, "msg":to_send, "signature":b64encode(signature).decode("utf-8"), "iv":b64encode(iv).decode("utf-8")}
        y = json.dumps(js)
    # finally, send the message
        s.send(y.encode())

# close the socket
s.close()
